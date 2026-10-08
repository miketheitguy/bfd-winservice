//! Windows UDP transport. WSARecvMsg is required to validate the received TTL and interface.
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io,
    mem::{align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::io::AsRawSocket,
    ptr,
    time::Duration,
};
use windows_sys::Win32::Networking::WinSock::*;

use crate::config::{Mode, Options};

/// Received UDP bytes and ancillary metadata, before session validation.
pub struct Datagram {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub destination: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub ttl: Option<u8>,
}

impl Datagram {
    /// Check peer source, source port, destination, interface, and TTL/hop limit.
    ///
    /// Pass validated, normalized options. Point-to-point skips the source IP
    /// comparison; Session still validates discriminators and authentication.
    ///
    /// # Errors
    /// Rejects mismatched addresses/path or missing required metadata.
    pub fn validate(&self, options: &Options) -> Result<(), &'static str> {
        // RFC 5881 section 6 identifies a point-to-point neighbor by its link,
        // then its discriminator, even if its source address changes.
        let point_to_point = options.mode == Mode::SingleHop && options.point_to_point;
        if !point_to_point && self.source.ip() != options.peer {
            return Err("unexpected peer address");
        }
        if self.source.port() < 49152 {
            return Err("peer source port is outside 49152..65535");
        }
        if self.destination != Some(options.local) {
            return Err("destination address is not the configured local address");
        }
        if options.interface_index.is_some() && self.interface_index != options.interface_index {
            return Err("packet arrived on another interface");
        }
        let ttl = self.ttl.ok_or("missing received TTL/hop limit")?;
        if options.mode == Mode::SingleHop && ttl != 255 {
            return Err("single-hop TTL/hop limit must be 255");
        }
        if options.mode == Mode::Multihop && options.min_ttl.is_some_and(|minimum| ttl < minimum) {
            return Err("multihop TTL/hop limit below MinTtl");
        }
        Ok(())
    }
}

/// Nonblocking receive/transmit sockets for one configured peer destination.
pub struct Transport {
    receiver: Socket,
    sender: Socket,
    peer: SockAddr,
    recv_msg: LPFN_WSARECVMSG,
    /// Bound transmit port reported at construction; changing this field does
    /// not rebind the socket.
    pub source_port: u16,
}

fn socket_error() -> io::Error {
    // SAFETY: WSAGetLastError has no arguments or memory access requirements.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn set_option(socket: &Socket, level: i32, name: i32, value: u32) -> io::Result<()> {
    // SAFETY: live socket; pointer references a four-byte DWORD for the entire call.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(socket_error())
    } else {
        Ok(())
    }
}

fn new_socket(options: &Options) -> io::Result<Socket> {
    let socket = Socket::new(
        if options.local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    set_option(&socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
    if options.local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // ICMP port-unreachable and TTL-expired feedback must not kill the service.
    let disabled = 0u32;
    let mut returned = 0u32;
    for code in [SIO_UDP_CONNRESET, SIO_UDP_NETRESET] {
        // SAFETY: correctly sized live DWORD input/output; no overlapped I/O.
        let result = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                code,
                (&disabled as *const u32).cast(),
                4,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            return Err(socket_error());
        }
    }
    Ok(socket)
}

impl Transport {
    /// Open sockets with TTL/hop limit 255 and receive metadata enabled.
    ///
    /// Checks numeric ranges only. Full session callers must first validate and
    /// normalize Options; Engine::open does so.
    ///
    /// # Errors
    /// Returns configuration, binding, or Winsock setup failures.
    pub fn open(options: &Options) -> io::Result<Self> {
        options
            .validate_ranges()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let receiver = new_socket(options)?;
        let sender = new_socket(options)?;
        receiver.bind(&options.address(options.local, options.mode.port()).into())?;
        let source_port = if let Some(port) = options.source_port {
            sender.bind(&options.address(options.local, port).into())?;
            port
        } else {
            let start: u32 = rand::thread_rng().gen_range(0..16384);
            let mut bound = None;
            for offset in 0..16384 {
                let port = (49152 + (start + offset) % 16384) as u16;
                match sender.bind(&options.address(options.local, port).into()) {
                    Ok(()) => {
                        bound = Some(port);
                        break;
                    }
                    // Windows also reports WSAEACCES for excluded/reserved UDP ports.
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                        ) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                }
            }
            bound.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "all BFD source ports are occupied",
                )
            })?
        };
        if options.local.is_ipv4() {
            set_option(&receiver, IPPROTO_IP, IP_RECVTTL, 1)?;
            set_option(&receiver, IPPROTO_IP, IP_PKTINFO, 1)?;
            set_option(&sender, IPPROTO_IP, IP_TTL, 255)?;
            if let Some(index) = options.interface_index {
                set_option(&sender, IPPROTO_IP, IP_UNICAST_IF, index.to_be())?;
            }
        } else {
            set_option(&receiver, IPPROTO_IPV6, IPV6_HOPLIMIT, 1)?;
            set_option(&receiver, IPPROTO_IPV6, IPV6_PKTINFO, 1)?;
            set_option(&sender, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255)?;
            if let Some(index) = options.interface_index {
                set_option(&sender, IPPROTO_IPV6, IPV6_UNICAST_IF, index)?;
            }
        }
        let mut recv_msg: LPFN_WSARECVMSG = None;
        let mut returned = 0u32;
        // SAFETY: the GUID selects this exact function pointer type. Winsock writes to its full storage.
        let result = unsafe {
            WSAIoctl(
                receiver.as_raw_socket() as SOCKET,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(),
                size_of::<windows_sys::core::GUID>() as u32,
                (&mut recv_msg as *mut LPFN_WSARECVMSG).cast(),
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            return Err(socket_error());
        }
        if recv_msg.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WSARecvMsg is unavailable",
            ));
        }
        receiver.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok(Self {
            receiver,
            sender,
            peer: options.address(options.peer, options.mode.port()).into(),
            recv_msg,
            source_port,
        })
    }

    /// Send bytes to the configured peer control port from the bound source port.
    ///
    /// # Errors
    /// Returns socket errors or an incomplete datagram write.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let sent = self.sender.send_to(packet, &self.peer)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete BFD datagram",
            ));
        }
        Ok(())
    }

    /// Wait for readability or timeout, rounding up to a whole millisecond.
    /// A successful return can also mean timeout; receive can still return WouldBlock.
    ///
    /// # Errors
    /// Returns Winsock poll errors or failed socket events.
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<()> {
        let mut fd = WSAPOLLFD {
            fd: self.receiver.as_raw_socket() as SOCKET,
            events: POLLRDNORM,
            revents: 0,
        };
        // Round up to milliseconds and cap the Winsock signed timeout.
        // The runtime supplies waits of at most its 10 ms stop-check interval.
        let milliseconds = timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        // SAFETY: fd is valid writable storage for exactly one descriptor.
        if unsafe { WSAPoll(&mut fd, 1, milliseconds) } == SOCKET_ERROR {
            return Err(socket_error());
        }
        if fd.revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
            return Err(io::Error::other("BFD receive socket failed"));
        }
        Ok(())
    }

    /// Receive one datagram with its metadata; does not validate the peer/session.
    ///
    /// # Errors
    /// Returns WouldBlock when no packet is ready, socket errors, or errors for
    /// truncated/invalid receive output and ancillary data.
    pub fn receive(&self) -> io::Result<Datagram> {
        let mut data = [0u8; 512];
        // usize storage provides the native WSACMSGHDR alignment on both x86 and x64.
        let mut control = [0usize; 64];
        let mut buffer = WSABUF {
            len: data.len() as u32,
            buf: data.as_mut_ptr(),
        };
        let mut count = 0u32;
        let recv_msg = self.recv_msg.expect("validated at socket creation");
        // SAFETY: WSARecvMsg initializes the address storage/length and writes only into the
        // provided buffers. No overlapped operation outlives these stack allocations.
        let ((count, control_len), source) = unsafe {
            SockAddr::try_init(|address, address_len| {
                let mut message = WSAMSG {
                    name: address.cast(),
                    namelen: *address_len,
                    lpBuffers: &mut buffer,
                    dwBufferCount: 1,
                    Control: WSABUF {
                        len: size_of_val(&control) as u32,
                        buf: control.as_mut_ptr().cast(),
                    },
                    dwFlags: 0,
                };
                if recv_msg(
                    self.receiver.as_raw_socket() as SOCKET,
                    &mut message,
                    &mut count,
                    ptr::null_mut(),
                    None,
                ) == SOCKET_ERROR
                {
                    return Err(socket_error());
                }
                if message.dwFlags & (MSG_TRUNC | MSG_CTRUNC) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated datagram or ancillary data",
                    ));
                }
                *address_len = message.namelen;
                Ok((count as usize, message.Control.len as usize))
            })
        }?;
        if count > data.len() || control_len > size_of_val(&control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Winsock buffer length",
            ));
        }
        let mut packet = Datagram {
            data: data[..count].to_vec(),
            source: source
                .as_socket()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP sender"))?,
            destination: None,
            interface_index: None,
            ttl: None,
        };
        // SAFETY: the returned length is checked and the complete buffer is initialized.
        let bytes =
            unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
        read_control(bytes, &mut packet)?;
        Ok(packet)
    }
}

fn align(length: usize) -> usize {
    length.next_multiple_of(align_of::<usize>())
}

fn read_control(bytes: &[u8], packet: &mut Datagram) -> io::Result<()> {
    let header_len = align(size_of::<CMSGHDR>());
    let mut offset = 0;
    while bytes.len().saturating_sub(offset) >= size_of::<CMSGHDR>() {
        // SAFETY: bounds checked; read_unaligned also supports test buffers with byte alignment.
        let header = unsafe { ptr::read_unaligned(bytes[offset..].as_ptr().cast::<CMSGHDR>()) };
        if header.cmsg_len < header_len || header.cmsg_len > bytes.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ancillary length",
            ));
        }
        let data = &bytes[offset + header_len..offset + header.cmsg_len];
        match (header.cmsg_level, header.cmsg_type) {
            (IPPROTO_IP, IP_TTL | IP_RECVTTL) | (IPPROTO_IPV6, IPV6_HOPLIMIT)
                if data.len() >= 4 =>
            {
                let value =
                    u32::from_ne_bytes(data[..4].try_into().expect("four-byte TTL payload"));
                packet.ttl = u8::try_from(value).ok();
            }
            (IPPROTO_IP, IP_PKTINFO) if data.len() >= size_of::<IN_PKTINFO>() => {
                // SAFETY: complete IN_PKTINFO fits in data; its union's S_addr field is valid.
                let info = unsafe { ptr::read_unaligned(data.as_ptr().cast::<IN_PKTINFO>()) };
                // SAFETY: IN_ADDR union's S_addr field is valid for every IPv4 address.
                let address = unsafe { info.ipi_addr.S_un.S_addr };
                packet.destination = Some(Ipv4Addr::from(address.to_ne_bytes()).into());
                packet.interface_index = Some(info.ipi_ifindex);
            }
            (IPPROTO_IPV6, IPV6_PKTINFO) if data.len() >= size_of::<IN6_PKTINFO>() => {
                // SAFETY: complete IN6_PKTINFO fits in data; its union contains the address bytes.
                let info = unsafe { ptr::read_unaligned(data.as_ptr().cast::<IN6_PKTINFO>()) };
                // SAFETY: IN6_ADDR union's Byte field contains all sixteen address bytes.
                let address = unsafe { info.ipi6_addr.u.Byte };
                packet.destination = Some(Ipv6Addr::from(address).into());
                packet.interface_index = Some(info.ipi6_ifindex);
            }
            _ => {}
        }
        offset += align(header.cmsg_len);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encode native ancillary bytes without raw-pointer writes, so the fixtures can
    // exercise the parser's unsafe reads independently of Winsock and alignment.
    fn ancillary_record(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
        let length = size_of::<CMSGHDR>() + payload.len();
        let mut bytes = vec![0; length.next_multiple_of(align_of::<CMSGHDR>())];
        let offset = std::mem::offset_of!(CMSGHDR, cmsg_len);
        bytes[offset..offset + size_of::<usize>()].copy_from_slice(&length.to_ne_bytes());
        let offset = std::mem::offset_of!(CMSGHDR, cmsg_level);
        bytes[offset..offset + 4].copy_from_slice(&level.to_ne_bytes());
        let offset = std::mem::offset_of!(CMSGHDR, cmsg_type);
        bytes[offset..offset + 4].copy_from_slice(&kind.to_ne_bytes());
        bytes[size_of::<CMSGHDR>()..length].copy_from_slice(payload);
        bytes
    }

    fn empty_datagram() -> Datagram {
        Datagram {
            data: Vec::new(),
            source: "192.0.2.2:49152".parse().unwrap(),
            destination: None,
            interface_index: None,
            ttl: None,
        }
    }

    #[test]
    fn ancillary_metadata_parses_unaligned_ipv4_and_ipv6_records() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut info4 = vec![0; size_of::<IN_PKTINFO>()];
        let offset = std::mem::offset_of!(IN_PKTINFO, ipi_addr);
        info4[offset..offset + 4].copy_from_slice(&ipv4.octets());
        let offset = std::mem::offset_of!(IN_PKTINFO, ipi_ifindex);
        info4[offset..offset + 4].copy_from_slice(&17u32.to_ne_bytes());
        let mut info6 = vec![0; size_of::<IN6_PKTINFO>()];
        let offset = std::mem::offset_of!(IN6_PKTINFO, ipi6_addr);
        info6[offset..offset + 16].copy_from_slice(&ipv6.octets());
        let offset = std::mem::offset_of!(IN6_PKTINFO, ipi6_ifindex);
        info6[offset..offset + 4].copy_from_slice(&23u32.to_ne_bytes());

        for (level, ttl_kind, info_kind, info, destination, index, ttl) in [
            (
                IPPROTO_IP,
                IP_RECVTTL,
                IP_PKTINFO,
                info4,
                IpAddr::V4(ipv4),
                17,
                255u32,
            ),
            (
                IPPROTO_IPV6,
                IPV6_HOPLIMIT,
                IPV6_PKTINFO,
                info6,
                IpAddr::V6(ipv6),
                23,
                64u32,
            ),
        ] {
            let mut records = ancillary_record(level, -1, &[1, 2, 3]);
            records.extend(ancillary_record(level, ttl_kind, &ttl.to_ne_bytes()));
            records.extend(ancillary_record(level, info_kind, &info));
            // Cover every header alignment residue, including byte-aligned input.
            for prefix in 0..align_of::<CMSGHDR>() {
                let mut storage = vec![0; prefix];
                storage.extend_from_slice(&records);
                let mut packet = empty_datagram();
                read_control(&storage[prefix..], &mut packet).unwrap();
                assert_eq!(packet.destination, Some(destination));
                assert_eq!(packet.interface_index, Some(index));
                assert_eq!(packet.ttl, Some(u8::try_from(ttl).unwrap()));
            }
        }
    }

    #[test]
    fn ancillary_metadata_rejects_invalid_record_lengths() {
        let good = ancillary_record(IPPROTO_IP, IP_RECVTTL, &255u32.to_ne_bytes());
        for length in [0, size_of::<CMSGHDR>() - 1, good.len() + 1, usize::MAX] {
            let mut bytes = good.clone();
            let offset = std::mem::offset_of!(CMSGHDR, cmsg_len);
            bytes[offset..offset + size_of::<usize>()].copy_from_slice(&length.to_ne_bytes());
            let mut packet = empty_datagram();
            assert_eq!(
                read_control(&bytes, &mut packet).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(packet.ttl, None);
        }
    }

    #[test]
    fn ancillary_metadata_ignores_short_payloads_and_handles_truncated_buffers() {
        for (level, kind, payload_len) in [
            (IPPROTO_IP, IP_RECVTTL, 4),
            (IPPROTO_IPV6, IPV6_HOPLIMIT, 4),
            (IPPROTO_IP, IP_PKTINFO, size_of::<IN_PKTINFO>()),
            (IPPROTO_IPV6, IPV6_PKTINFO, size_of::<IN6_PKTINFO>()),
        ] {
            for length in 0..payload_len {
                let bytes = ancillary_record(level, kind, &vec![0; length]);
                let mut packet = empty_datagram();
                read_control(&bytes, &mut packet).unwrap();
                assert_eq!(packet.destination, None);
                assert_eq!(packet.interface_index, None);
                assert_eq!(packet.ttl, None);
            }
        }

        let good = ancillary_record(IPPROTO_IP, IP_RECVTTL, &255u32.to_ne_bytes());
        for length in 0..size_of::<CMSGHDR>() + 4 {
            let mut packet = empty_datagram();
            // An incomplete header is ignored; a complete header with missing
            // payload is rejected. Neither may publish incomplete TTL metadata.
            let result = read_control(&good[..length], &mut packet);
            assert_eq!(result.is_ok(), length < size_of::<CMSGHDR>());
            assert_eq!(packet.ttl, None);
        }
        let invalid_ttl = ancillary_record(IPPROTO_IP, IP_RECVTTL, &256u32.to_ne_bytes());
        let mut packet = empty_datagram();
        read_control(&invalid_ttl, &mut packet).unwrap();
        assert_eq!(packet.ttl, None);
    }

    #[test]
    fn rejects_wrong_peer_port_interface_and_ttl() {
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.interface_index = Some(2);
        options.validate().unwrap();
        let mut packet = Datagram {
            data: vec![],
            source: "192.0.2.2:49152".parse().unwrap(),
            destination: Some(options.local),
            interface_index: Some(2),
            ttl: Some(255),
        };
        assert!(packet.validate(&options).is_ok());
        packet.ttl = Some(254);
        assert!(packet.validate(&options).is_err());
        options.mode = Mode::Multihop;
        assert!(packet.validate(&options).is_ok());
        options.min_ttl = Some(255);
        assert!(packet.validate(&options).is_err());
        packet.ttl = Some(255);
        packet.source.set_port(3784);
        assert!(packet.validate(&options).is_err());
        packet.source.set_port(49152);
        packet.interface_index = Some(3);
        assert!(packet.validate(&options).is_err());
    }

    #[test]
    fn point_to_point_source_changes_preserve_path_validation() {
        for (local, peer, alternate_source) in [
            ("192.0.2.1", "192.0.2.2", "192.0.2.3:49152"),
            ("2001:db8::1", "2001:db8::2", "[2001:db8::3]:49152"),
        ] {
            let mut options = Options::new(local.parse().unwrap(), peer.parse().unwrap());
            options.interface_index = Some(2);
            options.point_to_point = true;
            options.validate().unwrap();
            let mut packet = Datagram {
                data: vec![],
                source: alternate_source.parse().unwrap(),
                destination: Some(options.local),
                interface_index: Some(2),
                ttl: Some(255),
            };
            assert!(packet.validate(&options).is_ok());
            options.point_to_point = false;
            assert!(packet.validate(&options).is_err());
            options.point_to_point = true;
            options.mode = Mode::Multihop;
            assert!(packet.validate(&options).is_err());
            options.mode = Mode::SingleHop;

            packet.ttl = Some(254);
            assert!(packet.validate(&options).is_err());
            packet.ttl = None;
            assert!(packet.validate(&options).is_err());
            packet.ttl = Some(255);
            packet.interface_index = Some(3);
            assert!(packet.validate(&options).is_err());
            packet.interface_index = None;
            assert!(packet.validate(&options).is_err());
            packet.interface_index = Some(2);
            packet.destination = Some(options.peer);
            assert!(packet.validate(&options).is_err());
            packet.destination = None;
            assert!(packet.validate(&options).is_err());
            packet.destination = Some(options.local);
            packet.source.set_port(3784);
            assert!(packet.validate(&options).is_err());
        }
    }

    #[test]
    fn point_to_point_sources_still_require_discriminator_and_authentication() {
        use crate::{
            packet::{test_packet, AuthConfig, AuthType, State},
            session::Session,
        };
        use std::time::Instant;

        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.interface_index = Some(2);
        options.point_to_point = true;
        options.discriminator = Some(7);
        options.auth = crate::packet::AuthType::MeticulousSha1;
        options.auth_key = Some("secret".to_owned());
        let auth = options.validate().unwrap();
        let mut session = Session::new(options.clone(), auth.clone()).unwrap();
        let now = Instant::now();
        let mut control = test_packet(State::Down);
        control.your_discriminator = 0;
        control.desired_min_tx_us = 1000000;
        let mut datagram = Datagram {
            data: control.encode(&auth, 100),
            source: "192.0.2.3:49152".parse().unwrap(),
            destination: Some(options.local),
            interface_index: Some(2),
            ttl: Some(255),
        };
        datagram.validate(&options).unwrap();
        session.receive(&datagram.data, now).unwrap();
        assert_eq!(session.state, State::Init);

        control.state = State::Init;
        control.your_discriminator = 7;
        datagram.source = "192.0.2.4:49152".parse().unwrap();
        datagram.data = control.encode(&auth, 101);
        datagram.validate(&options).unwrap();
        session.receive(&datagram.data, now).unwrap();
        assert_eq!(session.state, State::Up);

        control.state = State::Up;
        control.your_discriminator = 8;
        datagram.data = control.encode(&auth, 102);
        datagram.validate(&options).unwrap();
        assert!(session
            .receive(&datagram.data, now + Duration::from_secs(1))
            .is_err());

        control.your_discriminator = 7;
        let wrong_key = AuthConfig::new(AuthType::MeticulousSha1, 0, b"wrong".to_vec()).unwrap();
        datagram.data = control.encode(&wrong_key, 102);
        datagram.validate(&options).unwrap();
        assert!(session
            .receive(&datagram.data, now + Duration::from_secs(2))
            .is_err());
        assert_eq!(session.state, State::Up);
        assert!(session.expire(now + Duration::from_secs(3)));
    }
}
