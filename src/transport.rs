//! Windows UDP transport. WSARecvMsg is required to validate the received TTL and interface.
// Winsock ancillary data and route lookup require the Windows FFI boundary.
#![allow(unsafe_code)]
use crate::error::PacketError;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io,
    mem::{align_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::{
    Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects},
};

use crate::config::{is_seamless_source, Mode, Options, SessionType, ValidatedOptions, SBFD_PORT};

fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: unnamed manual-reset event, no borrowed security/name storage.
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateEventW returned a new valid handle owned by this function.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct StopState {
    event: OwnedHandle,
    requested: AtomicBool,
}

/// Shared one-shot stop request that interrupts the engine's native socket wait.
#[derive(Clone)]
pub struct StopSignal {
    state: Arc<StopState>,
}

impl StopSignal {
    /// Creates a stop request that is initially unset and may be cloned by handlers.
    ///
    /// # Errors
    /// Returns an error if Windows cannot create the event.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(StopState {
                event: create_event()?,
                requested: AtomicBool::new(false),
            }),
        })
    }

    /// Requests shutdown and wakes any engine waiting on this signal.
    /// Repeated requests are harmless; the signal cannot be cleared.
    ///
    /// # Errors
    /// Returns an error if Windows cannot signal the event.
    pub fn signal(&self) -> io::Result<()> {
        self.state.requested.store(true, Ordering::Release);
        // SAFETY: shared ownership keeps the manual-reset event alive for this call.
        if unsafe { SetEvent(self.state.event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns whether a handler has requested shutdown.
    pub fn is_requested(&self) -> bool {
        self.state.requested.load(Ordering::Acquire)
    }
}

/// Received UDP bytes and ancillary metadata, before session validation.
pub struct Datagram {
    /// The received UDP payload, before BFD header or authentication checks.
    pub data: Vec<u8>,
    /// The sender's IP address and UDP source port.
    pub source: SocketAddr,
    /// The local destination address from packet metadata, or None if unavailable.
    pub destination: Option<IpAddr>,
    /// The incoming Windows interface index, or None if metadata is unavailable.
    pub interface_index: Option<u32>,
    /// The received IPv4 TTL or IPv6 hop limit, or None if unavailable.
    pub ttl: Option<u8>,
}

impl Default for Datagram {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            source: SocketAddr::from(([0, 0, 0, 0], 0)),
            destination: None,
            interface_index: None,
            ttl: None,
        }
    }
}

impl Datagram {
    /// Check peer source, source port, destination, interface, and TTL/hop limit.
    ///
    /// Pass validated, normalized options. Point-to-point skips the source IP
    /// comparison; Session still validates discriminators and authentication.
    ///
    /// # Errors
    /// Rejects mismatched addresses/path or missing required metadata.
    pub fn validate(&self, options: &Options) -> Result<(), PacketError> {
        // RFC 5881 section 6 identifies a point-to-point neighbor by its link,
        // then its discriminator, even if its source address changes.
        if options.session_type == SessionType::Classical {
            let point_to_point = options.mode == Mode::SingleHop && options.point_to_point;
            if !point_to_point && self.source.ip() != options.peer {
                return Err(PacketError::UnexpectedPeer);
            }
            if self.source.port() < 49152 {
                return Err(PacketError::SourcePort);
            }
        } else {
            let source = self.source.ip();
            if !is_seamless_source(options.local, source) {
                return Err(PacketError::InvalidSeamlessSource);
            }
            match options.session_type {
                SessionType::SbfdInitiator => {
                    if self.source.port() != SBFD_PORT {
                        return Err(PacketError::SeamlessResponsePort);
                    }
                    if source != options.peer && !options.allowed_peers.contains(&source) {
                        return Err(PacketError::DisallowedResponse);
                    }
                }
                SessionType::SbfdReflector => {
                    if self.source.port() == 0 || self.source.port() == SBFD_PORT {
                        return Err(PacketError::SeamlessRequestPort);
                    }
                    if !options.allowed_peers.is_empty() && !options.allowed_peers.contains(&source)
                    {
                        return Err(PacketError::DisallowedRequest);
                    }
                }
                SessionType::Classical => unreachable!("classical packets validated separately"),
            }
        }
        if self.destination != Some(options.local) {
            return Err(PacketError::WrongDestination);
        }
        if options.interface_index.is_some() && self.interface_index != options.interface_index {
            return Err(PacketError::WrongInterface);
        }
        let ttl = self.ttl.ok_or(PacketError::MissingTtl)?;
        if options.session_type == SessionType::Classical
            && options.mode == Mode::SingleHop
            && ttl != 255
        {
            return Err(PacketError::SingleHopTtl);
        }
        if options.min_ttl.is_some_and(|minimum| ttl < minimum) {
            return Err(PacketError::MinimumTtl);
        }
        Ok(())
    }
}

/// Nonblocking sockets for one classical session or S-BFD protocol role.
pub struct Transport {
    receiver: Socket,
    readable: OwnedHandle,
    sender: Option<Socket>,
    peer: Option<SockAddr>,
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
    /// Validates all startup settings before opening the sockets.
    ///
    /// # Errors
    /// Returns configuration, binding, or Winsock setup failures.
    pub fn open(options: &Options) -> io::Result<Self> {
        let options = options
            .clone()
            .into_validated()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Self::from_config(&options)
    }

    /// Opens sockets from an immutable snapshot without repeating validation.
    ///
    /// # Errors
    /// Returns binding or Winsock setup failures.
    pub fn from_config(options: &ValidatedOptions) -> io::Result<Self> {
        let receiver = new_socket(options)?;
        let sender = if options.session_type == SessionType::Classical {
            receiver.bind(
                &options
                    .address(options.local, options.control_port())
                    .into(),
            )?;
            Some(new_socket(options)?)
        } else {
            None
        };
        // S-BFD responses return to the request's source port, so an initiator
        // sends and receives on the same socket. A reflector also replies from
        // its listener, preserving the mandatory source port 7784.
        let sending_socket = sender.as_ref().unwrap_or(&receiver);
        let source_port = if options.session_type == SessionType::SbfdReflector {
            receiver.bind(&options.address(options.local, SBFD_PORT).into())?;
            SBFD_PORT
        } else if let Some(port) = options.source_port {
            sending_socket.bind(&options.address(options.local, port).into())?;
            port
        } else {
            let start: u32 = rand::thread_rng().gen_range(0..16384);
            let mut bound = None;
            for offset in 0..16384 {
                let port = (49152 + (start + offset) % 16384) as u16;
                match sending_socket.bind(&options.address(options.local, port).into()) {
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
            set_option(sending_socket, IPPROTO_IP, IP_TTL, 255)?;
            if let Some(index) = options.interface_index {
                set_option(sending_socket, IPPROTO_IP, IP_UNICAST_IF, index.to_be())?;
            }
        } else {
            set_option(&receiver, IPPROTO_IPV6, IPV6_HOPLIMIT, 1)?;
            set_option(&receiver, IPPROTO_IPV6, IPV6_PKTINFO, 1)?;
            set_option(sending_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255)?;
            if let Some(index) = options.interface_index {
                set_option(sending_socket, IPPROTO_IPV6, IPV6_UNICAST_IF, index)?;
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
        sending_socket.set_nonblocking(true)?;
        let readable = create_event()?;
        let network_events =
            i32::try_from(FD_READ | FD_CLOSE).expect("network event flags fit i32");
        // SAFETY: live socket and event; neither is closed while the transport is alive.
        if unsafe {
            WSAEventSelect(
                receiver.as_raw_socket() as SOCKET,
                readable.as_raw_handle() as WSAEVENT,
                network_events,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        Ok(Self {
            receiver,
            readable,
            sender,
            peer: (options.session_type != SessionType::SbfdReflector)
                .then(|| options.address(options.peer, options.control_port()).into()),
            recv_msg,
            source_port,
        })
    }

    /// Send bytes to the configured peer control port from the bound source port.
    ///
    /// # Errors
    /// Returns socket errors or an incomplete datagram write.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let peer = self.peer.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "reflectors only send replies")
        })?;
        let sent = self
            .sender
            .as_ref()
            .unwrap_or(&self.receiver)
            .send_to(packet, peer)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete BFD datagram",
            ));
        }
        Ok(())
    }

    /// Replies from an S-BFD listener to a validated request source.
    /// Checks the Windows return route before sending from UDP port 7784.
    ///
    /// # Errors
    /// Rejects another protocol role, invalid source addresses/ports, missing
    /// return routes, socket errors, or an incomplete datagram write.
    pub fn send_reply(
        &self,
        packet: &[u8],
        request: &Datagram,
        options: &Options,
    ) -> io::Result<()> {
        if self.peer.is_some()
            || self.source_port != SBFD_PORT
            || options.session_type != SessionType::SbfdReflector
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "S-BFD replies require a reflector transport",
            ));
        }
        request
            .validate(options)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))?;
        let destination = inet_address(request.source);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut best_source = SOCKADDR_INET::default();
        // SAFETY: fully initialized IPv4/IPv6 unions and correctly sized writable
        // output structures remain live for the synchronous call. No pointers
        // are retained. Null LUID/source let the index (zero = any) and routing
        // table select a return route, including valid loopback aliases. The
        // bound socket still supplies the request's local destination as source.
        let result = unsafe {
            GetBestRoute2(
                ptr::null(),
                options.interface_index.unwrap_or(0),
                ptr::null(),
                &destination,
                0,
                &mut route,
                &mut best_source,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
                result.to_ne_bytes(),
            )));
        }
        let sent = self.receiver.send_to(packet, &request.source.into())?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete S-BFD reply",
            ));
        }
        Ok(())
    }

    /// Wait for readability or timeout, rounding up to a whole millisecond.
    /// A successful return can also mean timeout; receive can still return WouldBlock.
    ///
    /// # Errors
    /// Returns native wait errors or failed socket events.
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<()> {
        self.wait_events(timeout, None)
    }

    pub(crate) fn wait_stoppable(&self, timeout: Duration, stop: &StopSignal) -> io::Result<()> {
        self.wait_events(timeout, Some(stop))
    }

    fn wait_events(&self, timeout: Duration, stop: Option<&StopSignal>) -> io::Result<()> {
        // Stop occupies the first slot so a simultaneous packet flood cannot mask it.
        let handles = [
            stop.map_or(self.readable.as_raw_handle(), |stop| {
                stop.state.event.as_raw_handle()
            }),
            self.readable.as_raw_handle(),
        ];
        let count = if stop.is_some() { 2 } else { 1 };
        // u32::MAX means an infinite Windows wait, so retain a finite timeout.
        let milliseconds = u32::try_from(timeout.as_nanos().div_ceil(1_000_000))
            .unwrap_or(u32::MAX - 1)
            .min(u32::MAX - 1);
        // SAFETY: count initialized handles remain alive; this is a synchronous wait.
        let result = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, milliseconds) };
        if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        if result == WAIT_TIMEOUT || stop.is_some() && result == WAIT_OBJECT_0 {
            return Ok(());
        }
        let readable_slot = u32::from(stop.is_some());
        if result != WAIT_OBJECT_0 + readable_slot {
            return Err(io::Error::other("unexpected BFD socket wait result"));
        }
        let mut events = WSANETWORKEVENTS::default();
        // SAFETY: live socket/event and initialized writable event record. Enumerating
        // after the wait atomically resets the event; the next pass receives first.
        if unsafe {
            WSAEnumNetworkEvents(
                self.receiver.as_raw_socket() as SOCKET,
                self.readable.as_raw_handle() as WSAEVENT,
                &mut events,
            )
        } == SOCKET_ERROR
        {
            return Err(socket_error());
        }
        for (flag, bit) in [(FD_READ, FD_READ_BIT), (FD_CLOSE, FD_CLOSE_BIT)] {
            let index = usize::try_from(bit).expect("network event index fits usize");
            if events.lNetworkEvents & i32::try_from(flag).expect("network event flag fits i32")
                != 0
                && events.iErrorCode[index] != 0
            {
                return Err(io::Error::from_raw_os_error(events.iErrorCode[index]));
            }
        }
        if events.lNetworkEvents & i32::try_from(FD_CLOSE).expect("close event flag fits i32") != 0
        {
            return Err(io::Error::other("BFD receive socket closed"));
        }
        Ok(())
    }

    /// Receive one datagram with its metadata; does not validate the peer/session.
    ///
    /// # Errors
    /// Returns WouldBlock when no packet is ready, socket errors, or errors for
    /// truncated/invalid receive output and ancillary data.
    pub fn receive(&self) -> io::Result<Datagram> {
        let mut packet = Datagram::default();
        self.receive_into(&mut packet)?;
        Ok(packet)
    }

    /// Receive into reusable payload storage, replacing all ancillary metadata.
    /// After an error the payload is empty; retain the buffer for the next call.
    ///
    /// # Errors
    /// Returns the same socket and validation errors as `receive`.
    pub fn receive_into(&self, packet: &mut Datagram) -> io::Result<()> {
        packet.destination = None;
        packet.interface_index = None;
        packet.ttl = None;
        let result = self.receive_buffered(packet);
        if result.is_err() {
            packet.data.clear();
        }
        result
    }

    fn receive_buffered(&self, packet: &mut Datagram) -> io::Result<()> {
        packet.data.resize(512, 0);
        // usize storage provides the native WSACMSGHDR alignment on both x86 and x64.
        let mut control = [0usize; 64];
        let mut buffer = WSABUF {
            len: 512,
            buf: packet.data.as_mut_ptr(),
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
        if count > packet.data.len() || control_len > size_of_val(&control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Winsock buffer length",
            ));
        }
        packet.data.truncate(count);
        packet.source = source
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP sender"))?;
        // SAFETY: the returned length is checked and the complete buffer is initialized.
        let bytes =
            unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
        read_control(bytes, packet)
    }
}

fn inet_address(address: SocketAddr) -> SOCKADDR_INET {
    let socket_address = SockAddr::from(address);
    if address.is_ipv4() {
        // SAFETY: socket2 constructed a complete initialized SOCKADDR_IN for
        // this IPv4 address; read_unaligned does not require pointer alignment.
        let ipv4 = unsafe { ptr::read_unaligned(socket_address.as_ptr().cast()) };
        SOCKADDR_INET { Ipv4: ipv4 }
    } else {
        // SAFETY: socket2 constructed a complete initialized SOCKADDR_IN6 for
        // this IPv6 address; the copied value owns no borrowed memory.
        let ipv6 = unsafe { ptr::read_unaligned(socket_address.as_ptr().cast()) };
        SOCKADDR_INET { Ipv6: ipv6 }
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

    #[cfg(not(miri))]
    #[test]
    fn receive_storage_is_reused_and_events_rearm_after_draining() {
        use std::{net::UdpSocket, thread, time::Instant};
        let mut options = Options::new(
            "127.0.0.248".parse().unwrap(),
            "127.0.0.249".parse().unwrap(),
        );
        options.multihop = true;
        let transport = Transport::open(&options).unwrap();
        let sender = UdpSocket::bind((options.peer, 0)).unwrap();
        let mut packet = Datagram::default();
        assert_eq!(
            transport.receive_into(&mut packet).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let storage = packet.data.as_ptr();
        for length in [512, 24, 48] {
            let destination = options.address(options.local, 4784);
            let sender = sender.try_clone().unwrap();
            let worker = thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                sender.send_to(&vec![0xa5; length], destination).unwrap();
            });
            let started = Instant::now();
            let deadline = started + Duration::from_secs(2);
            loop {
                match transport.receive_into(&mut packet) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        transport
                            .wait_readable(deadline.saturating_duration_since(Instant::now()))
                            .unwrap();
                    }
                    Err(error) => panic!("receiving test datagram: {error}"),
                }
            }
            worker.join().unwrap();
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "packet must wake the native wait"
            );
            assert_eq!(packet.data, vec![0xa5; length]);
            assert_eq!(packet.data.as_ptr(), storage);
            assert_eq!(packet.destination, Some(options.local));
            assert!(packet.interface_index.is_some() && packet.ttl.is_some());
            assert_eq!(
                transport.receive_into(&mut packet).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(packet.data.is_empty());
            assert!(
                packet.destination.is_none()
                    && packet.interface_index.is_none()
                    && packet.ttl.is_none()
            );
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn stop_signal_interrupts_a_long_native_wait_and_remains_set() {
        use std::{thread, time::Instant};
        let mut options = Options::new(
            "127.0.0.250".parse().unwrap(),
            "127.0.0.251".parse().unwrap(),
        );
        options.multihop = true;
        let transport = Transport::open(&options).unwrap();
        let stop = StopSignal::new().unwrap();
        assert!(!stop.is_requested());
        let handler = stop.clone();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            handler.signal().unwrap();
        });
        let started = Instant::now();
        transport
            .wait_stoppable(Duration::from_secs(5), &stop)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        worker.join().unwrap();
        assert!(stop.is_requested());
        stop.signal().unwrap();
        let started = Instant::now();
        transport
            .wait_stoppable(Duration::from_secs(5), &stop)
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

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
