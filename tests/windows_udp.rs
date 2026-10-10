#![cfg(windows)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)] // Test fixtures fail immediately on invalid setup.

use bfd_winservice::{
    config::{Mode, Options},
    packet::{AuthConfig, AuthType, ControlPacket, State},
    runtime::{Engine, Logger, StateObserver, StopSignal},
    transport::{Datagram, Transport},
};
use std::{
    io,
    net::UdpSocket,
    thread,
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;

fn options(local: &str, peer: &str, mode: &str) -> Options {
    let mut options = Options::new(local.parse().unwrap(), peer.parse().unwrap());
    options.discriminator = Some(7);
    options.min_tx_us = 100000;
    options.min_rx_us = 100000;
    // Transport tests discover the loopback interface through packet metadata.
    options.mode = if mode == "single-hop" {
        Mode::SingleHop
    } else {
        Mode::Multihop
    };
    options
}

fn receive(transport: &Transport) -> Datagram {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match transport.receive() {
            Ok(packet) => return packet,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                transport.wait_readable(Duration::from_millis(10)).unwrap();
            }
            Err(error) => panic!("receiving test datagram: {error}"),
        }
    }
}

fn loopback_interface(options: &Options) -> u32 {
    let mut discovery = options.clone();
    discovery.mode = Mode::Multihop;
    discovery.multihop = true;
    let transport = Transport::open(&discovery).unwrap();
    let sender = UdpSocket::bind(options.address(options.peer, 0)).unwrap();
    sender
        .send_to(&[0; 24], options.address(options.local, 4784))
        .unwrap();
    receive(&transport).interface_index.unwrap()
}

struct RunningEngine {
    state: StateObserver,
    stop: StopSignal,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

fn test_log(label: &str) -> NamedTempFile {
    tempfile::Builder::new()
        .prefix(&format!("bfd-{label}-"))
        .suffix(".log")
        .tempfile()
        .unwrap()
}

impl RunningEngine {
    fn start(mut options: Options) -> Self {
        let auth = options.validate().unwrap();
        let mut log = Logger::open(&options).unwrap();
        let mut engine = Engine::open(options, auth, &mut log).unwrap();
        let stop = StopSignal::new().unwrap();
        let receiver = stop.clone();
        Self {
            state: engine.state_observer(),
            stop,
            worker: Some(thread::spawn(move || engine.run_until(&receiver, &mut log))),
        }
    }

    fn stop(&mut self) {
        self.stop.signal().unwrap();
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for RunningEngine {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Also release sockets and the worker if a test assertion fails.
            let _ = self.stop.signal();
            let _ = worker.join();
        }
    }
}

fn bfd_sender(address: &str) -> UdpSocket {
    for port in 49152..=65535 {
        match UdpSocket::bind((address, port)) {
            Ok(socket) => return socket,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => panic!("binding BFD test sender: {error}"),
        }
    }
    panic!("no available BFD test source port");
}

fn peer_packet(state: State) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 10,
        my_discriminator: 99,
        your_discriminator: if state == State::Down { 0 } else { 7 },
        desired_min_tx_us: if state == State::Up { 100000 } else { 1000000 },
        required_min_rx_us: 100000,
        required_min_echo_rx_us: 0,
    }
}

#[test]
fn authenticated_engine_discards_unauthenticated_handshake_and_poll_packets() {
    let log = test_log("authentication");
    let mut options = options("127.0.0.50", "127.0.0.51", "multihop");
    options.passive = true;
    options.auth = AuthType::MeticulousSha1;
    options.auth_key_id = 9;
    options.auth_key = Some("secret".to_owned());
    options.log_file_path = log.path().to_path_buf();
    options.log_to_file = true;
    assert!(!options.verbose);
    let auth = options.validate().unwrap();
    let no_auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let peer = UdpSocket::bind("127.0.0.51:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let sender = bfd_sender("127.0.0.51");
    let mut engine = RunningEngine::start(options);
    let mut buffer = [0; 256];

    for state in [State::Down, State::Init, State::Up] {
        let mut packet = peer_packet(state);
        packet.poll = true;
        sender
            .send_to(&packet.encode(&no_auth, 0), "127.0.0.50:4784")
            .unwrap();
    }
    // A passive session must not learn an unauthenticated peer or answer its Poll.
    let error = peer.recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));

    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut received_sequence = None;
    for (sequence, remote, local) in [
        (100, State::Down, State::Init),
        (101, State::Init, State::Up),
    ] {
        let mut packet = peer_packet(remote);
        packet.poll = true;
        // Suppress periodic traffic so any later response must be a Final.
        packet.required_min_rx_us = 0;
        sender
            .send_to(&packet.encode(&auth, sequence), "127.0.0.50:4784")
            .unwrap();
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        received_sequence = auth.verify(&buffer[..length], received_sequence).unwrap();
        let reply = ControlPacket::decode(&buffer[..length]).unwrap();
        assert_eq!(reply.state, local);
        assert_eq!(reply.your_discriminator, 99);
        assert!(reply.final_bit);
        assert!(!reply.poll);
    }

    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut packet = peer_packet(State::Down);
    packet.poll = true;
    sender
        .send_to(&packet.encode(&no_auth, 0), "127.0.0.50:4784")
        .unwrap();
    // Also reject unauthenticated Polls after establishment, without enabling
    // periodic traffic from their advertised receive interval.
    let error = peer.recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    engine.stop();
    let contents = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        contents.contains("authentication failed for packet from 127.0.0.51:"),
        "{contents}"
    );
    assert!(contents.contains("authentication required"), "{contents}");
    assert!(!contents.contains("secret"), "{contents}");
    assert!(!contents.contains("discarded packet"), "{contents}");
}

#[test]
fn peer_communication_notifications_cover_down_state_timeout_and_recovery_once() {
    // Declared before the engine so the worker closes its log before removal.
    let log = test_log("communication");
    let mut options = options("127.0.0.60", "127.0.0.61", "multihop");
    options.passive = true;
    options.log_file_path = log.path().to_path_buf();
    options.log_to_file = true;
    let peer = UdpSocket::bind("127.0.0.61:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let sender = bfd_sender("127.0.0.61");
    let mut engine = RunningEngine::start(options);
    let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut packet = peer_packet(State::AdminDown);
    packet.poll = true;
    packet.detect_mult = 1;
    packet.desired_min_tx_us = 100000;
    packet.required_min_rx_us = 0;
    let mut buffer = [0; 256];
    for _ in 0..3 {
        sender
            .send_to(&packet.encode(&auth, 0), "127.0.0.60:4784")
            .unwrap();
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        let reply = ControlPacket::decode(&buffer[..length]).unwrap();
        assert!(reply.final_bit);
        assert_eq!(reply.state, State::Down);
    }
    // Valid AdminDown packets keep communication alive even though local state
    // never leaves Down. Expiry must still notify once without a state change.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read_to_string(log.path())
            .unwrap()
            .contains("communication=stopped")
        {
            break;
        }
        assert!(Instant::now() < deadline, "peer timeout was not logged");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(40));
    packet.state = State::Init;
    sender
        .send_to(&packet.encode(&auth, 0), "127.0.0.60:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Up
    );
    engine.stop();
    let contents = std::fs::read_to_string(log.path()).unwrap();
    assert_eq!(
        contents.matches("communication=started").count(),
        2,
        "{contents}"
    );
    assert_eq!(
        contents.matches("communication=stopped").count(),
        1,
        "{contents}"
    );
    assert!(
        contents
            .lines()
            .any(|line| line.contains("communication=stopped")
                && line.contains("remote_discriminator=99")),
        "{contents}"
    );
    assert!(contents.contains("state=Up diagnostic=None"), "{contents}");
    assert!(
        contents.contains("state=AdminDown diagnostic=AdminDown"),
        "{contents}"
    );
}

#[test]
fn windows_ipv4_metadata_and_single_hop_ttl_are_checked() {
    let mut options = options("127.0.0.10", "127.0.0.11", "single-hop");
    options.interface_index = Some(loopback_interface(&options));
    let transport = Transport::open(&options).unwrap();
    let peer = UdpSocket::bind("127.0.0.11:55001").unwrap();
    peer.set_ttl(255).unwrap();
    peer.send_to(&[0; 24], "127.0.0.10:3784").unwrap();
    let packet = receive(&transport);
    assert_eq!(packet.ttl, Some(255));
    assert_eq!(packet.destination, Some(options.local));
    assert!(packet.interface_index.is_some_and(|index| index != 0));
    options.interface_index = packet.interface_index;
    assert!(packet.validate(&options).is_ok());
    peer.set_ttl(254).unwrap();
    peer.send_to(&[0; 24], "127.0.0.10:3784").unwrap();
    assert!(receive(&transport).validate(&options).is_err());
}

#[test]
fn windows_ipv6_hop_limit_and_destination_metadata_are_available() {
    // S-BFD permits same-host probes, so this fixture also passes full validation.
    let mut options = Options::new("::1".parse().unwrap(), "::1".parse().unwrap());
    options.session_type = bfd_winservice::config::SessionType::SbfdInitiator;
    options.remote_discriminator = Some(99);
    let transport = Transport::open(&options).unwrap();
    let peer = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    peer.set_unicast_hops_v6(253).unwrap();
    peer.bind(&"[::1]:7784".parse::<std::net::SocketAddr>().unwrap().into())
        .unwrap();
    peer.send_to(
        &[0; 24],
        &options.address(options.local, transport.source_port).into(),
    )
    .unwrap();
    let packet = receive(&transport);
    assert_eq!(packet.ttl, Some(253));
    assert_eq!(packet.destination, Some(options.local));
    assert!(packet.validate(&options).is_ok());
}

#[test]
fn console_engine_handshake_poll_timeout_and_admin_down_over_udp() {
    let mut options = options("127.0.0.20", "127.0.0.21", "multihop");
    options.source_port = Some(55003);
    let peer = UdpSocket::bind("127.0.0.21:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let sender = UdpSocket::bind("127.0.0.21:55004").unwrap();
    // Multihop must accept packets with a TTL below 255.
    sender.set_ttl(64).unwrap();
    let mut engine = RunningEngine::start(options);
    assert_eq!(engine.state.current(), Some(State::Down));
    let no_auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut buffer = [0; 512];
    let (length, source) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(source.port(), 55003);
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Down
    );
    let mut packet = ControlPacket {
        diagnostic: 0,
        state: State::Down,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 3,
        my_discriminator: 99,
        your_discriminator: 0,
        desired_min_tx_us: 100000,
        required_min_rx_us: 100000,
        required_min_echo_rx_us: 0,
    };
    sender
        .send_to(&packet.encode(&no_auth, 0), "127.0.0.20:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Init
    );
    assert_eq!(engine.state.current(), Some(State::Init));
    packet.state = State::Init;
    packet.your_discriminator = 7;
    sender
        .send_to(&packet.encode(&no_auth, 0), "127.0.0.20:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let up = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(up.state, State::Up);
    assert_eq!(engine.state.current(), Some(State::Up));
    assert!(
        !up.poll && !up.final_bit,
        "state notification is separate from Poll"
    );
    assert_eq!(up.required_min_echo_rx_us, 0);
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let poll = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(poll.state, State::Up);
    assert!(
        poll.poll && !poll.final_bit,
        "Poll uses the periodic schedule"
    );
    packet.state = State::Up;
    packet.final_bit = true;
    packet.poll = false;
    sender
        .send_to(&packet.encode(&no_auth, 0), "127.0.0.20:4784")
        .unwrap();
    packet.final_bit = false;
    packet.poll = true;
    sender
        .send_to(&packet.encode(&no_auth, 0), "127.0.0.20:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let reply = ControlPacket::decode(&buffer[..length]).unwrap();
    assert!(reply.final_bit);
    assert!(!reply.poll);
    // Withhold valid packets. The real runtime must expire independently of input.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        let packet = ControlPacket::decode(&buffer[..length]).unwrap();
        if packet.state == State::Down {
            assert_eq!(engine.state.current(), Some(State::Down));
            assert_eq!(packet.diagnostic, 1);
            assert_eq!(packet.your_discriminator, 0);
            break;
        }
        assert!(Instant::now() < deadline, "session did not time out");
    }
    engine.stop();
    assert_eq!(engine.state.current(), None);
    loop {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        let packet = ControlPacket::decode(&buffer[..length]).unwrap();
        if packet.state == State::AdminDown {
            assert_eq!(packet.diagnostic, 7);
            break;
        }
    }
}

#[test]
fn state_notifications_are_authenticated_without_periodic_traffic_or_extra_polls() {
    let mut options = options("127.0.0.36", "127.0.0.37", "multihop");
    options.source_port = Some(55016);
    options.auth = AuthType::MeticulousSha1;
    options.auth_key = Some("secret".into());
    let log = test_log("state-notification");
    options.log_to_file = true;
    options.log_file_path = log.path().to_path_buf();
    let auth = options.validate().unwrap();
    let peer = UdpSocket::bind("127.0.0.37:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let sender = bfd_sender("127.0.0.37");
    let mut engine = RunningEngine::start(options);
    let mut buffer = [0; 512];
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Down
    );
    let sequence = auth.verify(&buffer[..length], None).unwrap();
    let mut packet = peer_packet(State::Init);
    packet.required_min_rx_us = 0;
    sender
        .send_to(&packet.encode(&auth, 1), "127.0.0.36:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let up = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(up.state, State::Up);
    assert_eq!(up.diagnostic, 0);
    assert_eq!(buffer[1], 0xc4, "Up and Authentication only");
    let sequence = auth.verify(&buffer[..length], sequence).unwrap();

    packet.state = State::AdminDown;
    sender
        .send_to(&packet.encode(&auth, 2), "127.0.0.36:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let down = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(down.state, State::Down);
    assert_eq!(down.diagnostic, 3);
    assert_eq!(buffer[1], 0x44, "Down and Authentication only");
    let sequence = auth.verify(&buffer[..length], sequence).unwrap();

    sender
        .send_to(&packet.encode(&auth, 3), "127.0.0.36:4784")
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let error = peer.recv_from(&mut buffer).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));

    // Reestablish, then expire while periodic traffic is still suppressed.
    packet.state = State::Init;
    packet.detect_mult = 3;
    packet.desired_min_tx_us = 100_000;
    sender
        .send_to(&packet.encode(&auth, 4), "127.0.0.36:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let recovered = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(recovered.state, State::Up);
    assert_eq!(recovered.diagnostic, 3);
    assert_eq!(buffer[1], 0xc4);
    let sequence = auth.verify(&buffer[..length], sequence).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let expired = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(expired.state, State::Down);
    assert_eq!(expired.diagnostic, 1);
    assert_eq!(expired.your_discriminator, 0);
    assert_eq!(buffer[1], 0x44);
    let sequence = auth.verify(&buffer[..length], sequence).unwrap();
    engine.stop();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let stopped = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(stopped.state, State::AdminDown);
    assert_eq!(stopped.diagnostic, 7);
    assert_eq!(buffer[1], 0x04, "AdminDown and Authentication only");
    assert!(auth.verify(&buffer[..length], sequence).is_ok());
    let contents = std::fs::read_to_string(log.path()).unwrap();
    for (change, count) in [
        ("state=Up diagnostic=None", 1),
        ("state=Up diagnostic=NeighborDown", 1),
        ("state=Down diagnostic=NeighborDown", 1),
        ("state=Down diagnostic=DetectionExpired", 1),
        ("state=AdminDown diagnostic=AdminDown", 1),
    ] {
        assert_eq!(
            contents
                .lines()
                .filter(|line| {
                    [102, 103, 106]
                        .iter()
                        .any(|id| line.contains(&format!("event_id={id} ")))
                        && line.contains(change)
                })
                .count(),
            count,
            "{contents}"
        );
    }
    for id in [201, 203, 207] {
        let expected = format!("event_id={id} level=Warning scope=Local");
        assert_eq!(contents.matches(&expected).count(), 1, "{contents}");
    }
}

#[test]
fn peer_diagnostics_and_states_are_logged_without_local_state_changes() {
    let log_file = test_log("peer-diagnostics");
    let mut options = options("127.0.0.100", "127.0.0.101", "multihop");
    options.source_port = Some(55100);
    options.log_to_file = true;
    options.log_file_path = log_file.path().to_path_buf();
    let peer = UdpSocket::bind("127.0.0.101:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let sender = bfd_sender("127.0.0.101");
    let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut engine = RunningEngine::start(options);
    let mut buffer = [0; 512];
    peer.recv_from(&mut buffer).unwrap();
    let mut packet = peer_packet(State::Down);
    packet.poll = true;
    packet.desired_min_tx_us = 100_000;
    let mut exchange = |packet: &ControlPacket| {
        sender
            .send_to(&packet.encode(&auth, 0), "127.0.0.100:4784")
            .unwrap();
        loop {
            let (length, _) = peer.recv_from(&mut buffer).unwrap();
            let response = ControlPacket::decode(&buffer[..length]).unwrap();
            if response.final_bit {
                return response;
            }
        }
    };
    assert_eq!(exchange(&packet).state, State::Init);
    assert_eq!(exchange(&packet).state, State::Init); // Repeated remote Down is silent.
    packet.state = State::Init;
    packet.your_discriminator = 7;
    assert_eq!(exchange(&packet).state, State::Up);
    packet.state = State::Up;
    for diagnostic in 1..=8 {
        packet.diagnostic = diagnostic;
        for _ in 0..2 {
            let response = exchange(&packet);
            assert_eq!(response.state, State::Up);
            assert_eq!(
                response.diagnostic, 0,
                "peer diagnostics never become LocalDiag"
            );
        }
    }
    for diagnostic in [0, 9, 31] {
        packet.diagnostic = diagnostic;
        assert_eq!(exchange(&packet).state, State::Up);
    }
    packet.diagnostic = 0;
    packet.state = State::Down;
    assert_eq!(exchange(&packet).state, State::Down);
    packet.state = State::AdminDown;
    assert_eq!(exchange(&packet).state, State::Down); // Remote state changes, local state doesn't.
    engine.stop();
    let contents = std::fs::read_to_string(log_file.path()).unwrap();
    for (code, level) in [
        (1, "Warning"),
        (2, "Error"),
        (3, "Warning"),
        (4, "Error"),
        (5, "Error"),
        (6, "Error"),
        (7, "Warning"),
        (8, "Error"),
    ] {
        let expected = format!("event_id={} level={level} scope=Remote", 200 + code);
        assert_eq!(contents.matches(&expected).count(), 1, "{contents}");
    }
    assert_eq!(contents.matches("event_id=111 level=Warning").count(), 2);
    assert_eq!(
        contents.matches("event_id=110 level=Information").count(),
        1
    );
    assert_eq!(
        contents.matches("event_id=102 level=Information").count(),
        1
    );
    assert_eq!(contents.matches("event_id=103 level=Warning").count(), 1);
    assert!(!contents.contains("event_id=200"));
    assert!(!contents.contains("event_id=209"));
    assert!(!contents.contains("event_id=231"));
}

#[test]
fn normal_shutdown_announces_admin_down_for_the_detection_period() {
    let mut options = options("127.0.0.90", "127.0.0.91", "multihop");
    options.source_port = Some(55090);
    let peer = UdpSocket::bind("127.0.0.91:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let sender = bfd_sender("127.0.0.91");
    let mut engine = RunningEngine::start(options);
    let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut buffer = [0; 512];
    peer.recv_from(&mut buffer).unwrap();
    let mut packet = peer_packet(State::Init);
    packet.desired_min_tx_us = 800_000; // 3 × 800 ms = 2.4 s detection.
    packet.detect_mult = 3;
    sender
        .send_to(&packet.encode(&auth, 0), "127.0.0.90:4784")
        .unwrap();
    loop {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        if ControlPacket::decode(&buffer[..length]).unwrap().state == State::Up {
            break;
        }
    }
    let started = Instant::now();
    engine.stop.signal().unwrap();
    let mut announcements = 0;
    while announcements < 2 {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        let packet = ControlPacket::decode(&buffer[..length]).unwrap();
        if packet.state == State::AdminDown {
            assert_eq!(packet.diagnostic, 7);
            assert!(!packet.poll && !packet.final_bit);
            announcements += 1;
        }
    }
    engine.worker.take().unwrap().join().unwrap().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(2300));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn shutdown_announces_for_the_peers_full_detection_time_without_a_cap() {
    let mut options = options("127.0.0.92", "127.0.0.93", "multihop");
    options.source_port = Some(55092);
    let peer = UdpSocket::bind("127.0.0.93:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let sender = bfd_sender("127.0.0.93");
    let mut engine = RunningEngine::start(options);
    let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut buffer = [0; 512];
    peer.recv_from(&mut buffer).unwrap();
    let mut packet = peer_packet(State::Init);
    packet.desired_min_tx_us = 1_000_000;
    packet.detect_mult = 3; // Local Detection Time: 3 × 1 s.
                            // The peer's Detection Time for our packets: local DetectMult 3 × 2.5 s.
    packet.required_min_rx_us = 2_500_000;
    sender
        .send_to(&packet.encode(&auth, 0), "127.0.0.92:4784")
        .unwrap();
    loop {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        if ControlPacket::decode(&buffer[..length]).unwrap().state == State::Up {
            break;
        }
    }
    let started = Instant::now();
    engine.stop.signal().unwrap();
    let mut announcements = 0;
    while announcements < 2 {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        if ControlPacket::decode(&buffer[..length]).unwrap().state == State::AdminDown {
            announcements += 1;
        }
    }
    engine.worker.take().unwrap().join().unwrap().unwrap();
    // RFC 5880 section 6.8.16: at least the longer Detection Time, beyond the former 5 s cap.
    assert!(
        started.elapsed() >= Duration::from_millis(7400),
        "{:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn peer_polls_do_not_starve_the_local_periodic_poll_sequence() {
    let mut options = options("127.0.0.30", "127.0.0.31", "multihop");
    options.min_tx_us = 300000;
    let peer = UdpSocket::bind("127.0.0.31:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let sender = bfd_sender("127.0.0.31");
    let mut engine = RunningEngine::start(options);
    let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
    let mut buffer = [0; 512];
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Down
    );

    // Enter Up while answering the peer's Poll: the Final advertises our new
    // timers, but our own Poll sequence still needs a periodic transmission.
    let mut packet = peer_packet(State::Init);
    packet.poll = true;
    packet.required_min_rx_us = 300000;
    sender
        .send_to(&packet.encode(&auth, 0), "127.0.0.30:4784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    let reply = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(reply.state, State::Up);
    assert!(reply.final_bit);
    assert!(!reply.poll);

    packet.state = State::Up;
    packet.desired_min_tx_us = 100000;
    peer.set_nonblocking(true).unwrap();
    let started = Instant::now();
    let mut next_poll = started;
    let mut local_polls = 0;
    let mut final_replies = 0;
    while started.elapsed() < Duration::from_secs(1) {
        let now = Instant::now();
        if now >= next_poll {
            // Repeated peer Polls model lost Final replies. Their 100 ms
            // interval is shorter than our 225–300 ms periodic interval.
            sender
                .send_to(&packet.encode(&auth, 0), "127.0.0.30:4784")
                .unwrap();
            next_poll = now + Duration::from_millis(100);
        }
        match peer.recv_from(&mut buffer) {
            Ok((length, _)) => {
                let reply = ControlPacket::decode(&buffer[..length]).unwrap();
                assert_eq!(reply.state, State::Up);
                assert!(!(reply.poll && reply.final_bit));
                local_polls += usize::from(reply.poll);
                final_replies += usize::from(reply.final_bit);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("receiving BFD response: {error}"),
        }
        thread::sleep(Duration::from_millis(1));
    }
    engine.stop();
    assert!(final_replies >= 5, "peer Polls were not answered");
    assert!(
        local_polls >= 2,
        "Final replies starved the local Poll sequence"
    );
}

#[test]
fn point_to_point_bootstrap_and_source_changes_keep_the_configured_destination() {
    let mut options = options("127.0.0.40", "127.0.0.41", "single-hop");
    let initial_sender = bfd_sender("127.0.0.42");
    initial_sender.set_ttl(255).unwrap();
    let changed_sender = bfd_sender("127.0.0.43");
    changed_sender.set_ttl(255).unwrap();
    // Discover the Windows loopback interface without assuming its index.
    options.interface_index = Some(loopback_interface(&options));
    options.point_to_point = true;
    options.auth = AuthType::MeticulousSha1;
    options.auth_key = Some("secret".to_owned());
    let auth = options.validate().unwrap();
    let peer = UdpSocket::bind("127.0.0.41:3784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut engine = RunningEngine::start(options);
    let mut buffer = [0; 512];
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(
        ControlPacket::decode(&buffer[..length]).unwrap().state,
        State::Down
    );
    let mut received_sequence = auth.verify(&buffer[..length], None).unwrap();

    let mut packet = peer_packet(State::Down);
    initial_sender
        .send_to(&packet.encode(&auth, 100), "127.0.0.40:3784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    received_sequence = auth.verify(&buffer[..length], received_sequence).unwrap();
    let init = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(init.state, State::Init);
    assert_eq!(init.your_discriminator, 99);

    packet.state = State::Init;
    packet.your_discriminator = 7;
    changed_sender
        .send_to(&packet.encode(&auth, 101), "127.0.0.40:3784")
        .unwrap();
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    received_sequence = auth.verify(&buffer[..length], received_sequence).unwrap();
    let up = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(up.state, State::Up);
    assert!(!up.poll && !up.final_bit);
    let (length, _) = peer.recv_from(&mut buffer).unwrap();
    received_sequence = auth.verify(&buffer[..length], received_sequence).unwrap();
    let poll = ControlPacket::decode(&buffer[..length]).unwrap();
    assert_eq!(poll.state, State::Up);
    assert!(poll.poll && !poll.final_bit);

    // A later Poll from the changed source must also get its Final at Peer.
    packet.state = State::Up;
    packet.final_bit = true;
    // Acknowledge our Poll first; the peer's separate Poll never sets both bits.
    changed_sender
        .send_to(&packet.encode(&auth, 102), "127.0.0.40:3784")
        .unwrap();
    packet.poll = true;
    packet.final_bit = false;
    packet.desired_min_tx_us = 100000;
    changed_sender
        .send_to(&packet.encode(&auth, 103), "127.0.0.40:3784")
        .unwrap();
    loop {
        let (length, _) = peer.recv_from(&mut buffer).unwrap();
        received_sequence = auth.verify(&buffer[..length], received_sequence).unwrap();
        let reply = ControlPacket::decode(&buffer[..length]).unwrap();
        assert_eq!(reply.state, State::Up);
        if reply.final_bit {
            assert!(!reply.poll);
            assert_eq!(reply.your_discriminator, 99);
            break;
        }
    }
    engine.stop();
}
