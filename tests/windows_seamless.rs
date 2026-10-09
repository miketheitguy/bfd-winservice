#![cfg(windows)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)] // Test fixtures fail immediately on invalid setup.
use bfd_winservice::{
    config::{Options, SessionType},
    packet::{AuthType, State},
    runtime::{Engine, Logger, StopSignal},
    seamless::Reflector,
    session::Session,
    transport::{Datagram, Transport},
};
use std::{
    io,
    net::{IpAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

struct RunningEngine {
    stop: StopSignal,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}
impl RunningEngine {
    fn start(mut options: Options) -> Self {
        let auth = options.validate().unwrap();
        let mut log = Logger::open(&options).unwrap();
        let mut engine = Engine::open(options, auth, &mut log).unwrap();
        let stop = StopSignal::new().unwrap();
        let receiver = stop.clone();
        Self {
            stop,
            worker: Some(thread::spawn(move || engine.run_until(&receiver, &mut log))),
        }
    }
}
impl Drop for RunningEngine {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.signal();
            worker.join().unwrap().unwrap();
        }
    }
}

fn initiator(local: &str, peer: &str, discriminator: u32) -> Options {
    let mut options = Options::new(local.parse().unwrap(), peer.parse().unwrap());
    options.session_type = SessionType::SbfdInitiator;
    options.remote_discriminator = Some(99);
    options.discriminator = Some(discriminator);
    options.min_tx_us = 100_000;
    options.min_rx_us = 100_000;
    options.auth = AuthType::MeticulousSha1;
    options.auth_key = Some("secret".into());
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
            Err(error) => panic!("S-BFD receive: {error}"),
        }
    }
}

#[test]
fn windows_reflector_serves_multiple_authenticated_initiators_from_port_7784() {
    let mut reflector = Options::reflector("127.0.0.90".parse().unwrap(), 99);
    reflector.auth = AuthType::MeticulousSha1;
    reflector.auth_key = Some("secret".into());
    let _engine = RunningEngine::start(reflector);
    let mut clients = Vec::new();
    for (local, discriminator) in [("127.0.0.91", 7), ("127.0.0.91", 8), ("127.0.0.92", 9)] {
        let mut options = initiator(local, "127.0.0.90", discriminator);
        let auth = options.validate().unwrap();
        let transport = Transport::open(&options).unwrap();
        assert_ne!(transport.source_port, 7784);
        transport.wait_readable(Duration::from_millis(30)).unwrap();
        assert_eq!(
            transport
                .receive()
                .err()
                .expect("reflector sends no unsolicited traffic")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let session = Session::new(options.clone(), auth.clone()).unwrap();
        clients.push((options, auth, transport, session));
    }
    for (options, auth, transport, session) in &mut clients {
        let request = session.packet(false);
        transport.send(&request).unwrap();
        let response = receive(transport);
        response.validate(options).unwrap();
        assert_eq!(response.source.port(), 7784);
        assert_eq!(response.ttl, Some(255));
        assert_eq!(
            auth.verify(&request, None),
            auth.verify(&response.data, None)
        );
        session.receive(&response.data, Instant::now()).unwrap();
        assert_eq!(session.state(), State::Up);
    }
}

#[test]
fn windows_maintenance_replies_never_trigger_retries_faster_than_one_second() {
    let target = UdpSocket::bind("127.0.0.98:7784").unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut options = initiator("127.0.0.99", "127.0.0.98", 7);
    options.detect_mult = 1;
    let auth = options.validate().unwrap();
    let mut reflector_options = Options::reflector(options.peer, 99);
    reflector_options.auth = options.auth;
    reflector_options.auth_key = options.auth_key.clone();
    reflector_options.sbfd_admin_down = true;
    let reflector = Reflector::new(reflector_options, auth).unwrap();
    let _engine = RunningEngine::start(options);
    let mut buffer = [0; 256];
    let (length, source) = target.recv_from(&mut buffer).unwrap();
    let first = Instant::now();
    target
        .send_to(&reflector.respond(&buffer[..length]).unwrap(), source)
        .unwrap();
    target.recv_from(&mut buffer).unwrap();
    assert!(
        first.elapsed() >= Duration::from_millis(950),
        "fast maintenance retry: {:?}",
        first.elapsed()
    );
}

#[test]
fn windows_ipv6_uses_the_initiators_source_socket_for_return_traffic() {
    let mut reflector_options = Options::reflector("::1".parse().unwrap(), 99);
    let reflector_auth = reflector_options.validate().unwrap();
    let reflector = Reflector::new(reflector_options.clone(), reflector_auth).unwrap();
    let reflector_transport = Transport::open(&reflector_options).unwrap();
    let mut options = initiator("::1", "::1", 7);
    options.auth = AuthType::None;
    options.auth_key = None;
    let auth = options.validate().unwrap();
    let mut session = Session::new(options.clone(), auth).unwrap();
    let transport = Transport::open(&options).unwrap();
    transport.send(&session.packet(false)).unwrap();
    let request = receive(&reflector_transport);
    request.validate(&reflector_options).unwrap();
    assert_eq!(request.source.port(), transport.source_port);
    reflector_transport
        .send_reply(
            &reflector.respond(&request.data).unwrap(),
            &request,
            &reflector_options,
        )
        .unwrap();
    let response = receive(&transport);
    response.validate(&options).unwrap();
    assert_eq!(response.ttl, Some(255));
    session.receive(&response.data, Instant::now()).unwrap();
    assert_eq!(session.state(), State::Up);
}

#[test]
fn windows_anycast_responses_can_change_source_without_resetting_the_session() {
    let target = UdpSocket::bind("127.0.0.93:7784").unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let alternate = UdpSocket::bind("127.0.0.94:7784").unwrap();
    alternate.set_ttl(255).unwrap();
    let mut options = initiator("127.0.0.95", "127.0.0.93", 7);
    options.allowed_peers = vec!["127.0.0.94".parse().unwrap()];
    let auth = options.validate().unwrap();
    let transport = Transport::open(&options).unwrap();
    let mut session = Session::new(options.clone(), auth.clone()).unwrap();
    let mut reflector_options = Options::reflector("127.0.0.93".parse().unwrap(), 99);
    reflector_options.auth = options.auth;
    reflector_options.auth_key = options.auth_key.clone();
    let reflector = Reflector::new(reflector_options, auth).unwrap();
    let mut buffer = [0; 256];
    for responder in [&target, &alternate] {
        transport.send(&session.packet(false)).unwrap();
        let (length, source) = target.recv_from(&mut buffer).unwrap();
        responder
            .send_to(&reflector.respond(&buffer[..length]).unwrap(), source)
            .unwrap();
        let response = receive(&transport);
        response.validate(&options).unwrap();
        session.receive(&response.data, Instant::now()).unwrap();
        assert_eq!(session.state(), State::Up);
        assert_eq!(session.remote_discriminator(), 99);
    }
}

#[test]
fn windows_filters_reject_disallowed_sources_ports_and_martian_addresses() {
    let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
    options.allowed_peers = vec!["192.0.2.1".parse().unwrap()];
    options.validate().unwrap();
    let mut request = Datagram {
        data: vec![],
        source: "192.0.2.1:12345".parse().unwrap(),
        destination: Some(options.local),
        interface_index: Some(1),
        ttl: Some(200),
    };
    request.validate(&options).unwrap();
    request.source.set_port(7784);
    assert!(request.validate(&options).is_err());
    request.source = "192.0.2.3:12345".parse().unwrap();
    assert!(request.validate(&options).is_err());
    options.allowed_peers.clear();
    for ip in [
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "127.0.0.1",
    ] {
        request.source.set_ip(ip.parse::<IpAddr>().unwrap());
        assert!(request.validate(&options).is_err(), "{ip}");
    }
}

#[test]
fn windows_initiator_reports_one_reply_up_and_then_detection_failure() {
    let log_file = tempfile::NamedTempFile::new().unwrap();
    let mut reflector_options = Options::reflector("127.0.0.96".parse().unwrap(), 99);
    reflector_options.auth = AuthType::MeticulousSha1;
    reflector_options.auth_key = Some("secret".into());
    reflector_options.min_rx_us = 100_000;
    let reflector = RunningEngine::start(reflector_options);
    let mut options = initiator("127.0.0.97", "127.0.0.96", 7);
    options.log_to_file = true;
    options.log_file_path = log_file.path().into();
    let _initiator = RunningEngine::start(options);
    wait_log(log_file.path(), "state=Up");
    drop(reflector);
    wait_log(log_file.path(), "diagnostic=DetectionExpired");
    let contents = std::fs::read_to_string(log_file.path()).unwrap();
    assert_eq!(contents.matches("communication=started").count(), 1);
    assert_eq!(contents.matches("communication=stopped").count(), 1);
    assert!(!contents.contains("state=Init"));
}

fn wait_log(path: &std::path::Path, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let contents = std::fs::read_to_string(path).unwrap();
        if contents.contains(message) {
            return;
        }
        assert!(Instant::now() < deadline, "missing {message}: {contents}");
        thread::sleep(Duration::from_millis(10));
    }
}
