//! Exercise status publication alongside real BFD traffic and concurrent readers.
#![cfg(windows)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use bfd_winservice::{
    config::Options,
    packet::{AuthConfig, AuthType, ControlPacket, State},
    runtime::{Engine, Logger, StateObserver, StatusObserver, StopSignal},
};
use std::{
    io,
    net::UdpSocket,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct RunningEngine {
    state: StateObserver,
    status: StatusObserver,
    stop: StopSignal,
    worker: Option<thread::JoinHandle<io::Result<()>>>,
}

impl RunningEngine {
    fn start() -> Self {
        let mut options =
            Options::new("127.0.0.86".parse().unwrap(), "127.0.0.87".parse().unwrap());
        options.multihop = true;
        options.passive = true;
        options.discriminator = Some(7);
        options.min_tx_us = 100_000;
        options.min_rx_us = 100_000;
        options.max_shutdown_announce_ms = 1;
        let mut logger = Logger::new(false).unwrap();
        let mut engine =
            Engine::from_config(options.into_validated().unwrap(), &mut logger).unwrap();
        let stop = StopSignal::new().unwrap();
        let worker_stop = stop.clone();
        Self {
            state: engine.state_observer(),
            status: engine.status_observer(),
            stop,
            worker: Some(thread::spawn(move || {
                engine.run_until(&worker_stop, &mut logger)
            })),
        }
    }
}

impl Drop for RunningEngine {
    fn drop(&mut self) {
        let _ = self.stop.signal();
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap().unwrap();
        }
    }
}

fn sender() -> UdpSocket {
    for port in 49152..=65535 {
        match UdpSocket::bind(("127.0.0.87", port)) {
            Ok(socket) => {
                socket.set_ttl(255).unwrap();
                return socket;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => panic!("status test sender: {error}"),
        }
    }
    panic!("no free BFD test source port");
}

fn packet(state: State) -> Vec<u8> {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 30,
        my_discriminator: 99,
        your_discriminator: if state == State::Down { 0 } else { 7 },
        desired_min_tx_us: 100_000,
        required_min_rx_us: 100_000,
        required_min_echo_rx_us: 0,
    }
    .encode(&AuthConfig::new(AuthType::None, 0, vec![]).unwrap(), 0)
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "status condition did not become true"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn retained_snapshots_and_busy_readers_do_not_delay_live_bfd_or_publication() {
    let peer = UdpSocket::bind("127.0.0.87:4784").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let sender = sender();
    let mut engine = RunningEngine::start();
    let initial = engine.status.snapshot().unwrap();
    let readers_running = Arc::new(AtomicBool::new(true));

    thread::scope(|scope| {
        let mut readers = Vec::new();
        for _ in 0..4 {
            let observer = engine.status.clone();
            let running = Arc::clone(&readers_running);
            readers.push(scope.spawn(move || {
                while running.load(Ordering::Relaxed) {
                    if let Some(snapshot) = observer.snapshot() {
                        assert_eq!(snapshot.local_discriminator, 7);
                        assert_eq!(snapshot.peer_address.unwrap().to_string(), "127.0.0.87");
                    }
                    thread::yield_now();
                }
            }));
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sender
                .send_to(&packet(State::Down), "127.0.0.86:4784")
                .unwrap();
            wait_until(|| engine.state.current() == Some(State::Init));
            sender
                .send_to(&packet(State::Init), "127.0.0.86:4784")
                .unwrap();
            wait_until(|| engine.state.current() == Some(State::Up));

            let deadline = Instant::now() + Duration::from_millis(1300);
            let valid = packet(State::Up);
            while Instant::now() < deadline {
                sender.send_to(&valid, "127.0.0.86:4784").unwrap();
                sender.send_to(&[0; 24], "127.0.0.86:4784").unwrap();
                thread::sleep(Duration::from_millis(2));
            }
            wait_until(|| {
                engine.status.snapshot().is_some_and(|snapshot| {
                    snapshot.local_state == State::Up
                        && snapshot.packets_received_accepted > 2
                        && snapshot.packets_rejected > 0
                })
            });
            let snapshot = engine.status.snapshot().unwrap();
            assert!(snapshot.packets_sent_successfully > 0);
            assert!(snapshot.last_valid_receive_utc.is_some());
            assert!(snapshot.last_successful_send_utc.is_some());
            assert_eq!(initial.local_state, State::Down);
            assert_eq!(initial.packets_received_accepted, 0);
            assert_eq!(engine.state.current(), Some(State::Up));
            let mut buffer = [0; 256];
            let (length, _) = peer.recv_from(&mut buffer).unwrap();
            assert!(ControlPacket::decode(&buffer[..length]).is_ok());
        }));
        readers_running.store(false, Ordering::Relaxed);
        for reader in readers {
            reader.join().unwrap();
        }
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    });

    engine.stop.signal().unwrap();
    engine.worker.take().unwrap().join().unwrap().unwrap();
    assert!(engine.status.snapshot().is_none());
    assert!(engine.state.current().is_none());
    assert_eq!(initial.local_state, State::Down);
}
