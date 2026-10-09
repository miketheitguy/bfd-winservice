//! RFC 5880 state, timer, diagnostic, and Poll boundary regressions.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
use bfd_winservice::{
    config::{Mode, Options, SessionType, Timing},
    error::AuthError,
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
    seamless::Reflector,
    session::{ReceiveError, Session},
};
use std::time::{Duration, Instant};

fn classical(kind: AuthType) -> (Session, AuthConfig) {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.mode = Mode::Multihop;
    options.discriminator = Some(7);
    options.min_tx_us = 100_000;
    options.min_rx_us = 100_000;
    options.auth = kind;
    if kind != AuthType::None {
        options.auth_key = Some("test-key".into());
    }
    let auth = options.validate().unwrap();
    (Session::new(options, auth.clone()).unwrap(), auth)
}

fn peer(state: State) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 3,
        my_discriminator: 99,
        your_discriminator: 7,
        desired_min_tx_us: 100_000,
        required_min_rx_us: 100_000,
        required_min_echo_rx_us: 0,
    }
}

#[test]
fn recovery_preserves_the_last_failure_diagnostic() {
    let (mut session, auth) = classical(AuthType::None);
    let now = Instant::now();
    session
        .receive(&peer(State::Init).encode(&auth, 0), now)
        .unwrap();
    let expired = now + session.detection_time();
    assert!(session.expire(expired));
    session
        .receive(&peer(State::Init).encode(&auth, 0), expired)
        .unwrap();
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
    assert_eq!(
        ControlPacket::decode(&session.packet(false))
            .unwrap()
            .diagnostic,
        1
    );
    session
        .receive(&peer(State::Down).encode(&auth, 0), expired)
        .unwrap();
    session
        .receive(&peer(State::Init).encode(&auth, 0), expired)
        .unwrap();
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.diagnostic(), Diagnostic::NeighborDown);
}

#[test]
fn zero_receive_interval_expires_and_active_probing_resumes() {
    let (mut session, auth) = classical(AuthType::None);
    let mut packet = peer(State::Init);
    packet.required_min_rx_us = 0;
    let now = Instant::now();
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    assert!(!session.periodic_enabled());
    assert!(session.expire(now + session.detection_time()));
    assert_eq!(session.remote_discriminator(), 0);
    assert!(
        session.periodic_enabled(),
        "an expired zero-RX advertisement must not suppress probes forever"
    );
}

#[test]
fn admin_down_reception_preserves_a_fresh_authentication_window() {
    let (mut session, auth) = classical(AuthType::MeticulousSha1);
    let now = Instant::now();
    session
        .receive(&peer(State::Init).encode(&auth, 100), now)
        .unwrap();
    let detection = session.detection_time();
    session.admin_down();
    session
        .receive(&peer(State::Down).encode(&auth, 101), now + detection)
        .unwrap();
    session
        .receive(&peer(State::Down).encode(&auth, 102), now + detection * 2)
        .unwrap();
    assert_eq!(
        session
            .receive(
                &peer(State::Down).encode(&auth, 101),
                now + detection * 2 + Duration::from_micros(1)
            )
            .err(),
        Some(ReceiveError::Authentication(AuthError::SequenceWindow))
    );
    assert_eq!(session.state(), State::AdminDown);
    assert_eq!(session.diagnostic(), Diagnostic::AdminDown);
}

#[test]
fn admin_down_discriminator_expires_without_starting_a_detection_timer() {
    let (mut session, auth) = classical(AuthType::None);
    session.admin_down();
    let now = Instant::now();
    let mut packet = peer(State::Down);
    packet.poll = true;
    let result = session.receive(&packet.encode(&auth, 0), now).unwrap();
    assert!(!result.reply_final);
    assert_eq!(session.remote_discriminator(), 99);
    assert!(!session.expire(now + session.detection_time()));
    assert_eq!(session.remote_discriminator(), 0);
    assert_eq!(session.state(), State::AdminDown);
    assert_eq!(session.diagnostic(), Diagnostic::AdminDown);
}

#[test]
fn final_cannot_complete_a_poll_that_has_not_been_transmitted() {
    let (mut session, auth) = classical(AuthType::None);
    let now = Instant::now();
    session
        .receive(&peer(State::Init).encode(&auth, 0), now)
        .unwrap();
    let mut final_packet = peer(State::Up);
    final_packet.final_bit = true;
    session
        .receive(&final_packet.encode(&auth, 0), now)
        .unwrap();
    assert!(session.polling());
    assert!(
        ControlPacket::decode(&session.packet_at(false, now))
            .unwrap()
            .poll
    );
    session
        .receive(&final_packet.encode(&auth, 0), now)
        .unwrap();
    assert!(!session.polling());
}

fn established_initiator(now: Instant) -> (Session, Reflector) {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.session_type = SessionType::SbfdInitiator;
    options.remote_discriminator = Some(99);
    options.discriminator = Some(7);
    options.min_tx_us = 100_000;
    let auth = options.validate().unwrap();
    let mut session = Session::new(options, auth).unwrap();
    let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
    options.min_rx_us = 100_000;
    let auth = options.validate().unwrap();
    let reflector = Reflector::new(options, auth).unwrap();
    for _ in 0..3 {
        let request = session.packet_at(false, now);
        session
            .receive(&reflector.respond(&request).unwrap(), now)
            .unwrap();
    }
    assert!(!session.polling());
    (session, reflector)
}

#[test]
fn increased_transmit_interval_waits_for_the_poll_final() {
    let now = Instant::now();
    let (mut session, reflector) = established_initiator(now);
    session
        .set_timing(Timing::new(500_000, 300_000, 3).unwrap())
        .unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_millis(100));
    let request = session.packet_at(false, now);
    let packet = ControlPacket::decode(&request).unwrap();
    assert!(packet.poll);
    assert_eq!(packet.desired_min_tx_us, 500_000);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_millis(500));
}

#[test]
fn overlapping_timer_changes_cannot_make_the_final_ambiguous() {
    let now = Instant::now();
    let (mut session, reflector) = established_initiator(now);
    session
        .set_timing(Timing::new(500_000, 300_000, 3).unwrap())
        .unwrap();
    let request = session.packet_at(false, now);
    assert!(session
        .set_timing(Timing::new(700_000, 300_000, 3).unwrap())
        .is_err());
    assert_eq!(session.desired_min_tx_us(), 500_000);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    assert!(session
        .set_timing(Timing::new(700_000, 300_000, 3).unwrap())
        .is_err());
    let request = session.packet_at(false, now);
    assert!(!ControlPacket::decode(&request).unwrap().poll);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    session
        .set_timing(Timing::new(700_000, 300_000, 3).unwrap())
        .unwrap();
}

#[test]
fn unanswered_multihop_probes_back_off_and_recover() {
    let (mut session, auth) = classical(AuthType::None);
    let now = Instant::now();
    session.packet_at(false, now);
    assert!(!session.expire(now + Duration::from_secs(3)));
    assert_eq!(session.desired_min_tx_us(), 2_000_000);
    assert!(!session.expire(now + Duration::from_secs(9)));
    assert_eq!(session.desired_min_tx_us(), 4_000_000);
    session
        .receive(
            &peer(State::Init).encode(&auth, 0),
            now + Duration::from_secs(9),
        )
        .unwrap();
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.transmit_interval(), Duration::from_millis(100));
}

#[test]
fn multihop_timeout_backoff_preserves_a_slow_peers_rate_as_its_floor() {
    let (mut session, auth) = classical(AuthType::None);
    let mut packet = peer(State::Init);
    packet.required_min_rx_us = 5_000_000;
    let now = Instant::now();
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_secs(5));
    assert!(session.expire(now + session.detection_time()));
    assert_eq!(session.transmit_interval(), Duration::from_secs(10));
    packet.required_min_rx_us = 100_000;
    session
        .receive(&packet.encode(&auth, 0), now + Duration::from_secs(1))
        .unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_millis(100));
}
