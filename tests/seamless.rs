#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)] // Test fixtures fail immediately on invalid setup.

use bfd_winservice::{
    config::{Options, SessionType, Timing},
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
    seamless::Reflector,
    session::Session,
};
use std::time::{Duration, Instant};

fn initiator_options() -> Options {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.session_type = SessionType::SbfdInitiator;
    options.remote_discriminator = Some(99);
    options.discriminator = Some(7);
    options.min_tx_us = 100_000;
    options.min_rx_us = 100_000;
    options
}

fn pair(kind: AuthType) -> (Session, Reflector, AuthConfig) {
    let mut options = initiator_options();
    options.auth = kind;
    if kind != AuthType::None {
        options.auth_key = Some("secret".into());
    }
    let auth = options.validate().unwrap();
    let mut reflector_options = Options::reflector(options.peer, 99);
    reflector_options.min_rx_us = 100_000;
    reflector_options.auth = kind;
    reflector_options.auth_key = options.auth_key.clone();
    (
        Session::new(options, auth.clone()).unwrap(),
        Reflector::new(reflector_options, auth.clone()).unwrap(),
        auth,
    )
}

#[test]
fn seamless_initiator_targets_the_reflector_before_any_handshake() {
    let mut options = initiator_options();
    let auth = options.validate().unwrap();
    let mut session = Session::new(options, auth).unwrap();
    let packet = ControlPacket::decode(&session.packet(false)).unwrap();
    assert_eq!(packet.state, State::Down);
    assert!(packet.demand);
    assert_eq!(packet.your_discriminator, 99);
    assert_eq!(packet.required_min_rx_us, 0);
    assert_eq!(packet.required_min_echo_rx_us, 0);
}

#[test]
fn one_reply_establishes_the_session_and_finishes_a_poll() {
    let (mut session, reflector, auth) = pair(AuthType::None);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    let reply = reflector.respond(&request).unwrap();
    let decoded = ControlPacket::decode(&reply).unwrap();
    assert_eq!(decoded.my_discriminator, 99);
    assert_eq!(decoded.your_discriminator, 7);
    assert_eq!(decoded.desired_min_tx_us, 1_000_000);
    assert_eq!(decoded.detect_mult, 3);
    assert!(!decoded.demand);
    assert_eq!(decoded.state, State::Up);
    assert!(
        session
            .receive(&reply, now + Duration::from_millis(20))
            .unwrap()
            .state_changed
    );
    assert_eq!(session.state(), State::Up);
    assert!(session.communicating());
    assert!(session.polling());
    let request = session.packet_at(false, now + Duration::from_millis(100));
    assert!(ControlPacket::decode(&request).unwrap().poll);
    let reply = reflector.respond(&request).unwrap();
    assert!(ControlPacket::decode(&reply).unwrap().final_bit);
    session
        .receive(&reply, now + Duration::from_millis(120))
        .unwrap();
    assert!(!session.polling());
    assert!(session.periodic_enabled());
    let mut zero_rx = ControlPacket::decode(&reply).unwrap();
    zero_rx.required_min_rx_us = 0;
    session
        .receive(&zero_rx.encode(&auth, 0), now + Duration::from_millis(130))
        .unwrap();
    assert!(session.periodic_enabled());
}

#[test]
fn maintenance_keeps_communication_and_slows_actual_transmissions() {
    let (mut session, mut reflector, auth) = pair(AuthType::None);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    reflector.set_admin_down(true);
    let request = session.packet_at(false, now + Duration::from_millis(100));
    let mut reply = ControlPacket::decode(&reflector.respond(&request).unwrap()).unwrap();
    reply.poll = true;
    reply.final_bit = false;
    session
        .receive(&reply.encode(&auth, 0), now + Duration::from_millis(120))
        .unwrap();
    assert_eq!(session.state(), State::Down);
    assert!(session.communicating());
    for _ in 0..20 {
        assert!(session.jittered_interval() >= Duration::from_secs(1));
    }
    let next = ControlPacket::decode(&session.packet(false)).unwrap();
    assert!(next.final_bit);
    assert!(!next.poll);
    reflector.set_admin_down(false);
    session
        .receive(
            &reflector.respond(&next.encode(&auth, 0)).unwrap(),
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(session.state(), State::Up);
}

#[test]
fn timeout_keeps_the_target_and_backs_off_until_recovery() {
    let (mut session, reflector, _) = pair(AuthType::None);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    let deadline = session.detection_deadline().unwrap();
    assert!(!session.expire(deadline - Duration::from_micros(1)));
    assert!(session.expire(deadline));
    assert_eq!(session.state(), State::Down);
    assert!(!session.communicating());
    assert_eq!(session.remote_discriminator(), 99);
    let first_backoff = session.transmit_interval();
    assert!(!session.expire(session.detection_deadline().unwrap()));
    assert!(session.transmit_interval() > first_backoff);
    let request = session.packet_at(false, deadline + Duration::from_secs(20));
    session
        .receive(
            &reflector.respond(&request).unwrap(),
            deadline + Duration::from_secs(20),
        )
        .unwrap();
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.transmit_interval(), Duration::from_millis(100));
}

#[test]
fn maintenance_without_a_state_change_preserves_the_last_failure_diagnostic() {
    let (mut session, mut reflector, _) = pair(AuthType::None);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    assert!(session.expire(session.detection_deadline().unwrap()));
    assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
    reflector.set_admin_down(true);
    let request = session.packet_at(false, now + Duration::from_secs(20));
    let result = session
        .receive(
            &reflector.respond(&request).unwrap(),
            now + Duration::from_secs(20),
        )
        .unwrap();
    assert!(!result.state_changed);
    assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
    let diagnostic =
        ControlPacket::decode(&session.packet_at(false, now + Duration::from_secs(21)))
            .unwrap()
            .diagnostic;
    assert_eq!(diagnostic, 1);
}

#[test]
fn startup_detection_waits_for_the_round_trip_budget() {
    let mut options = initiator_options();
    options.min_rx_us = 5_000_000;
    let auth = options.validate().unwrap();
    let mut session = Session::new(options, auth).unwrap();
    assert!(session.detection_deadline().is_none());
    let now = Instant::now();
    session.packet_at(false, now);
    assert_eq!(
        session.detection_deadline(),
        Some(now + Duration::from_secs(8))
    );
    assert!(!session.expire(now + Duration::from_secs(5)));
    assert_eq!(session.transmit_interval(), Duration::from_secs(1));
}

#[test]
fn roles_reject_loop_packets_and_wrong_discriminators_before_mutation() {
    let (mut session, reflector, auth) = pair(AuthType::None);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    let mut decoded = ControlPacket::decode(&request).unwrap();
    decoded.demand = false;
    assert!(reflector.respond(&decoded.encode(&auth, 0)).is_err());
    decoded.demand = true;
    decoded.your_discriminator = 100;
    assert!(reflector.respond(&decoded.encode(&auth, 0)).is_err());
    decoded.your_discriminator = 99;
    decoded.required_min_rx_us = 1;
    assert!(reflector.respond(&decoded.encode(&auth, 0)).is_err());
    let reply = reflector.respond(&request).unwrap();
    for field in 0..5 {
        let mut bad = ControlPacket::decode(&reply).unwrap();
        match field {
            0 => bad.demand = true,
            1 => bad.state = State::Down,
            2 => bad.state = State::Init,
            3 => bad.your_discriminator = 0,
            _ => bad.my_discriminator = 100,
        }
        assert!(session.receive(&bad.encode(&auth, 0), now).is_err());
        assert_eq!(session.state(), State::Down);
        assert!(!session.communicating());
    }
}

#[test]
fn authentication_reflects_sequences_without_a_peer_window_and_blocks_replays() {
    for kind in [
        AuthType::SimplePassword,
        AuthType::KeyedSha1,
        AuthType::MeticulousSha1,
    ] {
        let (mut session, reflector, auth) = pair(kind);
        let now = Instant::now();
        let request = session.packet_at(false, now);
        let reply = reflector.respond(&request).unwrap();
        assert_eq!(auth.verify(&request, None), auth.verify(&reply, None));
        assert_eq!(reflector.respond(&request).unwrap(), reply);
        session.receive(&reply, now).unwrap();
        if kind != AuthType::SimplePassword {
            assert!(session.receive(&reply, now).is_err());
        }
        let mut bad = reply.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(session.receive(&bad, now).is_err());
        assert_eq!(session.state(), State::Up);
    }
}

#[test]
fn correctly_signed_but_unissued_or_expired_sequences_are_rejected() {
    let (mut session, reflector, auth) = pair(AuthType::MeticulousSha1);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    let sequence = auth.verify(&request, None).unwrap().unwrap();
    let packet = ControlPacket::decode(&request).unwrap();
    let unsolicited = reflector
        .respond(&packet.encode(&auth, sequence.wrapping_add(10)))
        .unwrap();
    assert!(session.receive(&unsolicited, now).is_err());
    let response = reflector.respond(&request).unwrap();
    assert!(session
        .receive(&response, now + session.detection_time())
        .is_err());
    assert!(!session.communicating());
}

#[test]
fn timing_changes_preserve_state_discriminators_and_authentication() {
    let (mut session, mut reflector, _) = pair(AuthType::MeticulousSha1);
    let now = Instant::now();
    let request = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    let timing = Timing::new(250_000, 500_000, 5).unwrap();
    session.set_timing(timing).unwrap();
    reflector.set_timing(timing);
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.local_discriminator(), 7);
    assert_eq!(session.remote_discriminator(), 99);
    assert!(session.polling());
    let request = session.packet_at(false, now + Duration::from_millis(250));
    let reply = reflector.respond(&request).unwrap();
    assert_eq!(
        ControlPacket::decode(&reply).unwrap().required_min_rx_us,
        500_000
    );
    session
        .receive(&reply, now + Duration::from_millis(260))
        .unwrap();
    assert_eq!(session.state(), State::Up);
    assert_eq!(session.transmit_interval(), Duration::from_millis(500));
    assert!(Timing::new(0, 1, 1).is_err());
}

#[test]
fn invalid_role_configuration_is_rejected() {
    use bfd_winservice::error::ConfigError;

    let options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
    let mismatched = AuthConfig::new(AuthType::SimplePassword, 1, b"secret".to_vec()).unwrap();
    assert!(matches!(
        Reflector::new(options, mismatched),
        Err(ConfigError::AuthenticationMismatch)
    ));
    let mut options = initiator_options();
    options.remote_discriminator = None;
    assert!(options.validate().is_err());
    let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 0);
    assert!(options.validate().is_err());
    let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
    options.bgp_peer_name = Some("Peer1".into());
    assert!(options.validate().is_err());
    let mut options = initiator_options();
    options.allowed_peers = vec!["::1".parse().unwrap()];
    assert!(options.validate().is_err());
    options.allowed_peers = vec!["224.0.0.1".parse().unwrap()];
    assert!(options.validate().is_err());
    let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
    options.peer = "fe80::1".parse().unwrap();
    assert!(
        options.validate().is_ok(),
        "reflectors ignore unused Peer addresses"
    );
}

#[test]
fn congestion_backoff_reduces_traffic_even_with_a_slow_reflector() {
    let (mut session, mut reflector, _) = pair(AuthType::None);
    reflector.set_timing(Timing::new(100_000, 5_000_000, 3).unwrap());
    let now = Instant::now();
    let request = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&request).unwrap(), now)
        .unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_secs(5));
    session.expire(session.detection_deadline().unwrap());
    assert_eq!(session.transmit_interval(), Duration::from_secs(10));
}
