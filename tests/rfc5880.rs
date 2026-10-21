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

const KEYED_TYPES: [AuthType; 2] = [AuthType::KeyedSha1, AuthType::MeticulousSha1];

#[test]
fn removed_md5_types_cannot_change_session_or_refresh_detection() {
    let sender = AuthConfig::new(AuthType::KeyedSha1, 0, b"test-key".to_vec()).unwrap();
    let now = Instant::now();
    for kind in [
        AuthType::None,
        AuthType::SimplePassword,
        AuthType::KeyedSha1,
        AuthType::MeticulousSha1,
    ] {
        let (mut session, auth) = classical(kind);
        session
            .receive(&peer(State::Init).encode(&auth, 100), now)
            .unwrap();
        let deadline = session.detection_deadline();
        for wire_type in [2, 3] {
            let mut data = peer(State::Down).encode(&sender, 101);
            // MD5's legacy authentication section is 24 bytes, including its digest.
            data.truncate(48);
            data[3] = 48;
            data[24] = wire_type;
            data[25] = 24;
            let expected = if kind == AuthType::None {
                AuthError::Unexpected
            } else {
                AuthError::WrongType
            };
            assert_eq!(
                session.receive(&data, now + Duration::from_millis(1)),
                Err(ReceiveError::Authentication(expected))
            );
            assert_eq!(session.state(), State::Up);
            assert_eq!(session.remote_state(), State::Init);
            assert_eq!(session.detection_deadline(), deadline);
        }
        // Rejected types must not consume the next legitimate authentication sequence.
        session
            .receive(
                &peer(State::Up).encode(&auth, 101),
                now + Duration::from_millis(2),
            )
            .unwrap();
    }
}

#[test]
fn asymmetric_timers_and_multiplier_changes_take_effect_at_exact_boundaries() {
    // RFC 5880 sections 6.8.2, 6.8.4 and 6.8.12: the peer's multiplier
    // controls reception; its RX limit independently controls transmission.
    let (mut session, auth) = classical(AuthType::None);
    let now = Instant::now();
    let mut packet = peer(State::Init);
    packet.desired_min_tx_us = 1_000_000;
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    packet.state = State::Up;
    packet.desired_min_tx_us = 250_000;
    packet.required_min_rx_us = 700_000;
    packet.detect_mult = 7;
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    assert_eq!(session.transmit_interval(), Duration::from_millis(700));
    assert_eq!(session.detection_time(), Duration::from_millis(1_750));
    // The multiplier need not carry Poll and must not wait for a Final.
    packet.detect_mult = 1;
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    let deadline = now + Duration::from_millis(250);
    assert_eq!(session.detection_deadline(), Some(deadline));
    assert!(!session.expire(deadline - Duration::from_nanos(1)));
    assert!(session.expire(deadline));
    assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
}

#[test]
fn peer_receive_limit_changes_are_immediate_and_do_not_change_detection_time() {
    let (mut session, auth) = classical(AuthType::None);
    let now = Instant::now();
    let mut packet = peer(State::Init);
    session.receive(&packet.encode(&auth, 0), now).unwrap();
    packet.state = State::Up;
    for limit in [5_000_000, 10_000, 0, 333_333] {
        packet.required_min_rx_us = limit;
        session.receive(&packet.encode(&auth, 0), now).unwrap();
        assert_eq!(
            session.transmit_interval(),
            Duration::from_micros(u64::from(limit.max(100_000)))
        );
        assert_eq!(session.detection_time(), Duration::from_millis(300));
        assert_eq!(session.periodic_enabled(), limit != 0);
    }
}

#[test]
fn keyed_sequence_windows_include_only_the_rfc_circular_range_for_every_type() {
    // RFC 5880 section 6.7.4 specifies the received Detect Mult,
    // inclusive upper bound, and a stricter lower bound for meticulous types.
    for kind in KEYED_TYPES {
        let auth = AuthConfig::new(kind, 0, b"test-key".to_vec()).unwrap();
        let meticulous = kind == AuthType::MeticulousSha1;
        for last in [0, 100, u32::MAX - 3, u32::MAX] {
            for multiplier in [1, 3, 255] {
                let mut packet = peer(State::Up);
                packet.detect_mult = multiplier;
                let end = 3 * u32::from(multiplier);
                for delta in [0, 1, end, end + 1, u32::MAX] {
                    let sequence = last.wrapping_add(delta);
                    let result = auth.verify(&packet.encode(&auth, sequence), Some(last));
                    assert_eq!(
                        result.is_ok(),
                        delta <= end && (!meticulous || delta != 0),
                        "{kind:?}, last={last}, multiplier={multiplier}, delta={delta}"
                    );
                }
            }
        }
    }
}

#[test]
fn rejected_keyed_packets_neither_seed_nor_advance_authentication_sequences() {
    // Verified errata 7082/7083: do not commit sequence state until digest checks pass.
    for kind in KEYED_TYPES {
        let (mut session, auth) = classical(kind);
        let now = Instant::now();
        let packet = peer(State::Init);
        let mut corrupt = packet.encode(&auth, 500);
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(session.receive(&corrupt, now).is_err());
        session.receive(&packet.encode(&auth, 100), now).unwrap();
        let mut corrupt = packet.encode(&auth, 109);
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(session.receive(&corrupt, now).is_err());
        session.receive(&packet.encode(&auth, 101), now).unwrap();
        assert_eq!(session.state(), State::Up);
    }
}

#[test]
fn every_authenticated_bit_tamper_is_rejected_without_changing_session_state() {
    for kind in KEYED_TYPES {
        let (mut session, auth) = classical(kind);
        let now = Instant::now();
        session
            .receive(&peer(State::Init).encode(&auth, 100), now)
            .unwrap();
        let expected = (
            session.state(),
            session.remote_state(),
            session.remote_diagnostic(),
            session.remote_discriminator(),
            session.transmit_interval(),
            session.detection_deadline(),
            session.polling(),
        );
        let mut packet = peer(State::Up);
        packet.poll = true;
        let wire = packet.encode(&auth, 101);
        for byte in 0..wire.len() {
            for bit in 0..8 {
                let mut tampered = wire.clone();
                tampered[byte] ^= 1 << bit;
                assert!(
                    session
                        .receive(&tampered, now + Duration::from_millis(10))
                        .is_err(),
                    "{kind:?}, byte={byte}, bit={bit}"
                );
                assert_eq!(
                    (
                        session.state(),
                        session.remote_state(),
                        session.remote_diagnostic(),
                        session.remote_discriminator(),
                        session.transmit_interval(),
                        session.detection_deadline(),
                        session.polling()
                    ),
                    expected
                );
            }
        }
        // A legitimate next sequence still succeeds after all those discarded packets.
        assert!(
            session
                .receive(&wire, now + Duration::from_millis(20))
                .unwrap()
                .reply_final
        );
    }
}

#[test]
fn short_or_inconsistent_authentication_sections_are_discarded_without_panics() {
    // RFC 5880 section 6.8.6 allows a minimum authenticated header of 26,
    // which is shorter than any supported complete authentication section.
    for kind in KEYED_TYPES {
        let (mut session, auth) = classical(kind);
        let now = Instant::now();
        let wire = peer(State::Init).encode(&auth, 100);
        for length in 0..wire.len() {
            assert!(session.receive(&wire[..length], now).is_err());
        }
        for declared in 0..wire.len() {
            let mut short = wire.clone();
            short[3] = u8::try_from(declared).unwrap();
            assert!(session.receive(&short, now).is_err());
        }
        for length in [0, 1, 2, 3, 255] {
            let mut invalid = wire.clone();
            invalid[25] = length;
            assert!(session.receive(&invalid, now).is_err());
        }
        assert_eq!(session.remote_discriminator(), 0);
        assert_eq!(session.detection_deadline(), None);
        session.receive(&wire, now).unwrap();
    }
}

#[test]
fn authentication_can_resynchronize_after_two_detection_times_even_after_expiry() {
    for kind in KEYED_TYPES {
        let (mut session, auth) = classical(kind);
        let now = Instant::now();
        let packet = peer(State::Init);
        session.receive(&packet.encode(&auth, 100), now).unwrap();
        let detection = session.detection_time();
        assert!(session.expire(now + detection));
        assert!(session
            .receive(
                &packet.encode(&auth, 0),
                now + detection * 2 - Duration::from_nanos(1)
            )
            .is_err());
        assert_eq!(session.remote_discriminator(), 0);
        session
            .receive(&packet.encode(&auth, 0), now + detection * 2)
            .unwrap();
        assert_eq!(session.state(), State::Up);
    }
}

#[test]
fn multihop_congestion_must_reduce_traffic_even_when_the_peer_is_already_slow() {
    // Section 7 requires a traffic reduction on congestion. An absolute backoff
    // cap must not leave the original rate unchanged for slow negotiated timers.
    for rx in [30_000_000, 60_000_000, 2_500_000_000] {
        let (mut session, auth) = classical(AuthType::None);
        let now = Instant::now();
        let mut packet = peer(State::Init);
        packet.required_min_rx_us = rx;
        session.receive(&packet.encode(&auth, 0), now).unwrap();
        let initial = session.transmit_interval();
        session.expire(now + session.detection_time());
        assert!(
            session.transmit_interval() > initial,
            "congestion did not slow classical TX at {rx} us"
        );
    }
}
