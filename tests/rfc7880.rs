//! RFC 7880 role, reflection, Poll, authentication and failure boundaries.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use bfd_winservice::{
    config::{Options, SessionType, Timing},
    error::{AuthError, PacketError},
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
    seamless::Reflector,
    session::{ReceiveError, Session},
};
use std::time::{Duration, Instant};

const KEYED_TYPES: [AuthType; 3] = [
    AuthType::MeticulousMd5,
    AuthType::KeyedSha1,
    AuthType::MeticulousSha1,
];

fn pair(kind: AuthType) -> (Session, Reflector, AuthConfig) {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.session_type = SessionType::SbfdInitiator;
    options.discriminator = Some(7);
    options.remote_discriminator = Some(99);
    options.min_tx_us = 100_000;
    options.min_rx_us = 400_000;
    options.auth = kind;
    if kind != AuthType::None {
        options.auth_key = Some("test-key".into());
    }
    let auth = options.validate().unwrap();
    let mut reflector = Options::reflector(options.peer, 99);
    reflector.min_rx_us = 200_000;
    reflector.auth = kind;
    reflector.auth_key = options.auth_key.clone();
    (
        Session::new(options, auth.clone()).unwrap(),
        Reflector::new(reflector, auth.clone()).unwrap(),
        auth,
    )
}

// Independent request fixture; reflector assertions must not depend on the
// initiator having serialized the same fields correctly.
fn request(state: State, multiplier: u8, tx: u32) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: true,
        detect_mult: multiplier,
        my_discriminator: 7,
        your_discriminator: 99,
        desired_min_tx_us: tx,
        required_min_rx_us: 0,
        required_min_echo_rx_us: 0,
    }
}

#[test]
fn reflector_copies_required_fields_for_every_initiator_state_and_multiplier() {
    // Sections 5 and 7.2.2: local policy state and RX capacity are independent
    // of the request, while discriminators, multiplier and desired TX are copied.
    let (_, mut reflector, auth) = pair(AuthType::None);
    for administrative in [false, true] {
        reflector.set_admin_down(administrative);
        for state in [State::Down, State::Up, State::AdminDown] {
            for multiplier in 1..=255 {
                for tx in [3_300, 1_000_000, u32::MAX] {
                    let input = request(state, multiplier, tx).encode(&auth, 0);
                    let wire = reflector.respond(&input).unwrap();
                    let reply = ControlPacket::decode(&wire).unwrap();
                    assert_eq!(
                        reply.state,
                        if administrative {
                            State::AdminDown
                        } else {
                            State::Up
                        }
                    );
                    assert_eq!((reply.my_discriminator, reply.your_discriminator), (99, 7));
                    assert_eq!(
                        (reply.detect_mult, reply.desired_min_tx_us),
                        (multiplier, tx)
                    );
                    assert_eq!(reply.required_min_rx_us, 200_000);
                    assert_eq!(reply.required_min_echo_rx_us, 0);
                    assert!(!reply.demand && !reply.poll && !reply.final_bit);
                    assert_eq!(wire[1] & 1, 0);
                }
            }
        }
    }
}

#[test]
fn reflector_authentication_is_stateless_across_clients_replays_and_sequence_wrap() {
    // Section 11 prohibits the reflector from rejecting based on sequence order.
    for kind in KEYED_TYPES {
        let (_, reflector, auth) = pair(kind);
        for discriminator in [7, 8, u32::MAX] {
            for sequence in [100, 100, 0, u32::MAX, 1, 500_000] {
                let mut packet = request(State::Up, 3, 100_000);
                packet.my_discriminator = discriminator;
                let response = reflector.respond(&packet.encode(&auth, sequence)).unwrap();
                assert_eq!(auth.verify(&response, None), Ok(Some(sequence)));
                assert_eq!(
                    ControlPacket::decode(&response).unwrap().your_discriminator,
                    discriminator
                );
            }
        }
    }
}

#[test]
fn both_roles_reject_loop_markers_without_learning_or_responding() {
    let (mut session, reflector, auth) = pair(AuthType::None);
    let now = Instant::now();
    let mut packet = request(State::Down, 3, 1_000_000);
    packet.demand = false;
    assert_eq!(
        reflector.respond(&packet.encode(&auth, 0)).err(),
        Some(ReceiveError::Packet(PacketError::MissingDemand))
    );
    let probe = session.packet_at(false, now);
    let mut reply = ControlPacket::decode(&reflector.respond(&probe).unwrap()).unwrap();
    reply.demand = true;
    assert!(session.receive(&reply.encode(&auth, 0), now).is_err());
    assert_eq!(session.state(), State::Down);
    assert!(!session.communicating());
    assert_eq!(session.remote_state(), State::Down);
    assert_eq!(session.transmit_interval(), Duration::from_secs(1));
}

#[test]
fn reflector_final_acknowledges_only_poll_and_never_echoes_an_incoming_final() {
    // Section 7.5: respond to P with F; no P+F packet or reflection loop.
    let (_, reflector, auth) = pair(AuthType::None);
    for (poll, final_bit, expected_final) in [
        (false, false, false),
        (true, false, true),
        (false, true, false),
    ] {
        let mut packet = request(State::Up, 3, 100_000);
        packet.poll = poll;
        packet.final_bit = final_bit;
        let reply =
            ControlPacket::decode(&reflector.respond(&packet.encode(&auth, 0)).unwrap()).unwrap();
        assert_eq!(reply.final_bit, expected_final);
        assert!(!reply.poll);
    }
}

#[test]
fn simultaneous_polls_complete_independently_and_the_next_probe_carries_final() {
    let (mut session, reflector, auth) = pair(AuthType::None);
    let now = Instant::now();
    let probe = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&probe).unwrap(), now)
        .unwrap();
    assert!(session.polling());
    // A reflector Poll cannot acknowledge the initiator's pending Poll.
    let mut reply = request(State::Up, 3, 100_000);
    reply.demand = false;
    reply.my_discriminator = 99;
    reply.your_discriminator = 7;
    reply.required_min_rx_us = 200_000;
    reply.poll = true;
    assert!(
        !session
            .receive(&reply.encode(&auth, 0), now)
            .unwrap()
            .reply_final
    );
    let final_probe = session.packet_at(false, now);
    let final_packet = ControlPacket::decode(&final_probe).unwrap();
    assert!(final_packet.final_bit && !final_packet.poll && final_packet.demand);
    assert!(session.polling());
    session
        .receive(&reflector.respond(&final_probe).unwrap(), now)
        .unwrap();
    assert!(session.polling());
    let poll_probe = session.packet_at(false, now);
    assert!(ControlPacket::decode(&poll_probe).unwrap().poll);
    session
        .receive(&reflector.respond(&poll_probe).unwrap(), now)
        .unwrap();
    assert!(!session.polling());
}

#[test]
fn maintenance_is_reachable_and_actual_probe_spacing_respects_all_rate_floors() {
    let (mut session, mut reflector, _) = pair(AuthType::None);
    let now = Instant::now();
    let probe = session.packet_at(false, now);
    session
        .receive(&reflector.respond(&probe).unwrap(), now)
        .unwrap();
    reflector.set_admin_down(true);
    for rx in [1, 500_000, 2_000_000, 10_000_000] {
        reflector.set_timing(Timing::new(100_000, rx, 3).unwrap());
        let probe = session.packet_at(false, now);
        session
            .receive(&reflector.respond(&probe).unwrap(), now)
            .unwrap();
        assert!(session.communicating());
        assert_eq!(session.state(), State::Down);
        assert_eq!(session.diagnostic(), Diagnostic::NeighborDown);
        let base = u128::from(rx.max(1_000_000)) * 1_000;
        for _ in 0..128 {
            let interval = session.jittered_interval().as_nanos();
            assert!(interval >= 1_000_000_000 && interval >= base * 75 / 100 && interval <= base);
        }
    }
}

#[test]
fn authenticated_replies_must_match_unconsumed_unexpired_probes() {
    for kind in KEYED_TYPES {
        let (mut session, reflector, _) = pair(kind);
        let now = Instant::now();
        let first = session.packet_at(false, now);
        let second = session.packet_at(false, now);
        let first_reply = reflector.respond(&first).unwrap();
        let second_reply = reflector.respond(&second).unwrap();
        // Reordering is legal: reflector replies don't advance a classic window.
        session.receive(&second_reply, now).unwrap();
        session.receive(&first_reply, now).unwrap();
        let deadline = session.detection_deadline();
        assert_eq!(
            session.receive(&second_reply, now).err(),
            Some(ReceiveError::Authentication(
                AuthError::SequenceNotOutstanding
            ))
        );
        assert_eq!(session.detection_deadline(), deadline);
        let probe = session.packet_at(false, now);
        let reply = reflector.respond(&probe).unwrap();
        let expiry = now + session.detection_time();
        assert_eq!(
            session.receive(&reply, expiry).err(),
            Some(ReceiveError::Authentication(
                AuthError::SequenceNotOutstanding
            ))
        );
        assert_eq!(session.detection_deadline(), deadline);
        session
            .receive(&reply, expiry - Duration::from_nanos(1))
            .unwrap();
    }
}

#[test]
fn first_response_timeout_includes_round_trip_latency_and_large_timers_do_not_overflow() {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.session_type = SessionType::SbfdInitiator;
    options.remote_discriminator = Some(99);
    options.min_tx_us = u32::MAX;
    options.min_rx_us = u32::MAX;
    options.detect_mult = 255;
    let auth = options.validate().unwrap();
    let mut session = Session::new(options, auth).unwrap();
    let now = Instant::now();
    assert_eq!(session.detection_deadline(), None);
    session.packet_at(false, now);
    let budget = Duration::from_micros(u64::from(u32::MAX) * 256);
    assert_eq!(session.detection_time(), budget);
    assert_eq!(session.detection_deadline(), Some(now + budget));
    assert!(!session.expire(now + budget - Duration::from_nanos(1)));
    session.expire(now + budget);
    assert!(!session.communicating());
    assert_eq!(session.remote_discriminator(), 99);
}

#[test]
fn congestion_must_reduce_traffic_even_when_reflector_capacity_exceeds_the_backoff_cap() {
    // Section 8.2 requires congestion control across multihop paths even when
    // the reflector has already advertised a very slow receive capacity.
    for rx in [30_000_000, 60_000_000, 2_500_000_000] {
        let (mut session, mut reflector, _) = pair(AuthType::None);
        reflector.set_timing(Timing::new(100_000, rx, 3).unwrap());
        let now = Instant::now();
        let probe = session.packet_at(false, now);
        session
            .receive(&reflector.respond(&probe).unwrap(), now)
            .unwrap();
        let initial = session.transmit_interval();
        session.expire(session.detection_deadline().unwrap());
        assert!(
            session.transmit_interval() > initial,
            "congestion did not slow S-BFD TX at {rx} us"
        );
    }
}
