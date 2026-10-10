//! RFC 7419 section 3 common intervals and Appendix B interoperability.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use bfd_winservice::{
    config::{Mode, Options},
    packet::{ControlPacket, State},
    session::Session,
};
use std::time::{Duration, Instant};

// RFC 7419 section 3; 10 seconds is the additional graceful-restart recommendation.
const INTERVALS_US: [u32; 7] = [
    3_300, 10_000, 20_000, 50_000, 100_000, 1_000_000, 10_000_000,
];

fn establish(tx: u32, rx: u32, local_mult: u8, peer: &ControlPacket) -> Session {
    let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
    options.mode = Mode::Multihop;
    options.discriminator = Some(7);
    options.min_tx_us = tx;
    options.min_rx_us = rx;
    options.detect_mult = local_mult;
    let auth = options.validate().unwrap();
    let mut session = Session::new(options, auth.clone()).unwrap();
    let now = Instant::now();
    let mut initial = peer.clone();
    initial.state = State::Init;
    initial.desired_min_tx_us = initial.desired_min_tx_us.max(1_000_000);
    session.receive(&initial.encode(&auth, 0), now).unwrap();
    session.receive(&peer.encode(&auth, 0), now).unwrap();
    assert_eq!(session.state(), State::Up);
    session
}

fn peer(tx: u32, rx: u32, multiplier: u8) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state: State::Up,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: multiplier,
        my_discriminator: 99,
        your_discriminator: 7,
        desired_min_tx_us: tx,
        required_min_rx_us: rx,
        required_min_echo_rx_us: 0,
    }
}

#[test]
fn every_common_interval_negotiates_in_both_directions_without_rounding() {
    for local in INTERVALS_US {
        for remote in INTERVALS_US {
            let mut session = establish(local, local, 3, &peer(remote, remote, 9));
            let expected = Duration::from_micros(u64::from(local.max(remote)));
            assert_eq!(session.transmit_interval(), expected);
            assert_eq!(session.detection_time(), expected * 9);
            let wire = ControlPacket::decode(&session.packet(false)).unwrap();
            assert_eq!(wire.desired_min_tx_us, local);
            assert_eq!(wire.required_min_rx_us, local);
            assert_eq!(wire.detect_mult, 3);
        }
    }
}

#[test]
fn all_255_multipliers_and_long_graceful_restart_intervals_are_supported() {
    for multiplier in 1..=255 {
        let mut session = establish(
            10_000_000,
            10_000_000,
            multiplier,
            &peer(10_000_000, 10_000_000, multiplier),
        );
        assert_eq!(
            session.detection_time(),
            Duration::from_secs(10 * u64::from(multiplier))
        );
        assert_eq!(
            ControlPacket::decode(&session.packet(false))
                .unwrap()
                .detect_mult,
            multiplier
        );
    }
    // The wire interval and multiplier widths allow a much longer time than u32 microseconds.
    let session = establish(u32::MAX, u32::MAX, 255, &peer(u32::MAX, u32::MAX, 255));
    assert_eq!(
        session.detection_time(),
        Duration::from_micros(u64::from(u32::MAX) * 255)
    );
}

#[test]
fn continuous_timers_accept_peer_values_outside_the_common_set() {
    // Unlike Appendix B's hardware examples, this implementation can support both
    // 200 and 300 ms, so it must not escalate them to a common 1-second interval.
    for (local, remote) in [
        (200_000, 300_000),
        (300_000, 200_000),
        (3_300, 3_333),
        (10_000, 17_777),
    ] {
        let session = establish(local, 50_000, 3, &peer(remote, remote, 5));
        assert_eq!(
            session.transmit_interval(),
            Duration::from_micros(u64::from(local.max(remote)))
        );
        assert_eq!(
            session.detection_time(),
            Duration::from_micros(u64::from(50_000u32.max(remote)) * 5)
        );
    }
}

#[test]
fn common_interval_jitter_obeys_the_full_range_and_multiplier_one_margin() {
    for interval in INTERVALS_US {
        for multiplier in [1, 2, 255] {
            let session = establish(interval, interval, multiplier, &peer(interval, interval, 3));
            let base = u128::from(interval) * 1_000;
            let upper = if multiplier == 1 { 90 } else { 100 };
            for _ in 0..128 {
                assert!((base * 75 / 100..=base * upper / 100)
                    .contains(&session.jittered_interval().as_nanos()));
            }
        }
    }
}
