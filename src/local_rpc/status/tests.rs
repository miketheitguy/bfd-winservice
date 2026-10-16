use super::*;
use crate::{
    config::Options,
    runtime::status::{StatusPublisher, StatusTelemetry},
    session::Session,
};

pub(crate) fn fixture() -> (StatusPublisher, crate::runtime::StatusObserver) {
    let mut options = Options::new("127.0.0.8".parse().unwrap(), "127.0.0.9".parse().unwrap());
    options.multihop = true;
    let options = options.into_validated().unwrap();
    let session = Session::from_config(options.clone());
    let now = Instant::now();
    let telemetry = StatusTelemetry::new(now, SystemTime::now(), &options);
    let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
    let publisher = StatusPublisher::new(snapshot, telemetry.revision(), now);
    let observer = publisher.observer();
    (publisher, observer)
}

fn wire() -> WireStatus {
    let (_publisher, observer) = fixture();
    WireStatus::capture(&observer.snapshot().unwrap(), Instant::now()).unwrap()
}

pub(crate) fn sample_status() -> SessionStatus {
    wire().try_into().unwrap()
}

#[test]
fn native_and_rust_layouts_match() {
    assert_eq!(size_of::<WireStatus>(), 336);
    let layout = [
        size_of::<WireStatus>(),
        std::mem::align_of::<WireStatus>(),
        std::mem::offset_of!(WireStatus, instance),
        std::mem::offset_of!(WireStatus, sequence),
        std::mem::offset_of!(WireStatus, role),
        std::mem::offset_of!(WireStatus, local),
        std::mem::offset_of!(WireStatus, peer),
        std::mem::offset_of!(WireStatus, source),
    ];
    for (field, expected) in layout.into_iter().enumerate() {
        let actual = super::super::native_status_layout(u32::try_from(field).unwrap());
        assert_eq!(usize::try_from(actual).unwrap(), expected);
    }
}

#[test]
fn reflector_has_no_fabricated_peer_or_detection_state() {
    let options = Options::reflector("127.0.0.8".parse().unwrap(), 9)
        .into_validated()
        .unwrap();
    let session = Session::from_config(options.clone());
    let now = Instant::now();
    let telemetry = StatusTelemetry::new(now, SystemTime::now(), &options);
    let publisher = StatusPublisher::new(
        telemetry.snapshot(&session, &options, options.timing(), 7784),
        0,
        now,
    );
    let snapshot = publisher.observer().snapshot().unwrap();
    let status =
        SessionStatus::try_from(WireStatus::capture(&snapshot, Instant::now()).unwrap()).unwrap();
    assert_eq!(status.session_type, SessionType::SbfdReflector);
    assert_eq!(status.peer_state, None);
    assert_eq!(status.communicating, None);
    assert_eq!(status.detection_time, None);
}

#[test]
fn checked_types_reject_out_of_range_and_noncanonical_fields() {
    let good = wire();
    assert!(SessionStatus::try_from(good).is_ok());
    let mutations: &[fn(&mut WireStatus)] = &[
        |w| w.version = 2,
        |w| w.size += 1,
        |w| w.fields |= 1 << 63,
        |w| w.instance = [0; 16],
        |w| w.sequence = 0,
        |w| w.role = 3,
        |w| w.mode = 2,
        |w| w.local_state = 4,
        |w| w.local_diag = 2,
        |w| w.local_disc = 0,
        |w| w.local_mult = 0,
        |w| w.local_mult = 256,
        |w| w.communicating = 2,
        |w| w.control_port = 65536,
        |w| w.local.port = 65536,
        |w| w.local.family = 5,
        |w| w.local.bytes[15] = 1,
        |w| w.local.scope = 1,
        |w| w.peer_diag = 1,
        |w| w.tx_us = MAX_TX_US + 1,
        |w| w.detection_us = MAX_DETECTION_US + 1,
        |w| w.captured_utc = MAX_FILETIME + 1,
        |w| w.uptime_us = MAX_AGE_US + 1,
        |w| w.age_us = w.uptime_us + 1,
    ];
    for mutation in mutations {
        let mut bad = good;
        mutation(&mut bad);
        assert!(SessionStatus::try_from(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn historical_peer_up_and_saturated_counters_are_valid_after_local_expiry() {
    let mut w = wire();
    w.fields |= PEER_REPORT | RECEIVE | SOURCE | DOWN;
    w.local_state = 1;
    w.local_diag = 1;
    w.peer_state = 3;
    w.peer_diag = 31;
    w.peer_mult = 255;
    w.communicating = 0;
    w.received_utc = w.captured_utc;
    w.received_age_us = w.age_us;
    w.source = w.peer;
    w.down_utc = w.captured_utc;
    w.down_reason = 1;
    w.received = u64::MAX;
    w.auth_failures = u64::MAX;
    let status = SessionStatus::try_from(w).unwrap();
    assert_eq!(status.local_state, State::Down);
    assert_eq!(status.peer_state, Some(State::Up));
    assert_eq!(status.communicating, Some(false));
    assert_eq!(status.peer_diagnostic, Some(31));
}

#[test]
fn ipv6_scope_round_trips_and_invalid_ports_are_rejected() {
    let address = SocketAddr::V6(SocketAddrV6::new(
        "fe80::1234".parse().unwrap(),
        52000,
        0,
        17,
    ));
    assert_eq!(
        SocketAddr::try_from(WireAddress::from(address)).unwrap(),
        address
    );
    assert!(SocketAddr::try_from(WireAddress {
        port: 0,
        ..address.into()
    })
    .is_err());
}

#[test]
fn utc_conversion_preserves_times_without_clock_order_assumptions() {
    for time in [
        UNIX_EPOCH,
        SystemTime::now(),
        UNIX_EPOCH - Duration::from_secs(1),
    ] {
        let decoded = filetime(encode_time(time).unwrap()).unwrap();
        assert!(time.duration_since(decoded).unwrap() < Duration::from_nanos(100));
    }
}
