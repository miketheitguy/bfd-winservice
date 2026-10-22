use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn wait_for(cache: &ArcSwap<BrokerStatus>, predicate: impl Fn(&BrokerStatus) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate(&cache.load_full()) {
        assert!(
            Instant::now() < deadline,
            "cache did not reach expected state"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn malformed_data_clears_cache_and_recovers_on_the_same_worker() {
    let cache = Arc::new(ArcSwap::from_pointee(BrokerStatus::Unavailable));
    let (send, replies) = mpsc::channel();
    let (started, starts) = mpsc::channel();
    let valid = super::super::status::tests::sample_status();
    let monitor = Monitor::with_query(
        Logger::new().unwrap(),
        Arc::clone(&cache),
        move || {
            let _ = started.send(thread::current().id());
            replies
                .recv()
                .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::Interrupted).into()))
        },
        Duration::from_secs(1),
        Duration::from_millis(5),
    )
    .unwrap();
    let worker = starts.recv_timeout(Duration::from_secs(2)).unwrap();
    send.send(Ok(valid.clone())).unwrap();
    wait_for(&cache, |value| {
        matches!(value, BrokerStatus::Available { .. })
    });
    // Alternate native range faults and checked Rust conversion errors through
    // a failure streak, without replacing the worker or salvaging old telemetry.
    for failure in 0..6 {
        assert_eq!(starts.recv_timeout(Duration::from_secs(2)).unwrap(), worker);
        let error = if failure % 2 == 0 {
            SessionStatusQueryError::InvalidData("test record")
        } else {
            io::Error::from_raw_os_error(1783).into()
        };
        send.send(Err(error)).unwrap();
        wait_for(&cache, |value| matches!(value, BrokerStatus::Unavailable));
    }
    assert_eq!(starts.recv_timeout(Duration::from_secs(2)).unwrap(), worker);
    send.send(Ok(valid.clone())).unwrap();
    wait_for(&cache, |value| {
        matches!(value, BrokerStatus::Available { .. })
    });
    assert_eq!(starts.recv_timeout(Duration::from_secs(2)).unwrap(), worker);
    send.send(Err(SessionStatusQueryError::InvalidData("test record")))
        .unwrap();
    wait_for(&cache, |value| matches!(value, BrokerStatus::Unavailable));
    // The prior failure streak reached 160 ms and its next delay was 320 ms.
    // A valid reply must reset that history to this fixture's 5 ms interval.
    assert_eq!(
        starts.recv_timeout(Duration::from_millis(200)).unwrap(),
        worker
    );
    send.send(Ok(valid)).unwrap();
    wait_for(&cache, |value| {
        matches!(value, BrokerStatus::Available { .. })
    });
    drop(monitor);
    assert!(matches!(*cache.load_full(), BrokerStatus::Unavailable));
}

#[test]
fn transport_failure_clears_previous_data_and_valid_telemetry_can_recover() {
    let cache = Arc::new(ArcSwap::from_pointee(BrokerStatus::Unavailable));
    let (send, replies) = mpsc::channel();
    let monitor = Monitor::with_query(
        Logger::new().unwrap(),
        Arc::clone(&cache),
        move || {
            replies
                .recv()
                .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::Interrupted).into()))
        },
        Duration::from_secs(2),
        Duration::from_millis(5),
    )
    .unwrap();
    let valid = super::super::status::tests::sample_status();
    send.send(Ok(valid.clone())).unwrap();
    wait_for(&cache, BrokerStatus::is_fresh);
    send.send(Err(io::Error::from_raw_os_error(1722).into()))
        .unwrap();
    wait_for(&cache, |value| matches!(value, BrokerStatus::Unavailable));
    send.send(Ok(valid)).unwrap();
    wait_for(&cache, |value| {
        matches!(value, BrokerStatus::Available { .. })
    });
    drop(monitor);
}

#[test]
fn old_or_cached_snapshots_are_stale_without_becoming_protocol_down() {
    let mut session = super::super::status::tests::sample_status();
    session.snapshot_age = Duration::from_secs(3);
    let value = BrokerStatus::Available {
        session: Arc::new(session),
        received_at: Instant::now(),
        fetch_time: Duration::ZERO,
    };
    assert!(!value.is_fresh());
    let BrokerStatus::Available { session, .. } = value else {
        unreachable!()
    };
    assert_eq!(session.local_state, crate::packet::State::Down);
    assert!(!BrokerStatus::Quarantined.is_fresh());
}

#[test]
fn stalled_worker_is_bounded_and_shutdown_never_waits_for_native_completion() {
    let cache = Arc::new(ArcSwap::from_pointee(BrokerStatus::Unavailable));
    let (release, blocked) = mpsc::channel();
    let monitor = Monitor::with_query(
        Logger::new().unwrap(),
        Arc::clone(&cache),
        move || {
            let _ = blocked.recv();
            Err(io::Error::from(io::ErrorKind::TimedOut).into())
        },
        Duration::from_millis(20),
        INTERVAL,
    )
    .unwrap();
    wait_for(&cache, |value| matches!(value, BrokerStatus::Quarantined));
    let started = Instant::now();
    drop(monitor);
    assert!(started.elapsed() < Duration::from_millis(250));
    release.send(()).unwrap();
}

#[test]
fn native_bad_stub_data_is_reported_as_rejected_data() {
    let malformed = SessionStatusQueryError::Rpc(io::Error::from_raw_os_error(1783));
    assert!(malformed.invalid_data());
    assert!(!SessionStatusQueryError::Rpc(io::Error::from_raw_os_error(1722)).invalid_data());
    assert!(!SessionStatusQueryError::Quarantined.invalid_data());
}

#[test]
fn retry_backoff_is_capped_and_a_valid_reply_resets_failure_history() {
    let mut retry = RetryBackoff::new(INTERVAL);
    for seconds in [1, 2, 4, 8, 16, 30, 30, 30] {
        assert_eq!(retry.next_delay(), Duration::from_secs(seconds));
    }
    retry.reset();
    assert_eq!(retry.next_delay(), INTERVAL);
}

#[test]
fn shutdown_interrupts_the_longest_retry_wait() {
    let cache = Arc::new(ArcSwap::from_pointee(BrokerStatus::Available {
        session: Arc::new(super::super::status::tests::sample_status()),
        received_at: Instant::now(),
        fetch_time: Duration::ZERO,
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let query_calls = Arc::clone(&calls);
    let monitor = Monitor::with_query(
        Logger::new().unwrap(),
        Arc::clone(&cache),
        move || {
            query_calls.fetch_add(1, Ordering::Relaxed);
            Err(SessionStatusQueryError::InvalidData("test record"))
        },
        QUERY_BUDGET,
        MAX_RETRY_INTERVAL,
    )
    .unwrap();
    wait_for(&cache, |value| matches!(value, BrokerStatus::Unavailable));
    let started = Instant::now();
    drop(monitor);
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}
