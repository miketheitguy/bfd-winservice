//! Bounded BGP control through the authenticated local broker, off the BFD thread.

pub(crate) mod ipc;

use crate::{
    config::Options,
    packet::State,
    runtime::{Logger, StopSignal},
};
use std::{
    cell::Cell,
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const CONTROL_FAILURE_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Worker-local incident state; retries never allocate or acquire another lock.
#[derive(Default)]
struct ControlFailureLog {
    last_report: Option<Instant>,
}

impl ControlFailureLog {
    fn failed(&mut self, now: Instant) -> bool {
        if self.last_report.is_none_or(|last| {
            now.saturating_duration_since(last) >= CONTROL_FAILURE_REPORT_INTERVAL
        }) {
            self.last_report = Some(now);
            return true;
        }
        false
    }

    fn recovered(&mut self, rpc_completed: bool) -> bool {
        // A locally superseded Start may return Ok without contacting the broker.
        rpc_completed && self.last_report.take().is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Start,
    Stop,
}

impl Method {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Get => "Get",
            Self::Start => "Start",
            Self::Stop => "Stop",
        }
    }

    /// Maps ordinary state changes to provider actions. The controller handles
    /// local AdminDown separately by withdrawing its own latest Stop.
    fn transition(previous: State, current: State) -> Option<Self> {
        if previous == current {
            return None;
        }
        match current {
            State::Up => Some(Self::Start),
            State::Down => Some(Self::Stop),
            State::Init | State::AdminDown => None,
        }
    }
}

#[derive(Default)]
struct Pending {
    methods: VecDeque<Method>,
    closed: bool,
    established: bool,
    desired: Option<Method>,
}

impl Pending {
    fn push(&mut self, method: Method) {
        self.desired = Some(method);
        if method == Method::Stop {
            // Down/AdminDown discard queued recovery. An already issued provider
            // call completes before the worker processes this Stop.
            self.methods.clear();
            self.methods.push_back(method);
            return;
        }
        if self.methods.back() == Some(&method) {
            return;
        }
        // Keep the latest failure/recovery pair during sustained flapping. Never
        // build an unlimited queue behind a slow provider or block BFD timers.
        if self.methods.len() == 2 {
            self.methods.pop_front();
        }
        self.methods.push_back(method);
    }

    /// RFC 5882 section 4.1: while BFD is administratively disabled at either end,
    /// a control protocol adjacency MUST be allowed. Withdraws this controller's
    /// latest requested Stop, even if queued or of unknown outcome. The worker
    /// queries the peer and starts it if stopped; it does not track who stopped
    /// it. Returns whether a Start was queued.
    fn release(&mut self) -> bool {
        if self.desired != Some(Method::Stop) {
            return false;
        }
        // A queued Stop that hasn't started yet is superseded entirely.
        self.methods.clear();
        self.push(Method::Start);
        true
    }
}

type Mailbox = Arc<(Mutex<Pending>, Condvar)>;

pub(crate) struct Controller {
    mailbox: Mailbox,
    worker: Option<JoinHandle<io::Result<()>>>,
    log: Option<Logger>,
    /// Cancels an in-flight call when closing queues a newer final action.
    cancel: StopSignal,
}

impl Controller {
    pub(crate) fn open(options: &Options, logger: &Logger) -> io::Result<Option<Self>> {
        let Some(peer) = options.bgp_peer_name.clone() else {
            return Ok(None);
        };
        let mut log = logger.clone();
        let mailbox = Mailbox::default();
        let worker_mailbox = Arc::clone(&mailbox);
        let cancel = StopSignal::new()?;
        let worker_cancel = cancel.clone();
        let worker = thread::Builder::new()
            .name("bgp-ipc".into())
            .spawn(move || {
                let client = ipc::Client::with_cancel(worker_cancel.clone());
                let mut failure_log = ControlFailureLog::default();
                work(&worker_mailbox, |method| {
                    let rpc_completed = Cell::new(false);
                    let result = reconcile(
                        method,
                        || client.started().inspect(|_| rpc_completed.set(true)),
                        |method| client.invoke(method).inspect(|_| rpc_completed.set(true)),
                        || start_is_current(&worker_mailbox),
                    );
                    // Shutdown cancels a call superseded by the queued final action.
                    if result.as_ref().is_err_and(|error| {
                        superseded_cancellation(&worker_mailbox, &worker_cancel, error)
                    }) {
                        log.log(format!(
                            "BGP peer={peer:?} method={} superseded at service shutdown",
                            method.name()
                        ));
                        return Ok(());
                    }
                    if result.is_ok() && failure_log.recovered(rpc_completed.get()) {
                        log.bgp_control_message(
                            &peer,
                            method.name(),
                            "RPC requests are succeeding again; inspect the peer and management result for the action outcome",
                            true,
                        );
                    }
                    match &result {
                        Ok(true) => log.log(format!(
                            "BGP peer={peer:?} method={} succeeded",
                            method.name()
                        )),
                        Ok(false) => log.log(format!("BGP peer={peer:?} Start unnecessary or superseded by BFD; leaving BGP unchanged")),
                        Err(error) => {
                            if failure_log.failed(Instant::now()) {
                                log.bgp_control_message(
                                    &peer,
                                    method.name(),
                                    format_args!("failed: {error}"),
                                    false,
                                );
                            } else {
                                log.log(format!(
                                    "BGP peer={peer:?} method={} failed: {error}",
                                    method.name()
                                ));
                            }
                        }
                    }
                    result.map(|_| ())
                })
            })?;
        Ok(Some(Self {
            mailbox,
            worker: Some(worker),
            log: Some(logger.clone()),
            cancel,
        }))
    }

    pub(crate) fn state_changed(&self, previous: State, current: State) {
        // Local AdminDown, set when the BFD service stops, disables BFD here.
        if current == State::AdminDown && previous != current {
            self.administratively_disabled();
            return;
        }
        if let Some(method) = Method::transition(previous, current) {
            let (mutex, ready) = &*self.mailbox;
            // No provider call runs under this lock. Recover the mailbox data if
            // poisoned; this does not restart a worker that has panicked.
            let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            if pending.closed {
                return;
            }
            if current == State::Up {
                pending.established = true;
            }
            if current == State::Down && !pending.established {
                return;
            }
            pending.push(method);
            ready.notify_one();
        }
    }

    /// The peer signalled AdminDown, so BFD is administratively disabled there.
    pub(crate) fn peer_admin_down(&self) {
        self.administratively_disabled();
    }

    fn administratively_disabled(&self) {
        let (mutex, ready) = &*self.mailbox;
        let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
        if !pending.closed && pending.release() {
            ready.notify_one();
        }
    }

    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.finish()
    }

    fn finish(&mut self) -> io::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (mutex, ready) = &*self.mailbox;
        let cancellation = {
            let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            pending.closed = true;
            // The queued action is the final one, such as a Start that releases
            // BFD's Stop because the service is stopping (RFC 5882 section 4.1).
            // Publish cancellation before the worker can dequeue the final action.
            // Its client then recognizes every call of that action as final.
            let result = if !pending.methods.is_empty() {
                self.cancel.signal()
            } else {
                Ok(())
            };
            ready.notify_one();
            result
        };
        worker
            .join()
            .map_err(|_| io::Error::other("BGP MI worker panicked"))?
            .and(cancellation)
    }
}

// Query failure is unknown status, never evidence that the peer is stopped.
// Return whether a mutation occurred so logs distinguish Start from a no-op.
fn reconcile(
    method: Method,
    mut query: impl FnMut() -> io::Result<bool>,
    mut invoke: impl FnMut(Method) -> io::Result<()>,
    mut start_is_current: impl FnMut() -> bool,
) -> io::Result<bool> {
    match method {
        Method::Start => {
            if !start_is_current() {
                return Ok(false);
            }
            // Read the peer at Up rather than assume its state or use an old snapshot.
            let started = query()?;
            // BFD may have gone Down while this potentially slow query ran.
            if started || !start_is_current() {
                return Ok(false);
            }
        }
        Method::Stop => {}
        Method::Get => return Err(io::Error::other("Get is not a BGP state-change action")),
    }
    invoke(method)?;
    Ok(true)
}

// Checks only the mailbox snapshot, not atomicity with a subsequent MI call.
// A Start stays current during shutdown: stopping BFD releases its Stop.
fn start_is_current(mailbox: &Mailbox) -> bool {
    let pending = mailbox.0.lock().unwrap_or_else(|error| error.into_inner());
    pending.methods.is_empty()
}

fn superseded_cancellation(mailbox: &Mailbox, cancel: &StopSignal, error: &io::Error) -> bool {
    cancel.is_requested()
        && error.kind() == io::ErrorKind::Interrupted
        && !mailbox
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .methods
            .is_empty()
}

fn work(mailbox: &Mailbox, mut invoke: impl FnMut(Method) -> io::Result<()>) -> io::Result<()> {
    let (mutex, ready) = &**mailbox;
    let mut last_failure = None;
    loop {
        let method = {
            let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            while pending.methods.is_empty() && !pending.closed {
                pending = ready
                    .wait(pending)
                    .unwrap_or_else(|error| error.into_inner());
            }
            let Some(method) = pending.methods.pop_front() else {
                return last_failure.map_or(Ok(()), Err);
            };
            method
        };
        if let Err(error) = invoke(method) {
            last_failure = Some(error);
            let pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            // A new queued action supersedes a failed call. Otherwise retry after one
            // second, waking immediately for recovery or service shutdown.
            let (mut pending, _) = ready
                .wait_timeout_while(pending, Duration::from_secs(1), |pending| {
                    pending.methods.is_empty() && !pending.closed
                })
                .unwrap_or_else(|error| error.into_inner());
            if pending.methods.is_empty() && !pending.closed {
                pending.push(method);
            }
        } else {
            last_failure = None;
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            if let Some(log) = &mut self.log {
                log.log(format_args!("BGP MI shutdown failed: {error}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn client_failure_reporting_bounds_retries_and_requires_rpc_success_for_recovery() {
        let start = Instant::now();
        let mut report = ControlFailureLog::default();
        assert!(!report.recovered(true));
        assert!(report.failed(start));
        assert!(!report.failed(start + Duration::from_secs(59)));
        assert!(report.failed(start + CONTROL_FAILURE_REPORT_INTERVAL));
        // A queued Start superseded before its first RPC is not a recovery.
        assert!(!report.recovered(false));
        assert!(!report.failed(start + Duration::from_secs(61)));
        assert!(report.recovered(true));
        assert!(!report.recovered(true));
        // A new incident is visible immediately, even just after recovery.
        assert!(report.failed(start + Duration::from_secs(61)));
    }
    #[test]
    fn bfd_does_not_control_bgp_until_the_first_up() {
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox: Mailbox::default(),
            worker: None,
        };
        controller.state_changed(State::Down, State::Init);
        controller.state_changed(State::Init, State::Down);
        assert!(controller.mailbox.0.lock().unwrap().methods.is_empty());
        controller.state_changed(State::Down, State::Up);
        assert_eq!(
            controller.mailbox.0.lock().unwrap().methods,
            [Method::Start]
        );
        controller.state_changed(State::Up, State::Down);
        assert_eq!(controller.mailbox.0.lock().unwrap().methods, [Method::Stop]);
    }

    #[test]
    fn service_shutdown_queues_no_bgp_stop() {
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox: Mailbox::default(),
            worker: None,
        };
        controller.state_changed(State::Down, State::Up);
        controller.state_changed(State::Up, State::AdminDown);
        let pending = controller.mailbox.0.lock().unwrap();
        // Nothing stops the peer; the pending Start remains the final action.
        assert_eq!(pending.methods, [Method::Start]);
        assert_eq!(pending.desired, Some(Method::Start));
    }

    #[test]
    fn bfd_recovery_starts_only_stopped_bgp_peers() {
        let started = std::cell::Cell::new(false);
        let mut calls = Vec::new();
        for (method, changed) in [
            (Method::Start, true),
            (Method::Start, false),
            (Method::Stop, true),
            (Method::Start, true),
        ] {
            assert_eq!(
                reconcile(
                    method,
                    || Ok(started.get()),
                    |method| {
                        calls.push(method);
                        started.set(method == Method::Start);
                        Ok(())
                    },
                    || true,
                )
                .unwrap(),
                changed,
            );
        }
        assert_eq!(calls, [Method::Start, Method::Stop, Method::Start]);
    }

    #[test]
    fn unknown_status_and_failed_mutations_are_not_assumed_started_or_stopped() {
        assert!(reconcile(
            Method::Start,
            || Err(io::Error::other("query failed")),
            |_| panic!("failed status check must not mutate BGP"),
            || true,
        )
        .is_err());
        assert!(reconcile(
            Method::Stop,
            || Ok(true),
            |_| Err(io::Error::other("partial Stop failure")),
            || true,
        )
        .is_err());
        let mut calls = Vec::new();
        reconcile(
            Method::Start,
            || Ok(false),
            |method| {
                calls.push(method);
                Ok(())
            },
            || true,
        )
        .unwrap();
        assert_eq!(calls, [Method::Start]);
    }

    #[test]
    fn down_during_status_query_prevents_the_pending_start() {
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox: Mailbox::default(),
            worker: None,
        };
        controller.state_changed(State::Down, State::Up);
        assert_eq!(
            controller.mailbox.0.lock().unwrap().methods.pop_front(),
            Some(Method::Start)
        );
        assert!(!reconcile(
            Method::Start,
            || {
                controller.state_changed(State::Up, State::Down);
                Ok(false)
            },
            |_| panic!("Down during the status query must supersede Start"),
            || start_is_current(&controller.mailbox),
        )
        .unwrap());
        assert_eq!(controller.mailbox.0.lock().unwrap().methods, [Method::Stop]);
    }

    #[test]
    fn methods_follow_session_transitions() {
        assert_eq!(Method::transition(State::Down, State::Init), None);
        for previous in [State::Down, State::Init] {
            assert_eq!(Method::transition(previous, State::Up), Some(Method::Start));
        }
        for previous in [State::Init, State::Up] {
            assert_eq!(
                Method::transition(previous, State::Down),
                Some(Method::Stop)
            );
        }
        // Stopping the BFD service sets local AdminDown; it never stops BGP.
        for previous in [State::Down, State::Init, State::Up] {
            assert_eq!(Method::transition(previous, State::AdminDown), None);
        }
        for state in [State::Down, State::Init, State::Up, State::AdminDown] {
            assert_eq!(Method::transition(state, state), None);
        }
    }

    #[test]
    fn flapping_keeps_latest_pair_in_bounded_mailbox() {
        let mut pending = Pending::default();
        for _ in 0..1000 {
            pending.push(Method::Stop);
            pending.push(Method::Start);
        }
        assert_eq!(pending.methods, [Method::Stop, Method::Start]);
        pending.push(Method::Start);
        assert_eq!(pending.methods.len(), 2);
        pending.push(Method::Stop);
        assert_eq!(pending.methods, [Method::Stop]);
    }

    #[test]
    fn closing_publishes_cancellation_before_final_calls_and_propagates_their_errors() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Start);
        let cancel = StopSignal::new().unwrap();
        let worker_mailbox = Arc::clone(&mailbox);
        let worker_cancel = cancel.clone();
        let worker = thread::spawn(move || {
            let (mutex, ready) = &*worker_mailbox;
            let pending = mutex.lock().unwrap();
            let pending = ready
                .wait_while(pending, |pending| !pending.closed)
                .unwrap();
            assert!(
                worker_cancel.is_requested(),
                "final action must see closing before dequeue"
            );
            drop(pending);
            work(&worker_mailbox, |method| {
                assert_eq!(method, Method::Start);
                let error = io::Error::from(io::ErrorKind::Interrupted);
                assert!(
                    !superseded_cancellation(&worker_mailbox, &worker_cancel, &error),
                    "an interrupted final action must not be reported as success"
                );
                Err(error)
            })
        });
        let controller = Controller {
            mailbox,
            worker: Some(worker),
            log: None,
            cancel,
        };
        assert_eq!(
            controller.shutdown().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn shutdown_runs_the_queued_final_action_after_an_inflight_call() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Stop);
        let worker_mailbox = Arc::clone(&mailbox);
        let (called, calls) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let worker = thread::spawn(move || {
            work(&worker_mailbox, |method| {
                called.send(method).unwrap();
                if method == Method::Stop {
                    blocked.recv().unwrap();
                }
                Ok(())
            })
        });
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Stop
        );
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox: Arc::clone(&mailbox),
            worker: Some(worker),
        };
        // Stopping the service while BFD's Stop is in flight releases it.
        controller.state_changed(State::Down, State::AdminDown);
        let cancel = controller.cancel.clone();
        let closing = thread::spawn(move || drop(controller));
        {
            let (mutex, ready) = &*mailbox;
            let pending = mutex.lock().unwrap();
            let (pending, timeout) = ready
                .wait_timeout_while(pending, Duration::from_secs(2), |pending| !pending.closed)
                .unwrap();
            assert!(!timeout.timed_out());
            assert_eq!(pending.methods, [Method::Start]);
        }
        release.send(()).unwrap();
        closing.join().unwrap();
        assert!(
            cancel.is_requested(),
            "the superseded call must be cancelled"
        );
        assert_eq!(calls.try_iter().collect::<Vec<_>>(), [Method::Start]);
    }

    #[test]
    fn administrative_release_starts_stopped_peer_after_unexecuted_or_failed_stop() {
        for stop_failed in [false, true] {
            for local_admin_down in [false, true] {
                let controller = Controller {
                    log: None,
                    cancel: StopSignal::new().unwrap(),
                    mailbox: Mailbox::default(),
                    worker: None,
                };
                controller.state_changed(State::Down, State::Up);
                controller.mailbox.0.lock().unwrap().methods.clear();
                // An operator stops the peer after establishment. BFD then
                // requests Stop, but never successfully executes that request.
                controller.state_changed(State::Up, State::Down);
                if stop_failed {
                    let method = controller.mailbox.0.lock().unwrap().methods.pop_front();
                    assert_eq!(method, Some(Method::Stop));
                    assert!(reconcile(
                        method.unwrap(),
                        || panic!("Stop does not query status"),
                        |_| Err(io::Error::other("Stop failed before execution")),
                        || true,
                    )
                    .is_err());
                }
                if local_admin_down {
                    controller.state_changed(State::Down, State::AdminDown);
                } else {
                    controller.peer_admin_down();
                }
                // Drain the final action through the production worker and
                // reconciliation path with a stopped provider fixture.
                controller.mailbox.0.lock().unwrap().closed = true;
                let queries = Cell::new(0);
                let mut calls = Vec::new();
                work(&controller.mailbox, |method| {
                    reconcile(
                        method,
                        || {
                            queries.set(queries.get() + 1);
                            Ok(false)
                        },
                        |method| {
                            calls.push(method);
                            Ok(())
                        },
                        || start_is_current(&controller.mailbox),
                    )
                    .map(|_| ())
                })
                .unwrap();
                assert_eq!(queries.get(), 1);
                assert_eq!(
                    calls,
                    [Method::Start],
                    "stop_failed={stop_failed}, local_admin_down={local_admin_down}"
                );
            }
        }
    }

    #[test]
    fn administrative_disable_releases_only_a_stop_that_bfd_requested() {
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox: Mailbox::default(),
            worker: None,
        };
        let methods = |controller: &Controller| {
            let pending = controller.mailbox.0.lock().unwrap();
            (
                pending.methods.iter().copied().collect::<Vec<_>>(),
                pending.desired,
            )
        };
        // With no requested BFD Stop, administrative release queues no action.
        controller.peer_admin_down();
        controller.state_changed(State::Down, State::AdminDown);
        assert_eq!(methods(&controller), (vec![], None));
        controller.state_changed(State::AdminDown, State::Down);
        controller.state_changed(State::Down, State::Up);
        controller.mailbox.0.lock().unwrap().methods.clear();
        controller.peer_admin_down();
        assert_eq!(methods(&controller), (vec![], Some(Method::Start)));

        // After a failure, the peer's AdminDown withdraws BFD's Stop, even unstarted.
        controller.state_changed(State::Up, State::Down);
        assert_eq!(
            methods(&controller),
            (vec![Method::Stop], Some(Method::Stop))
        );
        controller.peer_admin_down();
        assert_eq!(
            methods(&controller),
            (vec![Method::Start], Some(Method::Start))
        );
        controller.peer_admin_down();
        assert_eq!(
            methods(&controller),
            (vec![Method::Start], Some(Method::Start))
        );

        // Stopping the local service does the same.
        controller.mailbox.0.lock().unwrap().methods.clear();
        controller.state_changed(State::Up, State::Down);
        controller.state_changed(State::Down, State::AdminDown);
        assert_eq!(
            methods(&controller),
            (vec![Method::Start], Some(Method::Start))
        );

        // A closed controller accepts no further actions.
        let mut pending = controller.mailbox.0.lock().unwrap();
        pending.push(Method::Stop);
        pending.closed = true;
        drop(pending);
        controller.peer_admin_down();
        assert_eq!(
            methods(&controller),
            (vec![Method::Stop], Some(Method::Stop))
        );
    }

    #[test]
    fn closing_cancels_an_inflight_call_and_still_runs_the_queued_stop() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Start);
        let cancel = StopSignal::new().unwrap();
        let worker_cancel = cancel.clone();
        let worker_mailbox = Arc::clone(&mailbox);
        let (called, calls) = mpsc::channel();
        let worker = thread::spawn(move || {
            work(&worker_mailbox, |method| {
                called.send(method).unwrap();
                if method == Method::Start {
                    // A slow provider call that ends only when the controller cancels it.
                    worker_cancel.wait(Duration::from_secs(30)).unwrap();
                    assert!(worker_cancel.is_requested());
                }
                Ok(())
            })
        });
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Start
        );
        let controller = Controller {
            log: None,
            mailbox,
            worker: Some(worker),
            cancel,
        };
        // A Down detected before shutdown still stops BGP; shutdown itself doesn't.
        controller.mailbox.0.lock().unwrap().established = true;
        controller.state_changed(State::Up, State::Down);
        let started = std::time::Instant::now();
        controller.shutdown().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Stop
        );
    }

    #[test]
    fn final_stop_failure_is_returned_to_the_service() {
        let mailbox = Mailbox::default();
        {
            let mut pending = mailbox.0.lock().unwrap();
            pending.push(Method::Stop);
            pending.closed = true;
        }
        let worker_mailbox = Arc::clone(&mailbox);
        let worker = thread::spawn(move || {
            work(&worker_mailbox, |method| {
                assert_eq!(method, Method::Stop);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "provider rejected Stop",
                ))
            })
        });
        let controller = Controller {
            log: None,
            cancel: StopSignal::new().unwrap(),
            mailbox,
            worker: Some(worker),
        };
        let error = controller.shutdown().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("provider rejected Stop"));
    }

    #[test]
    fn recovery_waits_for_slow_stop_before_starting() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Stop);
        let worker_mailbox = Arc::clone(&mailbox);
        let (called, calls) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let worker = thread::spawn(move || {
            work(&worker_mailbox, |method| {
                called.send(method).unwrap();
                if method == Method::Stop {
                    blocked.recv().unwrap();
                }
                Ok(())
            })
        });
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Stop
        );
        {
            let mut pending = mailbox.0.lock().unwrap();
            pending.push(Method::Start);
            mailbox.1.notify_one();
        }
        assert!(calls.try_recv().is_err());
        release.send(()).unwrap();
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Start
        );
        {
            let mut pending = mailbox.0.lock().unwrap();
            pending.closed = true;
            mailbox.1.notify_one();
        }
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn failed_call_retries_until_recovery_supersedes_it() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Stop);
        let mut calls = Vec::new();
        work(&mailbox, |method| {
            calls.push(method);
            if calls.len() == 1 {
                return Err(io::Error::other("temporary provider failure"));
            }
            let mut pending = mailbox.0.lock().unwrap();
            if method == Method::Stop {
                pending.push(Method::Start);
                Err(io::Error::other("superseded failure"))
            } else {
                pending.closed = true;
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(calls, [Method::Stop, Method::Stop, Method::Start]);
    }
}
