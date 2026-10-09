//! Bounded BGP control through the authenticated local broker, off the BFD thread.

pub(crate) mod ipc;

use crate::{config::Options, packet::State, runtime::Logger};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

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

    fn transition(previous: State, current: State) -> Option<Self> {
        if previous == current {
            return None;
        }
        match current {
            State::Up => Some(Self::Start),
            State::Down | State::AdminDown => Some(Self::Stop),
            State::Init => None,
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
}

type Mailbox = Arc<(Mutex<Pending>, Condvar)>;

pub(crate) struct Controller {
    mailbox: Mailbox,
    worker: Option<JoinHandle<io::Result<()>>>,
    log: Option<Logger>,
}

impl Controller {
    pub(crate) fn open(options: &Options, logger: &Logger) -> io::Result<Option<Self>> {
        let Some(peer) = options.bgp_peer_name.clone() else {
            return Ok(None);
        };
        if options.console {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "BGP control requires the installed BfdWinService service identity",
            ));
        }
        let mut log = logger.clone();
        let mailbox = Mailbox::default();
        let worker_mailbox = Arc::clone(&mailbox);
        let worker = thread::Builder::new()
            .name("bgp-ipc".into())
            .spawn(move || {
                let client = std::cell::RefCell::new(ipc::Client::new());
                match client.borrow_mut().started() {
                    Ok(started) => {
                        log.log(format!("BGP peer={peer:?} startup started={started}; BFD handshake begins without changing BGP"));
                    }
                    Err(error) => {
                        log.log(format!("BGP peer={peer:?} startup status check failed: {error}; will recheck when BFD reaches Up"));
                    }
                }
                work_with_health(&worker_mailbox, |method| {
                    let mut result = reconcile(method,
                        || client.borrow_mut().started(),
                        |method| client.borrow_mut().invoke(method),
                        || start_is_current(&worker_mailbox));
                    // Claim a running peer without restarting it, so the broker
                    // knows to Stop it if this managed connection disappears.
                    if method == Method::Start && matches!(result, Ok(false)) && start_is_current(&worker_mailbox) {
                        result = client.borrow_mut().invoke(Method::Start).map(|()| false);
                    }
                    match &result {
                        Ok(true) => log.log(format!(
                            "BGP peer={peer:?} method={} succeeded",
                            method.name()
                        )),
                        Ok(false) => log.log(format!("BGP peer={peer:?} Start unnecessary or superseded by BFD; leaving BGP unchanged")),
                        Err(error) => log.log(format!(
                            "BGP peer={peer:?} method={} failed: {error}",
                            method.name()
                        )),
                    }
                    result.map(|_| ())
                }, || client.borrow_mut().maintain())
            })?;
        Ok(Some(Self {
            mailbox,
            worker: Some(worker),
            log: Some(logger.clone()),
        }))
    }

    pub(crate) fn state_changed(&self, previous: State, current: State) {
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

    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.finish()
    }

    fn finish(&mut self) -> io::Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (mutex, ready) = &*self.mailbox;
        {
            let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            pending.closed = true;
            // Closing must never execute queued Starts, even without AdminDown.
            pending.methods.retain(|method| *method == Method::Stop);
            ready.notify_one();
        }
        worker
            .join()
            .map_err(|_| io::Error::other("BGP MI worker panicked"))?
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
            // The peer may have changed since startup or a failed method call.
            // Check again at Up rather than act on an old snapshot.
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
fn start_is_current(mailbox: &Mailbox) -> bool {
    let pending = mailbox.0.lock().unwrap_or_else(|error| error.into_inner());
    !pending.closed && pending.methods.is_empty()
}

#[cfg(test)]
fn work(mailbox: &Mailbox, mut invoke: impl FnMut(Method) -> io::Result<()>) -> io::Result<()> {
    work_with_health(mailbox, &mut invoke, || Ok(false))
}

fn work_with_health(
    mailbox: &Mailbox,
    mut invoke: impl FnMut(Method) -> io::Result<()>,
    mut health: impl FnMut() -> io::Result<bool>,
) -> io::Result<()> {
    let (mutex, ready) = &**mailbox;
    let mut last_failure = None;
    loop {
        let method = {
            let mut pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
            while pending.methods.is_empty() && !pending.closed {
                let (next, timeout) = ready
                    .wait_timeout(pending, Duration::from_secs(1))
                    .unwrap_or_else(|error| error.into_inner());
                pending = next;
                if timeout.timed_out() && pending.methods.is_empty() && !pending.closed {
                    // Pipe health checks and reconnects never hold the engine's lock.
                    drop(pending);
                    let reconnected = health();
                    pending = mutex.lock().unwrap_or_else(|error| error.into_inner());
                    if matches!(reconnected, Ok(true)) && !pending.closed {
                        if let Some(desired) = pending.desired {
                            pending.push(desired);
                        }
                    }
                }
            }
            let Some(method) = pending.methods.pop_front() else {
                return last_failure.map_or(Ok(()), Err);
            };
            if pending.closed && method == Method::Start {
                continue;
            }
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
    fn reconnection_reapplies_up_but_never_mutates_during_cold_start() {
        for established in [false, true] {
            let mailbox = Mailbox::default();
            if established {
                mailbox.0.lock().unwrap().push(Method::Start);
            }
            let mut calls = Vec::new();
            work_with_health(
                &mailbox,
                |method| {
                    calls.push(method);
                    if calls.len() == 2 {
                        mailbox.0.lock().unwrap().closed = true;
                    }
                    Ok(())
                },
                || {
                    let mut pending = mailbox
                        .0
                        .try_lock()
                        .expect("health check must not hold engine lock");
                    if !established {
                        pending.closed = true;
                    }
                    Ok(true)
                },
            )
            .unwrap();
            assert_eq!(
                calls,
                if established {
                    vec![Method::Start, Method::Start]
                } else {
                    vec![]
                }
            );
        }
    }

    #[test]
    fn down_during_reconnect_supersedes_up_without_blocking_the_mailbox() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Start);
        let (called, calls) = mpsc::channel();
        let (checking, checks) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        thread::scope(|scope| {
            let worker_mailbox = &mailbox;
            let worker = scope.spawn(move || {
                work_with_health(
                    worker_mailbox,
                    |method| {
                        called.send(method).unwrap();
                        if method == Method::Stop {
                            worker_mailbox.0.lock().unwrap().closed = true;
                        }
                        Ok(())
                    },
                    || {
                        checking.send(()).unwrap();
                        blocked.recv_timeout(Duration::from_secs(3)).unwrap();
                        Ok(true)
                    },
                )
            });
            assert_eq!(
                calls.recv_timeout(Duration::from_secs(3)).unwrap(),
                Method::Start
            );
            checks.recv_timeout(Duration::from_secs(3)).unwrap();
            mailbox
                .0
                .try_lock()
                .expect("reconnect blocked the engine")
                .push(Method::Stop);
            release.send(()).unwrap();
            assert_eq!(
                calls.recv_timeout(Duration::from_secs(3)).unwrap(),
                Method::Stop
            );
            worker.join().unwrap().unwrap();
            assert!(calls.try_recv().is_err());
        });
    }

    #[test]
    fn startup_handshake_preserves_bgp_until_bfd_first_establishes() {
        let controller = Controller {
            log: None,
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
    fn already_started_bgp_is_unchanged_when_bfd_establishes() {
        assert!(!reconcile(
            Method::Start,
            || Ok(true),
            |_| panic!("already started peer must not be changed"),
            || true,
        )
        .unwrap());
    }

    #[test]
    fn stopped_bgp_starts_on_bfd_up_and_restarts_after_later_failure() {
        let started = std::cell::Cell::new(false);
        let mut calls = Vec::new();
        for method in [Method::Start, Method::Start, Method::Stop, Method::Start] {
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
            .unwrap();
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
        assert_eq!(
            Method::transition(State::Up, State::AdminDown),
            Some(Method::Stop)
        );
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
    fn shutdown_discards_queued_start_behind_an_inflight_stop() {
        let mailbox = Mailbox::default();
        mailbox.0.lock().unwrap().push(Method::Stop);
        let worker_mailbox = Arc::clone(&mailbox);
        let (called, calls) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let worker = thread::spawn(move || {
            work(&worker_mailbox, |method| {
                called.send(method).unwrap();
                blocked.recv().unwrap();
                Ok(())
            })
        });
        assert_eq!(
            calls.recv_timeout(Duration::from_secs(2)).unwrap(),
            Method::Stop
        );
        let controller = Controller {
            log: None,
            mailbox: Arc::clone(&mailbox),
            worker: Some(worker),
        };
        controller.state_changed(State::Down, State::Up);
        let closing = thread::spawn(move || drop(controller));
        {
            let (mutex, ready) = &*mailbox;
            let pending = mutex.lock().unwrap();
            let (pending, timeout) = ready
                .wait_timeout_while(pending, Duration::from_secs(2), |pending| !pending.closed)
                .unwrap();
            assert!(!timeout.timed_out());
            assert!(pending.methods.is_empty());
        }
        release.send(()).unwrap();
        closing.join().unwrap();
        assert!(matches!(
            calls.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
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
