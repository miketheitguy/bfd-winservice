//! SCM lifecycle for the broker. Provider work stays off the control-handler thread.
use super::{
    com::ComHost,
    ipc, serve,
    watchdog::{ProviderWatch, PROVIDER_BUDGET},
    Target,
};
use crate::runtime::{Logger, StopSignal};
use std::{
    ffi::OsString,
    io, process,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

/// A synchronous MI call can outlast its requested timeout. After this long in
/// StopPending, the broker reports Stopped and ends its process.
const STOP_BUDGET: Duration = Duration::from_secs(60);
/// Final records are written before SERVICE_STOPPED ends the process lifetime.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
/// Another process may hold the pipe name; retry while reporting the conflict.
const LISTENER_RETRY: Duration = Duration::from_secs(1);
const SQUAT_REPORT_INTERVAL: Duration = Duration::from_secs(60);

define_windows_service!(broker_entry, entry);
pub(super) fn run() -> io::Result<()> {
    service_dispatcher::start(ipc::BROKER_NAME, broker_entry).map_err(io::Error::other)
}
fn entry(_: Vec<OsString>) {
    // start() records its own failures before reporting Stopped.
    if let Err(error) = start() {
        eprintln!("BGP broker service failed: {error}");
    }
}

struct Reporter {
    handle: Option<ServiceStatusHandle>,
    state: ServiceState,
    checkpoint: u32,
}
impl Reporter {
    fn publish(&mut self, state: ServiceState, failure: bool) -> io::Result<()> {
        // Reporting Stopped closes SCM's RPC context. Even a queued control
        // handler must never use that status handle again.
        if self.state == ServiceState::Stopped {
            return Ok(());
        }
        // A Stop received during startup must not be overwritten by Running.
        if self.state == ServiceState::StopPending && state == ServiceState::Running {
            return Ok(());
        }
        self.checkpoint = if self.state == state {
            self.checkpoint.saturating_add(1)
        } else {
            1
        };
        self.state = state;
        let pending = matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        );
        if let Some(handle) = &self.handle {
            handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: state,
                    controls_accepted: if state == ServiceState::Running {
                        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                    } else {
                        ServiceControlAccept::empty()
                    },
                    exit_code: if failure {
                        ServiceExitCode::ServiceSpecific(1)
                    } else {
                        ServiceExitCode::Win32(0)
                    },
                    checkpoint: if pending { self.checkpoint } else { 0 },
                    wait_hint: if pending {
                        Duration::from_secs(30)
                    } else {
                        Duration::ZERO
                    },
                    process_id: None,
                })
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

fn start() -> io::Result<()> {
    // Created first so every later failure is recorded before SERVICE_STOPPED.
    let mut log = Logger::new(false)?;
    let stop = StopSignal::new()?;
    let reporter = Arc::new(Mutex::new(Reporter {
        handle: None,
        state: ServiceState::StartPending,
        checkpoint: 0,
    }));
    let handler_reporter = Arc::clone(&reporter);
    let handler_stop = stop.clone();
    let handle =
        service_control_handler::register(ipc::BROKER_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let mut reporter = handler_reporter
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let _ = reporter.publish(ServiceState::StopPending, false);
                let _ = handler_stop.signal();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(io::Error::other)?;
    {
        let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
        reporter.handle = Some(handle);
        reporter.publish(ServiceState::StartPending, false)?;
    }
    let result = (|| -> io::Result<()> {
        ipc::require_broker_identity()?;
        // Initialize process security before MI can marshal anything. This process
        // registers no COM factory, so interactive users get no COM access.
        let com = ComHost::initialize()?;
        let target = Target::load()?;
        reporter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .publish(ServiceState::Running, false)?;
        let (sender, receiver) = mpsc::channel();
        let watch = ProviderWatch::default();
        thread::scope(|scope| -> io::Result<()> {
            let mut supervisor_log = log.clone();
            let worker_log = &mut log;
            let worker = scope.spawn(|| {
                let result = acquire_listener(&stop, worker_log).and_then(|listener| {
                    worker_log
                        .broker_message("ready; service identity and pipe ACL verified", false);
                    listener.map_or(Ok(()), |listener| {
                        serve(&listener, target.as_ref(), &stop, worker_log, &watch)
                    })
                });
                let _ = sender.send(());
                result
            });
            let mut stop_deadline = None;
            let mut status_failure = None;
            while receiver.recv_timeout(Duration::from_secs(1)).is_err() && !worker.is_finished() {
                let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
                if let Some(method) = watch.expired(Instant::now()) {
                    abandon_provider(&mut reporter, method);
                }
                if reporter.state == ServiceState::StopPending {
                    let deadline =
                        *stop_deadline.get_or_insert_with(|| Instant::now() + STOP_BUDGET);
                    if Instant::now() >= deadline {
                        abandon_cleanup(&mut reporter);
                    }
                    if let Err(error) = reporter.publish(ServiceState::StopPending, false) {
                        // Keep supervising after a status failure: leaving the scope
                        // would join a potentially stuck provider without a watchdog.
                        if status_failure.is_none() {
                            supervisor_log.broker_message(
                                format_args!("could not report broker shutdown progress: {error}"),
                                true,
                            );
                            status_failure = Some(error);
                        }
                        let _ = stop.signal();
                    }
                }
            }
            worker
                .join()
                .map_err(|_| io::Error::other("BGP broker worker panicked"))?
                .and(status_failure.map_or(Ok(()), Err))
        })?;
        com.shutdown()?;
        Ok(())
    })();
    if let Err(error) = &result {
        log.broker_message(format_args!("service failed: {error}"), true);
    }
    let _ = log.flush(LOG_FLUSH_TIMEOUT);
    drop(log);
    reporter
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .publish(ServiceState::Stopped, result.is_err())?;
    result
}

/// Creates the pipe server, retrying while another process holds its name. The
/// broker stays Running so plain BFD sessions, which never contact it, can start.
/// Returns None if Stop arrives first.
fn acquire_listener(stop: &StopSignal, log: &mut Logger) -> io::Result<Option<ipc::Listener>> {
    let mut last_report = None;
    loop {
        match ipc::Listener::new() {
            Ok(listener) => return Ok(Some(listener)),
            Err(error) if ipc::is_name_in_use(&error) => {
                let now = Instant::now();
                if last_report
                    .is_none_or(|last: Instant| now.duration_since(last) >= SQUAT_REPORT_INTERVAL)
                {
                    last_report = Some(now);
                    log.broker_message(
                        format_args!(
                            "another process holds the BGP pipe name; BGP control waits for it to close: {error}"
                        ),
                        true,
                    );
                }
                stop.wait(LISTENER_RETRY)?;
                if stop.is_requested() {
                    return Ok(None);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Ends the process when a provider call keeps cleanup running past the stop
/// budget. The BFD service reconciles BGP state when the broker next starts.
fn abandon_cleanup(reporter: &mut Reporter) -> ! {
    if let Ok(mut log) = Logger::new(false) {
        log.broker_message(
            format_args!(
                "cleanup did not finish within {} seconds; ending the broker process",
                STOP_BUDGET.as_secs()
            ),
            true,
        );
        let _ = log.flush(LOG_FLUSH_TIMEOUT);
    }
    let _ = reporter.publish(ServiceState::Stopped, true);
    process::exit(1);
}

/// A Running broker exits without reporting Stopped, triggering its configured
/// SCM crash recovery. A requested Stop remains final and must not restart it.
fn abandon_provider(reporter: &mut Reporter, method: crate::bgp::Method) -> ! {
    if let Ok(mut log) = Logger::new(false) {
        log.broker_message(
            format_args!(
                "provider method={} exceeded its {}-second wall-clock budget; ending the broker process",
                method.name(), PROVIDER_BUDGET.as_secs()
            ),
            true,
        );
        let _ = log.flush(LOG_FLUSH_TIMEOUT);
    }
    if reporter.state == ServiceState::StopPending {
        let _ = reporter.publish(ServiceState::Stopped, true);
    }
    process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopped_status_is_terminal_even_for_queued_controls() {
        let mut reporter = Reporter {
            handle: None,
            state: ServiceState::Running,
            checkpoint: 0,
        };
        reporter.publish(ServiceState::Stopped, false).unwrap();
        let checkpoint = reporter.checkpoint;
        for state in [
            ServiceState::StopPending,
            ServiceState::Running,
            ServiceState::Stopped,
        ] {
            reporter.publish(state, true).unwrap();
            assert_eq!(reporter.state, ServiceState::Stopped);
            assert_eq!(reporter.checkpoint, checkpoint);
        }
    }
}
