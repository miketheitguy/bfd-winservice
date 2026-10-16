use bfd_winservice::{
    config::{load_registry, SERVICE_NAME},
    local_rpc::LocalRpcServer,
    runtime::{drop_privileges, verify_bfd_service_identity, Engine, Logger, StopSignal},
};
use std::{
    error::Error,
    ffi::OsString,
    io::{self, Write},
    process,
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

/// After Stop, Shutdown, or Preshutdown, the engine announces AdminDown for a
/// Detection Time and completes any final BGP action. If cleanup still runs after
/// this budget plus the announcement period, the process reports Stopped and exits.
const STOP_BUDGET: Duration = Duration::from_secs(60);
/// Final log records are written before SERVICE_STOPPED, after which the process
/// can end at any time.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

define_windows_service!(service_main, service_entry);

pub fn run() -> Result<(), Box<dyn Error>> {
    service_dispatcher::start(SERVICE_NAME, service_main)?;
    Ok(())
}

fn service_entry(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        let _ = writeln!(io::stderr().lock(), "BFD service failed: {error}");
    }
}

fn run_service() -> Result<(), Box<dyn Error>> {
    let stop = StopSignal::new()?;
    let handler_stop = stop.clone();
    let (diagnostic_tx, diagnostic_rx) = mpsc::sync_channel(4);
    let reporter = Arc::new(Mutex::new(StatusReporter {
        handle: None,
        state: ServiceState::StartPending,
        checkpoint: 1,
    }));
    let stop_reporter = Arc::clone(&reporter);
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        // Preshutdown lets the final BGP Stop reach the broker, which keeps running
        // until the later shutdown phase, before Windows ends service processes.
        // Shutdown is handled too, in case an older registration delivers it.
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            // Serialize with startup/final reporting so a racing Running update
            // cannot overwrite StopPending, nor can Stop overwrite Stopped.
            let mut reporter = stop_reporter
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Err(error) = reporter.set(ServiceState::StopPending, ServiceExitCode::Win32(0)) {
                // Output must never block a control handler or retain its lock.
                let _ =
                    diagnostic_tx.try_send(format!("Unable to report BFD StopPending: {error}"));
            }
            let _ = handler_stop.signal();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    {
        let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
        reporter.handle = Some(handle);
        reporter.publish(ServiceExitCode::Win32(0))?;
    }
    let mut log = match Logger::new(false) {
        Ok(log) => log,
        Err(error) => {
            reporter
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .set(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1))?;
            return Err(error.into());
        }
    };
    let result = (|| -> Result<(), Box<dyn Error>> {
        // Startup can wait for the broker; advance StartPending checkpoints meanwhile.
        let mut engine = with_progress(&reporter, || -> Result<_, Box<dyn Error>> {
            // Require the SCM account and restricted service SID before opening
            // configured resources or accepting local RPC calls.
            verify_bfd_service_identity()?;
            // Drop unused privileges, including SeImpersonatePrivilege, before
            // accepting network traffic.
            let removed = drop_privileges()?;
            if !removed.is_empty() {
                log.log(format_args!(
                    "removed unused process privileges: {}",
                    removed.join(", ")
                ));
            }
            let options = load_registry(false)?;
            // Only BGP control needs the broker; plain BFD starts without it.
            if options.bgp_peer_name.is_some() {
                bfd_winservice::bgp_broker::verify_connection()?;
            }
            log.open_file(&options)?;
            Ok(Engine::from_config(options, &mut log)?)
        })?;
        // The private RPC interface accepts broker queries before Running. RPC
        // dispatch reads immutable snapshots separately from the UDP worker.
        let _local_rpc = LocalRpcServer::start(engine.status_observer())?;
        let started = {
            let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
            reporter.set(ServiceState::Running, ServiceExitCode::Win32(0))?;
            reporter.state == ServiceState::Running
        };
        if started {
            log.service_started();
        }
        // The engine thread waits for provider cleanup. After a Stop/Shutdown
        // request, advance SCM StopPending checkpoints until it finishes, or
        // abandon cleanup that exceeds the stop budget.
        let (done_tx, done_rx) = mpsc::channel();
        let progress = engine.shutdown_progress();
        thread::scope(|scope| -> io::Result<()> {
            let mut supervisor_log = log.clone();
            let worker_log = &mut log;
            let worker = scope.spawn(move || {
                let result = engine.run_until(&stop, worker_log);
                let _ = done_tx.send(());
                result
            });
            let mut stop_started = None;
            while let Err(mpsc::RecvTimeoutError::Timeout) =
                done_rx.recv_timeout(Duration::from_secs(1))
            {
                for diagnostic in diagnostic_rx.try_iter() {
                    supervisor_log.log(diagnostic);
                }
                let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
                if reporter.state == ServiceState::StopPending {
                    let started: Instant = *stop_started.get_or_insert_with(Instant::now);
                    let budget = STOP_BUDGET + progress.announcement();
                    if started.elapsed() >= budget {
                        abandon_cleanup(&mut reporter, &mut supervisor_log, budget);
                    }
                }
                if let Err(error) = reporter.heartbeat() {
                    supervisor_log.log(format_args!(
                        "Unable to report BFD shutdown progress: {error}"
                    ));
                }
                // The receiver also wakes if the worker unwinds.
                if worker.is_finished() {
                    break;
                }
            }
            let result = worker
                .join()
                .map_err(|_| io::Error::other("BFD engine worker panicked"))?;
            for diagnostic in diagnostic_rx.try_iter() {
                supervisor_log.log(diagnostic);
            }
            result
        })?;
        Ok(())
    })();
    if let Err(error) = &result {
        log.service_failed(error);
    }
    log.service_stopped(u32::from(result.is_err()));
    let _ = log.flush(LOG_FLUSH_TIMEOUT);
    drop(log);
    let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
    let exit_code = final_exit_code(result.is_ok(), reporter.state);
    reporter.set(ServiceState::Stopped, exit_code)?;
    result
}

/// SCM recovery restarts the service after an unrequested failure, including a
/// nonzero exit code. A Stop, Shutdown, or Preshutdown request is final even when
/// cleanup failed: events record the failure, and the exit code stays zero so an
/// administrator's Stop is never followed by an automatic restart.
fn final_exit_code(succeeded: bool, state: ServiceState) -> ServiceExitCode {
    if succeeded || state == ServiceState::StopPending {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    }
}

/// Ends the process when engine cleanup exceeds the stop budget. Windows
/// reclaims sockets and handles; the BGP peer is left unchanged, as for any stop.
fn abandon_cleanup(reporter: &mut StatusReporter, log: &mut Logger, budget: Duration) -> ! {
    log.service_failed(format_args!(
        "BFD engine cleanup did not finish within {} seconds; ending the service process",
        budget.as_secs()
    ));
    log.service_stopped(1);
    let _ = log.flush(LOG_FLUSH_TIMEOUT);
    let _ = reporter.set(ServiceState::Stopped, ServiceExitCode::Win32(0));
    process::exit(1);
}

/// Runs startup work while a helper thread advances StartPending checkpoints.
fn with_progress<T>(reporter: &Mutex<StatusReporter>, startup: impl FnOnce() -> T) -> T {
    let (done_tx, done_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) =
                done_rx.recv_timeout(Duration::from_secs(1))
            {
                let _ = reporter
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .heartbeat();
            }
        });
        let result = startup();
        drop(done_tx);
        result
    })
}

// All changes, including the native status call, occur under one mutex.
struct StatusReporter {
    handle: Option<ServiceStatusHandle>,
    state: ServiceState,
    checkpoint: u32,
}

impl StatusReporter {
    fn set(
        &mut self,
        state: ServiceState,
        exit_code: ServiceExitCode,
    ) -> windows_service::Result<()> {
        if self.state == ServiceState::Stopped
            || self.state == ServiceState::StopPending
                && matches!(state, ServiceState::StartPending | ServiceState::Running)
        {
            return Ok(());
        }
        if self.state != state {
            self.checkpoint = 1;
        }
        self.state = state;
        self.publish(exit_code)
    }

    /// Advances the checkpoint while startup or shutdown work is in progress.
    fn heartbeat(&mut self) -> windows_service::Result<()> {
        if matches!(
            self.state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            self.checkpoint = self.checkpoint.saturating_add(1);
            self.publish(ServiceExitCode::Win32(0))?;
        }
        Ok(())
    }

    fn publish(&self, exit_code: ServiceExitCode) -> windows_service::Result<()> {
        if let Some(handle) = &self.handle {
            handle.set_service_status(status(self.state, exit_code, self.checkpoint))?;
        }
        Ok(())
    }
}

fn status(state: ServiceState, exit_code: ServiceExitCode, checkpoint: u32) -> ServiceStatus {
    let pending = matches!(
        state,
        ServiceState::StartPending | ServiceState::StopPending
    );
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        // Preshutdown replaces the shutdown notification; the two are exclusive.
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: if pending { checkpoint } else { 0 },
        wait_hint: if pending {
            Duration::from_secs(30)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_notification_cannot_be_overwritten_by_racing_startup_or_late_stop() {
        let mut reporter = StatusReporter {
            handle: None,
            state: ServiceState::StartPending,
            checkpoint: 1,
        };
        reporter
            .set(ServiceState::StopPending, ServiceExitCode::Win32(0))
            .unwrap();
        reporter
            .set(ServiceState::Running, ServiceExitCode::Win32(0))
            .unwrap();
        assert_eq!(reporter.state, ServiceState::StopPending);
        reporter
            .set(ServiceState::Stopped, ServiceExitCode::Win32(0))
            .unwrap();
        reporter
            .set(ServiceState::StopPending, ServiceExitCode::Win32(0))
            .unwrap();
        assert_eq!(reporter.state, ServiceState::Stopped);
    }

    #[test]
    fn shutdown_checkpoints_advance_and_terminal_status_clears_pending_fields() {
        let mut reporter = StatusReporter {
            handle: None,
            state: ServiceState::StopPending,
            checkpoint: 1,
        };
        reporter.heartbeat().unwrap();
        reporter.heartbeat().unwrap();
        let pending = status(
            reporter.state,
            ServiceExitCode::Win32(0),
            reporter.checkpoint,
        );
        assert_eq!(pending.checkpoint, 3);
        assert_eq!(pending.wait_hint, Duration::from_secs(30));
        assert!(pending.controls_accepted.is_empty());
        let stopped = status(
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(1),
            3,
        );
        assert_eq!(stopped.checkpoint, 0);
        assert_eq!(stopped.wait_hint, Duration::ZERO);
        assert!(stopped.controls_accepted.is_empty());
    }

    #[test]
    fn startup_progress_advances_checkpoints_and_running_accepts_preshutdown() {
        let reporter = Mutex::new(StatusReporter {
            handle: None,
            state: ServiceState::StartPending,
            checkpoint: 1,
        });
        let value = with_progress(&reporter, || {
            thread::sleep(Duration::from_millis(2300));
            7
        });
        assert_eq!(value, 7);
        assert!(reporter.lock().unwrap().checkpoint >= 3);
        let running = status(ServiceState::Running, ServiceExitCode::Win32(0), 0);
        assert_eq!(
            running.controls_accepted,
            ServiceControlAccept::PRESHUTDOWN | ServiceControlAccept::STOP
        );
        let mut idle = StatusReporter {
            handle: None,
            state: ServiceState::Running,
            checkpoint: 0,
        };
        idle.heartbeat().unwrap();
        assert_eq!(idle.checkpoint, 0, "Running must not advance checkpoints");
    }

    #[test]
    fn only_unrequested_failures_report_an_error_exit_code_for_recovery() {
        assert_eq!(
            final_exit_code(false, ServiceState::Running),
            ServiceExitCode::ServiceSpecific(1)
        );
        assert_eq!(
            final_exit_code(false, ServiceState::StartPending),
            ServiceExitCode::ServiceSpecific(1)
        );
        for state in [ServiceState::Running, ServiceState::StopPending] {
            assert_eq!(final_exit_code(true, state), ServiceExitCode::Win32(0));
        }
        assert_eq!(
            final_exit_code(false, ServiceState::StopPending),
            ServiceExitCode::Win32(0)
        );
    }
}
