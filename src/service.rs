use bfd_winservice::{
    config::Options,
    packet::AuthConfig,
    runtime::{Engine, Logger},
};
use std::{
    ffi::OsString,
    io,
    sync::{mpsc, Arc, Mutex, OnceLock},
    thread,
    time::Duration,
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

const SERVICE_NAME: &str = "BfdWinService";
static CONFIGURATION: OnceLock<(Options, AuthConfig)> = OnceLock::new();
define_windows_service!(service_main, service_entry);

pub fn run(options: Options, auth: AuthConfig) -> Result<(), Box<dyn std::error::Error>> {
    CONFIGURATION
        .set((options, auth))
        .map_err(|_| "service configuration already initialized")?;
    service_dispatcher::start(SERVICE_NAME, service_main)?;
    Ok(())
}

fn service_entry(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("BFD service failed: {error}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let reporter = Arc::new(Mutex::new(StatusReporter {
        handle: None,
        state: ServiceState::StartPending,
        checkpoint: 1,
    }));
    let stop_reporter = Arc::clone(&reporter);
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Serialize with startup/final reporting so a racing Running update
            // cannot overwrite StopPending, nor can Stop overwrite Stopped.
            let mut reporter = stop_reporter
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Err(error) = reporter.set(ServiceState::StopPending, ServiceExitCode::Win32(0)) {
                eprintln!("Unable to report BFD StopPending: {error}");
            }
            let _ = stop_tx.send(());
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
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let (options, auth) = CONFIGURATION.get().ok_or("missing service configuration")?;
        let mut log = Logger::open(options)?;
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let mut engine = Engine::open(options.clone(), auth.clone(), &mut log)?;
            reporter
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .set(ServiceState::Running, ServiceExitCode::Win32(0))?;
            // The engine thread waits for provider cleanup. After a Stop/Shutdown
            // request, advance SCM StopPending checkpoints until it finishes.
            let (done_tx, done_rx) = mpsc::channel();
            thread::scope(|scope| -> io::Result<()> {
                let worker_log = &mut log;
                let worker = scope.spawn(move || {
                    let result = engine.run(&stop_rx, worker_log);
                    let _ = done_tx.send(());
                    result
                });
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    done_rx.recv_timeout(Duration::from_secs(1))
                {
                    let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
                    if let Err(error) = reporter.heartbeat() {
                        eprintln!("Unable to report BFD shutdown progress: {error}");
                    }
                    // The receiver also wakes if the worker unwinds.
                    if worker.is_finished() {
                        break;
                    }
                }
                worker
                    .join()
                    .map_err(|_| io::Error::other("BFD engine worker panicked"))?
            })?;
            Ok(())
        })();
        if let Err(error) = &result {
            log.log(format!("service failed: {error}"));
        }
        result
    })();
    reporter
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .set(
            ServiceState::Stopped,
            if result.is_ok() {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(1)
            },
        )?;
    result
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

    fn heartbeat(&mut self) -> windows_service::Result<()> {
        if self.state == ServiceState::StopPending {
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
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: if pending { checkpoint } else { 0 },
        wait_hint: if state == ServiceState::StopPending {
            Duration::from_secs(30)
        } else if pending {
            Duration::from_secs(5)
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
}
