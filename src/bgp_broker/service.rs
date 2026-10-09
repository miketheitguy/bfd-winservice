//! SCM lifecycle for the broker. Provider work stays off the control-handler thread.
use super::{ipc, serve, Target};
use crate::{
    com::ComServer,
    runtime::{Logger, StopSignal},
};
use std::{
    ffi::OsString,
    io,
    sync::{mpsc, Arc, Mutex},
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

define_windows_service!(broker_entry, entry);
pub(super) fn run() -> io::Result<()> {
    service_dispatcher::start(ipc::BROKER_NAME, broker_entry).map_err(io::Error::other)
}
fn entry(_: Vec<OsString>) {
    if let Err(error) = start() {
        if let Ok(mut log) = Logger::new(false) {
            log.broker_message(format_args!("service failed: {error}"), true);
        }
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
        // uses the apartment/security lifecycle without registering a COM factory.
        let com = ComServer::initialize()?;
        let target = Target::load()?;
        let listener = ipc::Listener::new()?;
        let mut log = Logger::new(false)?;
        log.broker_message("ready; service identity and pipe ACL verified", false);
        reporter
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .publish(ServiceState::Running, false)?;
        let (sender, receiver) = mpsc::channel();
        thread::scope(|scope| -> io::Result<()> {
            let worker = scope.spawn(|| {
                let result = serve(&listener, target.as_ref(), &stop, &mut log);
                let _ = sender.send(());
                result
            });
            while receiver.recv_timeout(Duration::from_secs(1)).is_err() && !worker.is_finished() {
                let mut reporter = reporter.lock().unwrap_or_else(|error| error.into_inner());
                if reporter.state == ServiceState::StopPending {
                    if let Err(error) = reporter.publish(ServiceState::StopPending, false) {
                        // A scoped worker must be cancelled before returning, otherwise
                        // its pending pipe read would keep scope teardown waiting forever.
                        let _ = stop.signal();
                        return Err(error);
                    }
                }
            }
            worker
                .join()
                .map_err(|_| io::Error::other("BGP broker worker panicked"))?
        })?;
        com.shutdown()?;
        Ok(())
    })();
    reporter
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .publish(ServiceState::Stopped, result.is_err())?;
    result
}
