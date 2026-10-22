//! Privileged, fixed-target BGP management hosted by BfdBgpBroker.
//! This service has no UDP listener or public COM class factory.
mod com;
mod install;
mod mi;
mod service;
mod watchdog;

use crate::{
    bgp::{
        ipc::{self, Listener},
        Method,
    },
    config::load_bgp_target,
    runtime::{Logger, StopSignal},
};
use std::io;

// Test-only bridge: exercise real MI traffic and local RPC in one process while
// keeping the provider host's production COM initialization unchanged.
#[cfg(test)]
pub(crate) fn test_rpc_with_provider<R>(
    work: impl FnOnce(fn() -> io::Result<()>) -> R,
) -> io::Result<R> {
    let _com = com::ComHost::initialize()?;
    Ok(work(mi::rpc_schema_fixture))
}

/// Dispatch fixed installer commands or enter the broker's SCM service.
///
/// # Errors
/// Returns command-line, installer-provisioning, or SCM errors.
pub fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => service::run(),
        [argument] if argument == "--prepare-install" => install::prepare(),
        [argument] if argument == "--configure-install" => install::configure(),
        [argument] if argument == "--rollback-install" => install::rollback(),
        [argument] if argument == "--commit-install" => install::commit(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported BGP broker arguments",
        )),
    }
}

struct Target {
    peer: String,
    domain: Option<String>,
}
impl Target {
    fn load() -> io::Result<Option<Self>> {
        load_bgp_target().map(|target| target.map(|(peer, domain)| Self { peer, domain }))
    }
    fn execute(&self, method: Method, log: &Logger) -> io::Result<u32> {
        match method {
            Method::Get => mi::started(&self.peer, self.domain.as_deref(), log).map(u32::from),
            Method::Start => {
                if mi::started(&self.peer, self.domain.as_deref(), log)? {
                    return Ok(0);
                }
                mi::invoke(&self.peer, self.domain.as_deref(), method, log).map(|()| 1)
            }
            Method::Stop => mi::invoke(&self.peer, self.domain.as_deref(), method, log).map(|()| 0),
        }
    }
}

fn serve(
    listener: &Listener,
    target: Option<&Target>,
    stop: &StopSignal,
    log: &mut Logger,
    watch: &watchdog::ProviderWatch,
) -> io::Result<()> {
    serve_with_backend(listener, target.is_some(), stop, log, |method, log| {
        let target = target.ok_or_else(|| io::Error::other("BGP is not configured"))?;
        let result = {
            let _call = watch.begin(method);
            target.execute(method, log)
        };
        if method != Method::Get || result.is_err() {
            log.broker_message(
                format_args!(
                    "BGP broker peer={:?} method={} result={result:?}",
                    target.peer,
                    method.name()
                ),
                result.is_err(),
            );
        }
        result
    })
}

pub(crate) fn serve_with_backend(
    listener: &Listener,
    configured: bool,
    stop: &StopSignal,
    log: &mut Logger,
    mut execute: impl FnMut(Method, &mut Logger) -> io::Result<u32>,
) -> io::Result<()> {
    while let Some(request) = listener.request(stop)? {
        // Never execute a queued request after its caller cancelled or shutdown
        // started. An already running provider operation cannot be rolled back.
        if stop.is_requested() || request.is_cancelled() {
            request.respond(995, 0);
            continue;
        }
        let (status, value) = if configured {
            match execute(request.method, log) {
                Ok(value) => (0, value),
                Err(error) => (
                    error
                        .raw_os_error()
                        .and_then(|code| u32::try_from(code).ok())
                        .filter(|code| *code != 0)
                        .unwrap_or(31),
                    0,
                ),
            }
        } else {
            (ipc::NOT_CONFIGURED, 0)
        };
        request.respond(status, value);
    }
    // Loss of the RPC caller never initiates a provider mutation.
    Ok(())
}
