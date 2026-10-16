//! Privileged, fixed-target BGP management hosted by BfdBgpBroker.
//! This service has no UDP listener or public COM class factory.
mod com;
mod install;
mod mi;
mod service;
mod watchdog;

use crate::{
    bgp::{
        ipc::{self, Frame, Listener},
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

/// Verify the installed broker's identity and the BFD service's pipe authorization.
/// Provider errors do not prevent BFD startup; transport/authentication errors do.
///
/// # Errors
/// Returns authentication, protocol, or connection errors after a bounded retry.
pub fn verify_connection() -> io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match ipc::Client::new().probe() {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(error.raw_os_error(), Some(2 | 231))
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(error) => return Err(error),
        }
    }
}

/// Dispatch fixed installer/probe commands or enter the broker's SCM service.
///
/// # Errors
/// Returns command-line, installer-provisioning, or SCM errors.
pub fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => service::run(),
        [argument] if argument == "--version" => {
            println!("bfd-bgp-broker {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
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

fn serve_with_backend(
    listener: &Listener,
    configured: bool,
    stop: &StopSignal,
    log: &mut Logger,
    mut execute: impl FnMut(Method, &mut Logger) -> io::Result<u32>,
) -> io::Result<()> {
    while !stop.is_requested() {
        if let Err(error) = listener.accept(stop) {
            if stop.is_requested() {
                break;
            }
            return Err(error);
        }
        let mut sequence = 0;
        let result = (|| -> io::Result<()> {
            while !stop.is_requested() {
                let request = listener.request(sequence, stop)?;
                sequence = request.sequence;
                let mut response = Frame {
                    method: request.method,
                    sequence,
                    status: 0,
                    value: 0,
                };
                if configured {
                    match execute(request.method, log) {
                        Ok(value) => response.value = value,
                        Err(error) => {
                            response.status = error
                                .raw_os_error()
                                .and_then(|code| u32::try_from(code).ok())
                                .filter(|code| *code != 0)
                                .unwrap_or(31);
                        }
                    }
                } else {
                    response.status = ipc::NOT_CONFIGURED;
                }
                listener.respond(response, stop)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            if !stop.is_requested()
                && !matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                )
            {
                log.broker_message(
                    format_args!("BGP broker client disconnected: {error}"),
                    true,
                );
            }
        }
        // The BFD service stopping, failing, or crashing is not a path failure:
        // a disconnection, like broker shutdown, leaves the peer unchanged.
        listener.disconnect();
    }
    Ok(())
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use ipc::fixtures;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn disconnect_before_accept_keeps_broker_available_for_the_next_client() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        drop(fixtures::connect_pipe(&name));
        let stop = StopSignal::new().unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                serve_with_backend(
                    &listener,
                    true,
                    &stop,
                    &mut Logger::new(false).unwrap(),
                    |method, _| {
                        assert_eq!(method, Method::Get);
                        Ok(1)
                    },
                )
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            assert_eq!(fixtures::request(&client, Method::Get, 1).unwrap().value, 1);
            stop.signal().unwrap();
            server.join().unwrap().unwrap();
        });
    }

    #[test]
    fn query_only_and_unconfigured_connections_never_mutate_on_disconnect() {
        for configured in [false, true] {
            let (listener, name) = fixtures::listener("S-1-1-0");
            let stop = StopSignal::new().unwrap();
            let (called, calls) = mpsc::channel();
            thread::scope(|scope| {
                let server = scope.spawn(|| {
                    let mut log = Logger::new(true).unwrap();
                    serve_with_backend(&listener, configured, &stop, &mut log, |method, _| {
                        called.send(method).unwrap();
                        Ok(1)
                    })
                });
                let _cleanup = fixtures::StopOnDrop(stop.clone());
                let client = fixtures::connect_pipe(&name);
                let response = fixtures::request(&client, Method::Get, 1).unwrap();
                assert_eq!(
                    response.status,
                    if configured { 0 } else { ipc::NOT_CONFIGURED }
                );
                if configured {
                    assert_eq!(
                        calls.recv_timeout(Duration::from_secs(3)).unwrap(),
                        Method::Get
                    );
                }
                drop(client);
                stop.signal().unwrap();
                server.join().unwrap().unwrap();
                assert!(calls.try_recv().is_err());
            });
        }
    }

    #[test]
    fn disconnect_after_a_mutation_leaves_the_peer_and_serves_the_next_client() {
        for start_fails in [false, true] {
            let (listener, name) = fixtures::listener("S-1-1-0");
            let stop = StopSignal::new().unwrap();
            let (called, calls) = mpsc::channel();
            thread::scope(|scope| {
                let server = scope.spawn(|| {
                    let mut log = Logger::new(true).unwrap();
                    serve_with_backend(&listener, true, &stop, &mut log, |method, _| {
                        called.send(method).unwrap();
                        match method {
                            Method::Start if start_fails => Err(io::Error::from_raw_os_error(5)),
                            Method::Start => Ok(1),
                            Method::Stop | Method::Get => Ok(0),
                        }
                    })
                });
                let _cleanup = fixtures::StopOnDrop(stop.clone());
                let client = fixtures::connect_pipe(&name);
                let response = fixtures::request(&client, Method::Start, 1).unwrap();
                assert_eq!(response.status, if start_fails { 5 } else { 0 });
                // The BFD service stopping or failing must not stop the peer.
                drop(client);
                let next = fixtures::connect_pipe(&name);
                assert_eq!(fixtures::request(&next, Method::Get, 1).unwrap().status, 0);
                stop.signal().unwrap();
                server.join().unwrap().unwrap();
                assert_eq!(
                    calls.try_iter().collect::<Vec<_>>(),
                    [Method::Start, Method::Get]
                );
            });
        }
    }

    #[test]
    fn replay_is_rejected_before_backend_and_disconnect_leaves_the_peer() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        let stop = StopSignal::new().unwrap();
        let (called, calls) = mpsc::channel();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut log = Logger::new(true).unwrap();
                serve_with_backend(&listener, true, &stop, &mut log, |method, _| {
                    called.send(method).unwrap();
                    Ok(0)
                })
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            fixtures::request(&client, Method::Start, 1).unwrap();
            assert!(fixtures::request(&client, Method::Get, 1).is_err());
            // Confirm the broker finished with the rejected connection.
            drop(client);
            let next = fixtures::connect_pipe(&name);
            drop(next);
            stop.signal().unwrap();
            server.join().unwrap().unwrap();
            assert_eq!(calls.try_iter().collect::<Vec<_>>(), [Method::Start]);
        });
    }

    #[test]
    fn broker_shutdown_leaves_a_started_peer_unchanged() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        let stop = StopSignal::new().unwrap();
        let (called, calls) = mpsc::channel();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut log = Logger::new(true).unwrap();
                serve_with_backend(&listener, true, &stop, &mut log, |method, _| {
                    called.send(method).unwrap();
                    Ok(1)
                })
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            fixtures::request(&client, Method::Start, 1).unwrap();
            stop.signal().unwrap();
            server.join().unwrap().unwrap();
            assert_eq!(calls.try_iter().collect::<Vec<_>>(), [Method::Start]);
        });
    }

    #[test]
    fn unauthorized_request_never_reaches_backend() {
        let (listener, name) = fixtures::listener(ipc::SERVICE_SID);
        let stop = StopSignal::new().unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut log = Logger::new(true).unwrap();
                serve_with_backend(&listener, true, &stop, &mut log, |_, _| {
                    panic!("unauthorized provider operation")
                })
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            assert!(fixtures::request(&client, Method::Start, 1).is_err());
            stop.signal().unwrap();
            server.join().unwrap().unwrap();
        });
    }
}
