//! Windows BFD packet/timer loop, logging, and optional background BGP control.
use crate::{
    bgp::Controller,
    config::Options,
    event_log::{Provider, SessionEvent},
    packet::{AuthConfig, State},
    session::{ReceiveError, Session},
    transport::Transport,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Operational ETW events in service mode, STDOUT in console mode, and an
/// optional append-only file log in either mode.
pub struct Logger {
    file: Option<File>,
    console: bool,
    event_log: Option<Provider>,
}

impl Logger {
    /// Create a startup logger before registry settings are loaded, so a
    /// configuration failure is visible in the service log or on STDOUT.
    pub fn new(console: bool) -> Self {
        let mut log = Self {
            file: None,
            console,
            event_log: None,
        };
        if !console {
            match Provider::register() {
                Ok(provider) => log.event_log = Some(provider),
                // Registry settings and the optional file log are not open
                // yet; use stderr so this failure has a fallback destination.
                Err(error) => {
                    eprintln!("unable to register BFD-Service ETW provider: {error}");
                }
            }
        }
        log
    }

    /// Open/create the append log and select Operational ETW or console STDOUT.
    ///
    /// # Errors
    /// Returns an error if the configured file cannot be opened.
    pub fn open(options: &Options) -> io::Result<Self> {
        let mut log = Self::new(options.console);
        log.open_file(options.log_file.as_deref())?;
        Ok(log)
    }

    /// Configure the optional append log after loading registry settings.
    ///
    /// # Errors
    /// Returns an error if the configured file cannot be opened.
    pub fn open_file(&mut self, path: Option<&Path>) -> io::Result<()> {
        self.file = path
            .map(|path| OpenOptions::new().create(true).append(true).open(path))
            .transpose()?;
        Ok(())
    }

    /// Record successful engine startup (after SCM Running in service mode).
    pub fn service_started(&mut self) {
        self.log(format_args!(
            "service started mode={}",
            if self.console { "console" } else { "service" }
        ));
        self.event(|provider, console| provider.service_started(console));
    }

    /// Record completed shutdown, with zero for success and one for failure.
    pub fn service_stopped(&mut self, exit_code: u32) {
        self.log(format_args!("service stopped exit_code={exit_code}"));
        self.event(|provider, console| provider.service_stopped(console, exit_code));
    }

    /// Record an initialization or execution failure without authentication data.
    pub fn service_failed(&mut self, error: impl std::fmt::Display) {
        let error = error.to_string();
        self.log(format_args!("service failed: {error}"));
        self.event(|provider, console| provider.service_failed(console, &error));
    }

    fn event(&mut self, write: impl FnOnce(&Provider, bool) -> io::Result<()>) {
        if let Some(Err(error)) = self
            .event_log
            .as_ref()
            .map(|provider| write(provider, self.console))
        {
            self.log(format_args!(
                "unable to write BFD-Service ETW event: {error}"
            ));
        }
    }

    fn session_event(
        &mut self,
        event: SessionEvent,
        options: &Options,
        session: &Session,
        previous: State,
        remote_discriminator: u32,
    ) {
        self.event(|provider, _| {
            provider.session_event(event, options, session, previous, remote_discriminator)
        });
    }
    /// Write a Unix-millisecond timestamp and message. File write failures are
    /// reported to stderr rather than returned to the caller.
    pub fn log(&mut self, message: impl std::fmt::Display) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let line = format!("{timestamp} {message}\n");
        if self.console {
            print!("{line}");
        }
        if let Some(file) = &mut self.file {
            if let Err(error) = file.write_all(line.as_bytes()) {
                eprintln!("Unable to write BFD log: {error}");
            }
        }
    }
}

/// One validated session, its UDP sockets, and any configured BGP worker.
pub struct Engine {
    options: Options,
    session: Session,
    transport: Transport,
    bgp: Option<Controller>,
}

impl Engine {
    /// Validate and normalize options, open sockets, and start optional BGP control.
    /// This does not wait for BFD establishment or the background BGP status query.
    ///
    /// # Errors
    /// Returns configuration/authentication mismatch, socket, log, or worker startup errors.
    pub fn open(mut options: Options, auth: AuthConfig, log: &mut Logger) -> io::Result<Self> {
        options
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let session = Session::new(options.clone(), auth)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let transport = Transport::open(&options)?;
        let bgp = Controller::open(&options)?;
        if let Some(peer) = &options.bgp_peer_name {
            log.log(format!(
                "BGP MI control enabled: peer={peer:?} routing_domain={:?}",
                options.bgp_routing_domain
            ));
        }
        log.log(format!(
            "BFD {:?}: local={} peer={} control_port={} source_port={} discriminator={} state=Down",
            options.mode,
            options.local,
            options.peer,
            options.mode.port(),
            transport.source_port,
            session.local_discriminator
        ));
        Ok(Self {
            options,
            session,
            transport,
            bgp,
        })
    }
    fn state_changed(&self, previous: State, log: &mut Logger) {
        log.log(format!(
            "peer={} state={:?} diagnostic={:?} remote_discriminator={} tx_us={} detection_us={}",
            self.options.peer,
            self.session.state,
            self.session.diagnostic,
            self.session.remote_discriminator,
            self.session.transmit_interval().as_micros(),
            self.session.detection_time().as_micros()
        ));
        log.session_event(
            SessionEvent::StateChanged,
            &self.options,
            &self.session,
            previous,
            self.session.remote_discriminator,
        );
        if let Some(bgp) = &self.bgp {
            bgp.state_changed(previous, self.session.state);
        }
    }
    fn peer_communication_changed(
        &self,
        communicating: bool,
        previous: State,
        remote_discriminator: u32,
        log: &mut Logger,
    ) {
        log.log(format_args!(
            "peer={} communication={} remote_discriminator={remote_discriminator}",
            self.options.peer,
            if communicating { "started" } else { "stopped" },
        ));
        log.session_event(
            if communicating {
                SessionEvent::CommunicationStarted
            } else {
                SessionEvent::CommunicationStopped
            },
            &self.options,
            &self.session,
            previous,
            remote_discriminator,
        );
    }
    fn transmit(&mut self, final_bit: bool, log: &mut Logger, last_error: &mut Option<Instant>) {
        if let Err(error) = self.transport.send(&self.session.packet(final_bit)) {
            let now = Instant::now();
            if last_error.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)) {
                log.log(format!("send to {} failed: {error}", self.options.peer));
                *last_error = Some(now);
            }
        }
    }
    /// Run until a stop message/channel disconnect or fatal receive/wait error.
    ///
    /// On exit, set AdminDown, attempt one role-permitted shutdown packet, and
    /// wait for BGP cleanup. Send failures are logged, not returned. The BGP
    /// controller is consumed during cleanup; construct a new engine to restart.
    ///
    /// # Errors
    /// Returns fatal receive/wait errors or BGP cleanup failures. If both fail,
    /// the receive/wait error takes precedence.
    pub fn run(&mut self, stop: &Receiver<()>, log: &mut Logger) -> io::Result<()> {
        let result = self.run_session(stop, log);
        let previous = self.session.state;
        self.session.admin_down();
        self.state_changed(previous, log);
        // Queue BGP Stop also after fatal transport errors. Attempt one AdminDown
        // packet; unlike RFC 5880 section 6.8.16's recommendation, shutdown does
        // not continue BFD transmission for a full Detection Time.
        if self.session.can_transmit() {
            self.transmit(false, log, &mut None);
        }
        // Wait for the pending Stop attempt and propagate failure before completion.
        let shutdown = self.bgp.take().map_or(Ok(()), Controller::shutdown);
        result.and(shutdown)
    }

    fn run_session(&mut self, stop: &Receiver<()>, log: &mut Logger) -> io::Result<()> {
        let mut next_periodic_tx = Instant::now();
        let mut last_periodic_tx = None;
        let mut last_error = None;
        let mut last_discard = None;
        let mut last_auth_failure = None;
        loop {
            match stop.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }
            let now = Instant::now();
            let previous = self.session.state;
            let remote_discriminator = self.session.remote_discriminator;
            let state_changed = self.session.expire(now);
            if remote_discriminator != 0 && self.session.remote_discriminator == 0 {
                self.peer_communication_changed(false, previous, remote_discriminator, log);
            }
            if state_changed {
                self.state_changed(previous, log);
                if self.session.periodic_enabled() {
                    self.transmit(false, log, &mut last_error);
                    last_periodic_tx = Some(now);
                    next_periodic_tx = now + self.session.jittered_interval();
                }
            }
            if self.session.periodic_enabled() && now >= next_periodic_tx {
                self.transmit(false, log, &mut last_error);
                last_periodic_tx = Some(now);
                next_periodic_tx = now + self.session.jittered_interval();
            }
            let before_interval = self.session.transmit_interval();
            let before_enabled = self.session.periodic_enabled();
            match self.transport.receive() {
                Ok(datagram) => {
                    let received_at = Instant::now();
                    let previous = self.session.state;
                    let remote_discriminator = self.session.remote_discriminator;
                    let received = datagram
                        .validate(&self.options)
                        .map_err(ReceiveError::Packet)
                        .and_then(|()| self.session.receive_checked(&datagram.data, received_at));
                    match received {
                        Ok(result) => {
                            if remote_discriminator == 0 {
                                self.peer_communication_changed(
                                    true,
                                    previous,
                                    self.session.remote_discriminator,
                                    log,
                                );
                            }
                            if result.state_changed {
                                self.state_changed(previous, log);
                            }
                            if result.reply_final {
                                // Final replies are independent of periodic traffic (RFC 5880
                                // section 6.5); they must not postpone our own Poll sequence.
                                self.transmit(true, log, &mut last_error);
                            }
                            if !result.reply_final
                                && result.state_changed
                                && self.session.periodic_enabled()
                            {
                                self.transmit(false, log, &mut last_error);
                                last_periodic_tx = Some(received_at);
                                next_periodic_tx = received_at + self.session.jittered_interval();
                            } else if !before_enabled && self.session.periodic_enabled() {
                                next_periodic_tx = received_at;
                            } else if before_interval != self.session.transmit_interval() {
                                // Honor peer interval changes relative to the previous transmission
                                // (RFC 5880 section 6.8.3), rather than delaying from this receipt.
                                next_periodic_tx = last_periodic_tx.unwrap_or(received_at)
                                    + self.session.jittered_interval();
                            }
                        }
                        Err(ReceiveError::Authentication(reason)) => {
                            if log_due(&mut last_auth_failure, received_at) {
                                log.log(format_args!(
                                    "authentication failed for packet from {}: {reason}",
                                    datagram.source,
                                ));
                                log.event(|provider, _| {
                                    provider.authentication_failed(
                                        &self.options,
                                        &self.session,
                                        datagram.source,
                                        reason,
                                    )
                                });
                            }
                        }
                        Err(ReceiveError::Packet(reason)) if self.options.verbose => {
                            if log_due(&mut last_discard, received_at) {
                                log.log(format!(
                                    "discarded packet from {}: {reason}",
                                    datagram.source
                                ));
                            }
                        }
                        Err(_) => {}
                    }
                    // One datagram per pass so floods cannot starve timers or Stop.
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidData
                        || error.raw_os_error() == Some(10040) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            let mut wait = Duration::from_millis(10);
            if self.session.periodic_enabled() {
                wait = wait.min(next_periodic_tx.saturating_duration_since(now));
            }
            if let Some(deadline) = self.session.detection_deadline() {
                wait = wait.min(deadline.saturating_duration_since(now));
            }
            self.transport.wait_readable(wait)?;
        }
        Ok(())
    }
}

fn log_due(last: &mut Option<Instant>, now: Instant) -> bool {
    if last.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)) {
        *last = Some(now);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(miri))]
    #[test]
    fn console_events_are_written_to_stdout_without_etw() {
        const CHILD: &str = "BFD_TEST_CONSOLE_LOG_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut log = Logger::new(true);
            assert!(log.event_log.is_none());
            log.service_started();
            log.service_failed("registry value Local is required");
            log.service_stopped(1);
            return;
        }

        // A subprocess provides real STDOUT/STDERR handles without libtest's
        // in-process capture or changes to the installed service's registry.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::console_events_are_written_to_stdout_without_etw",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for message in [
            "service started mode=console",
            "service failed: registry value Local is required",
            "service stopped exit_code=1",
        ] {
            assert!(stdout.contains(message), "{stdout}");
        }
    }

    #[test]
    fn authentication_warnings_are_limited_to_once_per_second() {
        let now = Instant::now();
        let mut last = None;
        assert!(log_due(&mut last, now));
        for millis in [0, 1, 500, 999] {
            assert!(!log_due(&mut last, now + Duration::from_millis(millis)));
        }
        assert!(log_due(&mut last, now + Duration::from_secs(1)));
        assert!(!log_due(&mut last, now + Duration::from_millis(1999)));
        assert!(log_due(&mut last, now + Duration::from_secs(2)));
    }
}
