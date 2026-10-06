//! Windows BFD packet/timer loop, logging, and optional background BGP control.
use crate::{
    bgp::Controller,
    config::Options,
    packet::{AuthConfig, State},
    session::Session,
    transport::Transport,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Append-only file logging and optional console stderr output.
pub struct Logger {
    file: Option<File>,
    console: bool,
}

impl Logger {
    /// Open/create the configured append log; console output follows options.console.
    ///
    /// # Errors
    /// Returns an error if the configured file cannot be opened.
    pub fn open(options: &Options) -> io::Result<Self> {
        Ok(Self {
            file: options
                .log_file
                .as_ref()
                .map(|path| OpenOptions::new().create(true).append(true).open(path))
                .transpose()?,
            console: options.console,
        })
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
            eprint!("{line}");
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
        if let Some(bgp) = &self.bgp {
            bgp.state_changed(previous, self.session.state);
        }
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
        loop {
            match stop.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }
            let now = Instant::now();
            let previous = self.session.state;
            if self.session.expire(now) {
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
                    let received = datagram
                        .validate(&self.options)
                        .and_then(|()| self.session.receive(&datagram.data, received_at));
                    match received {
                        Ok(result) => {
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
                        Err(reason) if self.options.verbose => {
                            if last_discard.is_none_or(|last| {
                                received_at.duration_since(last) >= Duration::from_secs(1)
                            }) {
                                log.log(format!(
                                    "discarded packet from {}: {reason}",
                                    datagram.source
                                ));
                                last_discard = Some(received_at);
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
