//! Windows BFD packet/timer loop, logging, and optional background BGP control.
use crate::{
    bgp::Controller,
    config::{load_sbfd_settings, Options, SessionType, Timing, ValidatedOptions},
    error::ConfigError,
    event_log::SessionEvent,
    packet::{AuthConfig, Diagnostic, State},
    seamless::Reflector,
    session::{ReceiveError, Session},
    transport::{Datagram, Transport},
};
use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::SYSTEMTIME, System::SystemInformation::GetSystemTime};

mod logging;
pub use logging::Logger;

/// Read the Windows UTC clock without applying the local timezone.
#[allow(unsafe_code)] // GetSystemTime is the sole FFI operation in this module.
fn utc_timestamp() -> String {
    let mut time = SYSTEMTIME::default();
    // SAFETY: time is a valid, writable SYSTEMTIME that remains alive throughout
    // the synchronous call. GetSystemTime initializes its fields with UTC values.
    unsafe { GetSystemTime(&mut time) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds,
    )
}

/// One validated session, its UDP sockets, and any configured BGP worker.
pub struct Engine {
    options: ValidatedOptions,
    timing: Timing,
    sbfd_admin_down: bool,
    session: Session,
    transport: Transport,
    bgp: Option<Controller>,
    reflector: Option<Reflector>,
}

impl Engine {
    /// Validate and normalize options, open sockets, and start optional BGP control.
    /// This does not wait for BFD establishment or the background BGP status query.
    ///
    /// # Errors
    /// Returns configuration/authentication mismatch or socket errors. When BGP
    /// control is configured, also returns worker thread startup errors.
    pub fn open(options: Options, auth: AuthConfig, log: &mut Logger) -> io::Result<Self> {
        let options = options
            .into_validated()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if options.authentication() != &auth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                ConfigError::AuthenticationMismatch,
            ));
        }
        Self::from_config(options, log)
    }

    /// Opens an engine from a validated startup snapshot without repeating validation.
    ///
    /// # Errors
    /// Returns socket or BGP worker startup errors.
    pub fn from_config(options: ValidatedOptions, log: &mut Logger) -> io::Result<Self> {
        let reflector = if options.session_type == SessionType::SbfdReflector {
            Some(
                Reflector::from_config(&options)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            )
        } else {
            None
        };
        let session = Session::from_config(options.clone());
        let transport = Transport::from_config(&options)?;
        let bgp = Controller::open(&options, log)?;
        if let Some(peer) = &options.bgp_peer_name {
            log.log(format!(
                "BGP MI control enabled: peer={peer:?} routing_domain={:?}",
                options.bgp_routing_domain
            ));
        }
        log.log(format!(
            "BFD {:?} {:?}: local={} peer={} control_port={} source_port={} discriminator={} state={:?}",
            options.session_type, options.mode,
            options.local,
            options.peer,
            options.control_port(),
            transport.source_port,
            session.local_discriminator, session.state()
        ));
        Ok(Self {
            timing: options.timing(),
            sbfd_admin_down: options.sbfd_admin_down,
            options,
            session,
            transport,
            bgp,
            reflector,
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
    fn transmit(&mut self, kind: Transmission, log: &mut Logger, last_error: &mut Option<Instant>) {
        let packet = match kind {
            Transmission::Periodic => self.session.packet(false),
            Transmission::Final => self.session.packet(true),
            Transmission::StateChange => self.session.state_change_packet(),
        };
        if let Err(error) = self.transport.send(&packet) {
            let now = Instant::now();
            if last_error.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)) {
                log.log(format!("send to {} failed: {error}", self.options.peer));
                *last_error = Some(now);
            }
        }
    }

    /// Applies live S-BFD timers without resetting protocol state.
    ///
    /// # Errors
    /// Rejects classical sessions, which use startup-only local settings.
    pub fn set_timing(&mut self, timing: Timing) -> io::Result<()> {
        self.session
            .set_timing(timing)
            .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;
        if let Some(reflector) = &mut self.reflector {
            reflector.set_timing(timing);
        }
        self.timing = timing;
        Ok(())
    }

    fn reload_sbfd_settings(&mut self, log: &mut Logger) {
        if !self.options.registry_backed || self.options.session_type == SessionType::Classical {
            return;
        }
        let result = load_sbfd_settings(&self.options).and_then(|(timing, admin_down)| {
            if self.timing != timing {
                self.set_timing(timing)?;
                log.log("S-BFD timing settings reloaded");
            }
            if let Some(reflector) = &mut self.reflector {
                if self.sbfd_admin_down != admin_down {
                    reflector.set_admin_down(admin_down);
                    self.sbfd_admin_down = admin_down;
                    self.session.state = reflector.state();
                    self.session.diagnostic = if admin_down {
                        Diagnostic::AdminDown
                    } else {
                        Diagnostic::None
                    };
                    log.log(format_args!(
                        "S-BFD reflector entity state={:?}",
                        reflector.state()
                    ));
                }
            }
            Ok(())
        });
        if let Err(error) = result {
            log.log(format_args!("S-BFD settings reload rejected: {error}"));
        }
    }

    fn log_rejection(
        &self,
        datagram: &Datagram,
        error: ReceiveError,
        log: &mut Logger,
        last_discard: &mut Option<Instant>,
        last_auth_failure: &mut Option<Instant>,
    ) {
        let now = Instant::now();
        match error {
            ReceiveError::Authentication(reason) if log_due(last_auth_failure, now) => {
                log.log(format_args!(
                    "authentication failed for packet from {}: {reason}",
                    datagram.source
                ));
                log.authentication_failed(&self.options, &self.session, datagram.source, reason);
            }
            ReceiveError::Packet(reason) if self.options.verbose && log_due(last_discard, now) => {
                log.log(format_args!(
                    "discarded packet from {}: {reason}",
                    datagram.source
                ));
            }
            _ => {}
        }
    }

    fn run_reflector(&mut self, stop: &Receiver<()>, log: &mut Logger) -> io::Result<()> {
        let mut next_registry_read = Instant::now() + Duration::from_secs(1);
        let mut last_error = None;
        let mut last_discard = None;
        let mut last_auth_failure = None;
        loop {
            match stop.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) => {}
            }
            let now = Instant::now();
            if now >= next_registry_read {
                self.reload_sbfd_settings(log);
                next_registry_read = now + Duration::from_secs(1);
            }
            match self.transport.receive() {
                Ok(datagram) => {
                    let reply = datagram
                        .validate(&self.options)
                        .map_err(ReceiveError::Packet)
                        .and_then(|()| {
                            self.reflector
                                .as_ref()
                                .expect("reflector runtime selected")
                                .respond_checked(&datagram.data)
                        });
                    match reply {
                        Ok(reply) => {
                            if let Err(error) =
                                self.transport.send_reply(&reply, &datagram, &self.options)
                            {
                                if log_due(&mut last_error, now) {
                                    log.log(format_args!(
                                        "S-BFD reply to {} failed: {error}",
                                        datagram.source
                                    ));
                                }
                            }
                        }
                        Err(error) => self.log_rejection(
                            &datagram,
                            error,
                            log,
                            &mut last_discard,
                            &mut last_auth_failure,
                        ),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.transport.wait_readable(Duration::from_millis(10))?;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidData
                        || error.raw_os_error() == Some(10040) => {}
                Err(error) => return Err(error),
            }
            // One request per pass keeps Stop and settings reload responsive under load.
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
        let result = if self.reflector.is_some() {
            self.run_reflector(stop, log)
        } else {
            self.run_session(stop, log)
        };
        let previous = self.session.state;
        self.session.admin_down();
        if self.reflector.is_none() {
            self.state_changed(previous, log);
        }
        // Queue BGP Stop also after fatal transport errors. Attempt one AdminDown
        // packet; unlike RFC 5880 section 6.8.16's recommendation, shutdown does
        // not continue BFD transmission for a full Detection Time.
        if self.session.can_transmit() {
            self.transmit(Transmission::Periodic, log, &mut None);
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
        let mut next_registry_read = Instant::now() + Duration::from_secs(1);
        loop {
            match stop.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }
            let now = Instant::now();
            let previous = self.session.state;
            let remote_discriminator = self.session.remote_discriminator;
            let communicating = self.session.communicating();
            let old_interval = self.session.transmit_interval();
            if now >= next_registry_read {
                self.reload_sbfd_settings(log);
                next_registry_read = now + Duration::from_secs(1);
            }
            let state_changed = self.session.expire(now);
            if communicating && !self.session.communicating() {
                self.peer_communication_changed(false, previous, remote_discriminator, log);
            }
            if state_changed {
                self.state_changed(previous, log);
                if self.options.session_type == SessionType::Classical
                    && self.session.can_transmit()
                {
                    self.transmit(Transmission::StateChange, log, &mut last_error);
                    last_periodic_tx = Some(now);
                    next_periodic_tx = now + self.session.jittered_interval();
                }
            }
            if old_interval != self.session.transmit_interval() {
                next_periodic_tx =
                    last_periodic_tx.unwrap_or(now) + self.session.jittered_interval();
            }
            if self.session.periodic_enabled() && now >= next_periodic_tx {
                self.transmit(Transmission::Periodic, log, &mut last_error);
                last_periodic_tx = Some(now);
                next_periodic_tx = now + self.session.jittered_interval();
            }
            let before_interval = self.session.transmit_interval();
            let before_enabled = self.session.periodic_enabled();
            match self.transport.receive() {
                Ok(datagram) => {
                    let received_at = Instant::now();
                    let previous = self.session.state;
                    let communicating = self.session.communicating();
                    let received = datagram
                        .validate(&self.options)
                        .map_err(ReceiveError::Packet)
                        .and_then(|()| self.session.receive_checked(&datagram.data, received_at));
                    match received {
                        Ok(result) => {
                            if !communicating && self.session.communicating() {
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
                                self.transmit(Transmission::Final, log, &mut last_error);
                            }
                            if !result.reply_final
                                && result.state_changed
                                && self.options.session_type == SessionType::Classical
                                && self.session.can_transmit()
                            {
                                // State notifications are independent of periodic suppression.
                                // Keep Poll clear here (RFC 5880 sections 6.5 and 6.8.7).
                                self.transmit(Transmission::StateChange, log, &mut last_error);
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
                            // AdminDown must also lengthen an already scheduled
                            // jittered retry when the negotiated interval is unchanged.
                            if self.options.session_type == SessionType::SbfdInitiator {
                                next_periodic_tx = next_periodic_tx.max(
                                    last_periodic_tx.unwrap_or(received_at)
                                        + self.session.minimum_transmit_interval(),
                                );
                            }
                        }
                        Err(error) => self.log_rejection(
                            &datagram,
                            error,
                            log,
                            &mut last_discard,
                            &mut last_auth_failure,
                        ),
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

#[derive(Clone, Copy)]
enum Transmission {
    Periodic,
    Final,
    StateChange,
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
    use std::{fs, io::Write};

    #[cfg(not(miri))]
    #[test]
    fn unread_stdout_cannot_block_engine_shutdown() {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
            sync::mpsc,
            thread,
        };
        const CHILD: &str = "BFD_TEST_UNREAD_STDOUT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut options =
                Options::new("127.0.0.80".parse().unwrap(), "127.0.0.81".parse().unwrap());
            options.multihop = true;
            options.console = true;
            let auth = options.validate().unwrap();
            let mut log = Logger::open(&options).unwrap();
            let mut engine = Engine::open(options, auth, &mut log).unwrap();
            // Fill the pipe while retaining enough queue space for a flush barrier.
            for _ in 0..32 {
                log.log("X".repeat(16_384));
            }
            assert_eq!(
                log.flush(Duration::from_millis(50)).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            let message = "X".repeat(4096);
            for _ in 0..1024 {
                log.log(&message);
            }
            assert!(log.dropped_records() > 0, "queue growth must be bounded");
            let (stop, receiver) = mpsc::channel();
            drop(stop);
            engine.run(&receiver, &mut log).unwrap();
            drop(engine);
            drop(log);
            eprintln!("engine-stopped");
            std::process::exit(0);
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::unread_stdout_cannot_block_engine_shutdown",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sent, received) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut diagnostics = Vec::new();
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if line == "engine-stopped" {
                    let _ = sent.send(());
                }
                diagnostics.push(line);
            }
            diagnostics
        });
        let stopped = received.recv_timeout(Duration::from_secs(3)).is_ok();
        if !stopped {
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        let diagnostics = reader.join().unwrap();
        assert!(
            stopped,
            "logging prevented engine shutdown: {diagnostics:?}"
        );
        assert!(status.success(), "{status}");
    }

    #[cfg(not(miri))]
    #[test]
    fn file_logging_creates_missing_parent_directories_and_appends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("missing")
            .join("nested")
            .join("trace.log");
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.console = true;
        options.log_file_path = path.clone();
        options.log_to_file = true;

        for message in ["first message", "second message"] {
            let mut log = Logger::open(&options).unwrap();
            log.log(message);
        }

        let contents = std::fs::read_to_string(path).unwrap();
        let messages: Vec<_> = contents
            .lines()
            .map(|line| line.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(messages, ["first message", "second message"]);
    }

    #[cfg(not(miri))]
    #[test]
    fn every_file_log_line_has_an_iso8601_utc_timestamp() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.log");
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.console = true;
        options.log_to_file = true;
        options.log_file_path = path.clone();
        let mut log = Logger::open(&options).unwrap();
        log.log("first line\n\nthird line\r\nfourth line");
        log.log("");
        drop(log);

        let contents = fs::read_to_string(path).unwrap();
        let mut messages = Vec::new();
        for line in contents.lines() {
            let (timestamp, message) = line.split_once(' ').unwrap();
            assert_eq!(timestamp.len(), 24, "{timestamp}");
            for (index, byte) in timestamp.bytes().enumerate() {
                match index {
                    4 | 7 => assert_eq!(byte, b'-'),
                    10 => assert_eq!(byte, b'T'),
                    13 | 16 => assert_eq!(byte, b':'),
                    19 => assert_eq!(byte, b'.'),
                    23 => assert_eq!(byte, b'Z'),
                    _ => assert!(byte.is_ascii_digit(), "{timestamp}"),
                }
            }
            messages.push(message);
        }
        assert_eq!(
            messages,
            ["first line", "", "third line", "fourth line", ""]
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn disabled_file_logging_leaves_paths_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing.log");
        fs::write(&existing, b"existing contents").unwrap();
        let missing_parent = directory.path().join("missing");
        let missing = missing_parent.join("trace.log");
        // A file in place of a parent directory would fail if opened or created.
        let blocked = existing.join("trace.log");
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.console = true;
        assert!(!options.log_to_file);

        for path in [&existing, &missing, &blocked] {
            options.log_file_path = path.clone();
            let mut log = Logger::open(&options).unwrap();
            log.service_started();
            log.service_failed("file output is disabled");
            log.service_stopped(0);
        }

        assert_eq!(fs::read(existing).unwrap(), b"existing contents");
        assert!(!missing_parent.exists());
        assert!(!blocked.exists());
    }

    #[cfg(not(miri))]
    #[test]
    fn enabled_file_logging_reports_parent_directory_errors() {
        let directory = tempfile::tempdir().unwrap();
        let blocked = directory.path().join("file");
        fs::write(&blocked, b"existing contents").unwrap();
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.console = true;
        options.log_to_file = true;
        options.log_file_path = blocked.join("trace.log");

        assert!(Logger::open(&options).is_err());
        assert_eq!(fs::read(blocked).unwrap(), b"existing contents");
    }

    #[cfg(not(miri))]
    #[test]
    fn closed_stdout_does_not_interrupt_engine_shutdown_or_file_logging() {
        use std::{
            io::{BufRead, BufReader, Read},
            process::{Command, Stdio},
            sync::mpsc,
        };

        const CHILD: &str = "BFD_TEST_CLOSED_STDOUT_CHILD";
        const LOG_PATH: &str = "BFD_TEST_CLOSED_STDOUT_LOG";
        if std::env::var_os(CHILD).is_some() {
            let mut options =
                Options::new("127.0.0.70".parse().unwrap(), "127.0.0.71".parse().unwrap());
            options.multihop = true;
            options.console = true;
            options.log_file_path = std::env::var_os(LOG_PATH).unwrap().into();
            options.log_to_file = true;
            let auth = options.validate().unwrap();
            let mut log = Logger::open(&options).unwrap();
            let mut engine = Engine::open(options, auth, &mut log).unwrap();
            log.service_started();
            // Wait until the parent closes the pipe reader. This runs in a
            // subprocess so native STDOUT changes cannot affect other tests.
            eprintln!("ready");
            io::stdin().read_exact(&mut [0]).unwrap();
            let (stop, receiver) = mpsc::channel();
            drop(stop);
            engine.run(&receiver, &mut log).unwrap();
            log.service_failed("synthetic failure after STDOUT closed");
            log.service_stopped(0);
            assert!(log.console);
            drop(engine);
            drop(log);
            // Libtest's own completion output also uses STDOUT; avoid it after
            // verifying the application completed with the pipe reader closed.
            std::process::exit(0);
        }

        // Also cover redirected STDERR sharing an unavailable output sink.
        for close_stderr in [false, true] {
            let log = tempfile::NamedTempFile::new().unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::closed_stdout_does_not_interrupt_engine_shutdown_or_file_logging",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(LOG_PATH, log.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
            let mut stderr = BufReader::new(child.stderr.take().unwrap());
            let mut ready = String::new();
            stderr.read_line(&mut ready).unwrap();
            drop(child.stdout.take());
            let mut stderr = (!close_stderr).then_some(stderr);
            // Dropping the temporary stdin writer also wakes the child on failure.
            child.stdin.take().unwrap().write_all(&[1]).unwrap();
            let mut diagnostic = String::new();
            if let Some(stderr) = &mut stderr {
                stderr.read_to_string(&mut diagnostic).unwrap();
            }
            let status = child.wait().unwrap();
            assert_eq!(ready.trim(), "ready");
            assert!(status.success(), "{status}: {diagnostic}");
            if !close_stderr {
                assert_eq!(diagnostic.lines().count(), 1, "{diagnostic}");
                assert!(diagnostic.contains("unable to write BFD console log"));
            }
            let contents = std::fs::read_to_string(log.path()).unwrap();
            for message in [
                "state=AdminDown",
                "synthetic failure after STDOUT closed",
                "service stopped exit_code=0",
            ] {
                assert!(contents.contains(message), "{contents}");
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn console_events_are_written_to_stdout_without_etw() {
        const CHILD: &str = "BFD_TEST_CONSOLE_LOG_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut log = Logger::new(true).unwrap();
            assert!(log.console);
            log.service_started();
            log.service_failed("registry value Local is required");
            log.service_stopped(1);
            return;
        }

        // A subprocess provides real STDOUT/STDERR handles without libtest's
        // in-process capture or changes to the installed service's registry.
        let output = assert_cmd::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::tests::console_events_are_written_to_stdout_without_etw",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .assert()
            .success()
            .get_output()
            .clone();
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
