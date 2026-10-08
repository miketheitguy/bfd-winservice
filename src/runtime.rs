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
    fmt::Display,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{Foundation::SYSTEMTIME, System::SystemInformation::GetSystemTime};

/// Operational ETW events in service mode, STDOUT in console mode, and an
/// optional append-only file log in either mode.
pub struct Logger {
    file: Option<File>,
    console: bool,
    stdout_failed: bool,
    event_log: Option<Provider>,
}

impl Logger {
    /// Create a startup logger before registry settings are loaded, so a
    /// configuration failure is visible in the service log or on STDOUT.
    pub fn new(console: bool) -> Self {
        let mut log = Self {
            file: None,
            console,
            stdout_failed: false,
            event_log: None,
        };
        if !console {
            match Provider::register() {
                Ok(provider) => log.event_log = Some(provider),
                // Registry settings and the optional file log are not open
                // yet; use stderr so this failure has a fallback destination.
                Err(error) => {
                    let _ = writeln!(
                        io::stderr().lock(),
                        "unable to register BFD-Service ETW provider: {error}"
                    );
                }
            }
        }
        log
    }

    /// Open/create the append log and select Operational ETW or console STDOUT.
    ///
    /// # Errors
    /// Returns an error if enabled file logging cannot create its parent
    /// directories or open the configured file.
    pub fn open(options: &Options) -> io::Result<Self> {
        let mut log = Self::new(options.console);
        log.open_file(options)?;
        Ok(log)
    }

    /// Configure the append log after loading registry settings. Disabled file
    /// logging never opens, creates, or writes the configured path. When enabled,
    /// missing parent directories are created before opening the file.
    ///
    /// # Errors
    /// Returns an error if enabled file logging cannot create its parent
    /// directories or open the configured file.
    pub fn open_file(&mut self, options: &Options) -> io::Result<()> {
        self.file = if options.log_to_file {
            if let Some(parent) = options
                .log_file_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)?;
            }
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&options.log_file_path)?,
            )
        } else {
            None
        };
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
    pub fn service_failed(&mut self, error: impl Display) {
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
    /// Write a timestamped message. Every file line starts with an ISO-8601 UTC
    /// timestamp with milliseconds and a trailing Z; STDOUT uses Unix milliseconds.
    /// Multiline file entries share the timestamp sampled immediately before writing.
    /// Output errors are
    /// reported to stderr on a best-effort basis rather than returned or panicked.
    /// A failed STDOUT write disables further console writes for this logger;
    /// file logging, ETW mode selection, and engine execution continue.
    ///
    /// # Examples
    /// ```no_run
    /// use bfd_winservice::runtime::Logger;
    ///
    /// let mut log = Logger::new(true);
    /// log.log("BFD initialization started");
    /// ```
    pub fn log(&mut self, message: impl Display) {
        let message = message.to_string();
        if self.console && !self.stdout_failed {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let line = format!("{timestamp} {message}\n");
            if let Err(error) = io::stdout().lock().write_all(line.as_bytes()) {
                self.stdout_failed = true;
                // Diagnostics must not panic if STDERR is also unavailable.
                let _ = writeln!(
                    io::stderr().lock(),
                    "unable to write BFD console log: {error}"
                );
            }
        }
        if let Some(file) = &mut self.file {
            let timestamp = utc_timestamp();
            let message = message.replace('\n', &format!("\n{timestamp} "));
            let line = format!("{timestamp} {message}\n");
            if let Err(error) = file.write_all(line.as_bytes()) {
                let _ = writeln!(io::stderr().lock(), "unable to write BFD file log: {error}");
            }
        }
    }
}

/// Read the Windows UTC clock without applying the local timezone.
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
    /// Returns configuration/authentication mismatch or socket errors. When BGP
    /// control is configured, also returns worker file-log or thread startup errors.
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
            assert!(log.console && log.event_log.is_none());
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
            let mut log = Logger::new(true);
            assert!(log.event_log.is_none());
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
