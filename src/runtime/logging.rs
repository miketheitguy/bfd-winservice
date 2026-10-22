//! Bounded output worker shared by the engine and BGP controller.
use super::utc_timestamp;
use crate::{
    config::Options,
    error::AuthError,
    event_log::{Origin, Provider, Record, SessionEvent},
    packet::State,
    session::Session,
};
use std::{
    fmt::{self, Display, Write as _},
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const QUEUE_CAPACITY: usize = 256;
const MAX_TEXT_BYTES: usize = 16_384;
const SHUTDOWN_WAIT: Duration = Duration::from_millis(500);
const FILE_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
/// A full file is renamed to `<name>.1`, so file output uses at most twice this.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const ROTATION_RETRY_INTERVAL: Duration = Duration::from_secs(30);

enum Command {
    Text(String),
    Event(Record),
    File(Option<(File, PathBuf)>),
    Flush(mpsc::Sender<io::Result<()>>),
}

/// The enabled append file and its size-based rotation state.
struct OutputFile {
    writer: BufWriter<File>,
    path: PathBuf,
    /// File length, including buffered output, since opening or rotation.
    length: u64,
    limit: u64,
    retry_rotation_at: Option<Instant>,
    /// A successful rename followed by a failed reopen leaves the writer on .1.
    renamed: bool,
}

impl OutputFile {
    fn new(file: File, path: PathBuf, limit: u64) -> Self {
        // An unknown length must force rotation instead of granting write space.
        let length = file.metadata().map_or(limit, |metadata| metadata.len());
        Self {
            writer: BufWriter::new(file),
            path,
            length,
            limit,
            retry_rotation_at: None,
            renamed: false,
        }
    }

    /// Reserve room for a complete line before writing it. Failed rotation never
    /// permits growth beyond the ceiling, nor appending to a renamed backup.
    fn prepare_line(&mut self, bytes: u64) -> bool {
        if bytes > self.limit {
            return false;
        }
        if !self.renamed && self.length <= self.limit - bytes {
            return true;
        }
        let now = Instant::now();
        if self.retry_rotation_at.is_some_and(|retry| now < retry) {
            return false;
        }
        self.rotate_with(|path| OpenOptions::new().create_new(true).append(true).open(path))
            .is_ok()
            && self.length <= self.limit - bytes
    }

    fn rotate_with(&mut self, open: impl FnOnce(&Path) -> io::Result<File>) -> io::Result<()> {
        let result = (|| {
            self.writer.flush()?;
            if !self.renamed {
                let mut backup = self.path.clone().into_os_string();
                backup.push(".1");
                // The writer permits renaming; another reader may deny it.
                fs::rename(&self.path, &backup)?;
                self.renamed = true;
            }
            let file = open(&self.path)?;
            // Replacing the flushed writer closes the renamed file.
            self.length = file.metadata()?.len();
            self.writer = BufWriter::new(file);
            self.renamed = false;
            Ok(())
        })();
        match &result {
            Ok(()) => self.retry_rotation_at = None,
            Err(error) => {
                diagnostic(format_args!(
                    "unable to rotate BFD file log; file output paused: {error}"
                ));
                self.retry_rotation_at = Some(Instant::now() + ROTATION_RETRY_INTERVAL);
            }
        }
        result
    }
}

struct Shutdown {
    done: Receiver<()>,
    thread: JoinHandle<()>,
}
struct Worker {
    sender: Option<SyncSender<Command>>,
    shutdown: Mutex<Shutdown>,
    dropped: Arc<AtomicU64>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Disconnect first so a healthy worker drains all remaining records.
        self.sender.take();
        let shutdown = self
            .shutdown
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        if !shutdown.thread.is_finished() {
            let _ = shutdown.done.recv_timeout(SHUTDOWN_WAIT);
        }
    }
}

/// Nonblocking logging through a bounded worker queue.
/// Clones share one writer, ETW registration, queue, and dropped-record count.
/// Healthy output drains on final drop; blocked output gets at most 500 ms.
#[derive(Clone)]
pub struct Logger {
    worker: Arc<Worker>,
}

impl Logger {
    /// Starts the output worker before registry loading.
    ///
    /// # Errors
    /// Returns a thread creation error. ETW registration failures are diagnostic only.
    pub fn new() -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (done_tx, done) = mpsc::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let thread = thread::Builder::new()
            .name("bfd-log".into())
            .spawn(move || {
                write_records(receiver, &worker_dropped);
                let _ = done_tx.send(());
            })?;
        Ok(Self {
            worker: Arc::new(Worker {
                sender: Some(sender),
                shutdown: Mutex::new(Shutdown { done, thread }),
                dropped,
            }),
        })
    }

    /// Starts the output worker and opens the configured append file if enabled.
    ///
    /// # Errors
    /// Returns thread creation, directory creation, file opening, or queue errors.
    pub fn open(options: &Options) -> io::Result<Self> {
        let mut logger = Self::new()?;
        logger.open_file(options)?;
        Ok(logger)
    }

    /// Opens the append file during startup; disabled logging leaves the path untouched.
    ///
    /// # Errors
    /// Returns directory/file errors or WouldBlock if the configuration queue is full.
    pub fn open_file(&mut self, options: &Options) -> io::Result<()> {
        let file = if options.log_to_file {
            if let Some(parent) = options
                .log_file_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)?;
            }
            Some((
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&options.log_file_path)?,
                options.log_file_path.clone(),
            ))
        } else {
            None
        };
        self.send_control(Command::File(file))
    }

    /// Waits for preceding records and flushes the file, within the supplied deadline.
    /// The packet loop doesn't call this method; service cleanup flushes explicitly.
    ///
    /// # Errors
    /// Returns WouldBlock for a full queue, TimedOut for blocked output, BrokenPipe
    /// if the worker stopped, or a file flush error.
    pub fn flush(&self, timeout: Duration) -> io::Result<()> {
        let (sender, receiver) = mpsc::channel();
        self.send_control(Command::Flush(sender))?;
        receiver.recv_timeout(timeout).map_err(|error| {
            io::Error::new(
                if error == mpsc::RecvTimeoutError::Timeout {
                    io::ErrorKind::TimedOut
                } else {
                    io::ErrorKind::BrokenPipe
                },
                "logging flush did not complete",
            )
        })?
    }

    /// Returns the number of records rejected because the worker queue was full or closed.
    pub fn dropped_records(&self) -> u64 {
        self.worker.dropped.load(Ordering::Relaxed)
    }

    fn send_control(&self, command: Command) -> io::Result<()> {
        self.worker
            .sender
            .as_ref()
            .expect("sender exists until final owner drops")
            .try_send(command)
            .map_err(|error| {
                io::Error::new(
                    match error {
                        TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                        TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe,
                    },
                    "logging worker cannot accept the request",
                )
            })
    }

    fn enqueue(&self, command: Command) {
        if self.send_control(command).is_err() {
            let _ = self
                .worker
                .dropped
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(count.saturating_add(1))
                });
        }
    }

    /// Queues a message without waiting for output. Messages are capped at 16 KiB
    /// on UTF-8 character boundaries. File lines use ISO-8601 UTC with a trailing Z.
    /// The service writes text only to the enabled file destination.
    ///
    /// ```no_run
    /// use bfd_winservice::runtime::Logger;
    /// let mut log = Logger::new()?;
    /// log.log("BFD initialization started");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn log(&mut self, message: impl Display) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{message}");
        self.enqueue(Command::Text(text.0));
    }
    pub(crate) fn broker_message(&mut self, message: impl Display, failure: bool) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{message}");
        self.enqueue(Command::Event(Record::broker_message(&text.0, failure)));
    }
    pub(crate) fn bgp_control_message(
        &mut self,
        peer: &str,
        method: &str,
        detail: impl Display,
        recovered: bool,
    ) {
        let mut detail_text = BoundedText(String::new());
        let _ = write!(&mut detail_text, "{detail}");
        let mut record = Record::bgp_control_message(peer, method, &detail_text.0, recovered);
        let mut text = BoundedText(String::new());
        let (id, level) = if recovered {
            (303, "Information")
        } else {
            (302, "Error")
        };
        let _ = write!(
            &mut text,
            "event_id={id} level={level} BGP control client peer={peer:?} method={method} {}",
            detail_text.0
        );
        record.text = Some(text.0);
        self.enqueue(Command::Event(record));
    }
    /// Queues successful engine startup.
    pub fn service_started(&mut self) {
        self.log("service started mode=service");
        self.enqueue(Command::Event(Record::service_started()));
    }
    /// Queues completed shutdown; zero indicates success.
    pub fn service_stopped(&mut self, exit_code: u32) {
        self.log(format_args!("service stopped exit_code={exit_code}"));
        self.enqueue(Command::Event(Record::service_stopped(exit_code)));
    }
    /// Queues a Warning event for a weak configuration or a recoverable runtime
    /// condition. Callers rate-limit repeated warnings; text omits key material.
    pub fn service_warning(&mut self, warning: impl Display) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{warning}");
        self.enqueue(Command::Event(Record::service_warning(&text.0)));
    }
    /// Queues a startup/runtime error without authentication data.
    pub fn service_failed(&mut self, error: impl Display) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{error}");
        self.log(format_args!("service failed: {}", text.0));
        self.enqueue(Command::Event(Record::service_failed(&text.0)));
    }
    pub(super) fn session_event(
        &mut self,
        event: SessionEvent,
        options: &Options,
        session: &Session,
        previous: State,
        remote_discriminator: u32,
    ) {
        match Record::session_event(event, options, session, previous, remote_discriminator) {
            Ok(record) => self.enqueue(Command::Event(record)),
            Err(error) => self.log(format_args!(
                "unable to prepare BFD-Service ETW event: {error}"
            )),
        }
    }
    pub(super) fn diagnostic_event(
        &mut self,
        options: &Options,
        session: &Session,
        origin: Origin,
        code: u8,
        previous: State,
    ) {
        match Record::diagnostic_event(options, session, origin, code, previous) {
            Ok(Some(record)) => self.enqueue(Command::Event(record)),
            Ok(None) => {}
            Err(error) => self.log(format_args!(
                "unable to prepare BFD-Service diagnostic event: {error}"
            )),
        }
    }
    pub(super) fn authentication_failed(
        &mut self,
        options: &Options,
        session: &Session,
        source: SocketAddr,
        reason: AuthError,
    ) {
        self.enqueue(Command::Event(Record::authentication_failed(
            options,
            session,
            source,
            &reason.to_string(),
        )));
    }
}

struct BoundedText(String);
impl fmt::Write for BoundedText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut length = text.len().min(MAX_TEXT_BYTES.saturating_sub(self.0.len()));
        while !text.is_char_boundary(length) {
            length -= 1;
        }
        self.0.push_str(&text[..length]);
        Ok(())
    }
}

fn diagnostic(message: impl Display) {
    let _ = writeln!(io::stderr().lock(), "{message}");
}

fn text_output(message: &str, file: &mut Option<OutputFile>, timestamp: &mut String) {
    if let Some(output) = file {
        utc_timestamp(timestamp);
        for line in message.split('\n') {
            // Timestamp, separator, text, and newline. Check before buffering so
            // even a reader blocking rename cannot make the file grow unbounded.
            let written = timestamp.len().saturating_add(line.len()).saturating_add(2);
            let written = u64::try_from(written).unwrap_or(u64::MAX);
            if !output.prepare_line(written) {
                continue;
            }
            if let Err(error) = writeln!(output.writer, "{timestamp} {line}") {
                diagnostic(format_args!("unable to write BFD file log: {error}"));
                // A partial write has an uncertain length. Require rotation
                // before any further append instead of undercounting its bytes.
                output.length = output.limit;
                break;
            }
            output.length = output.length.saturating_add(written);
        }
    }
}

fn flush_file(file: &mut BufWriter<File>) {
    if let Err(error) = file.flush() {
        diagnostic(format_args!("unable to flush BFD file log: {error}"));
    }
}

fn write_records(receiver: Receiver<Command>, dropped: &AtomicU64) {
    let provider = match Provider::register() {
        Ok(provider) => Some(provider),
        Err(error) => {
            diagnostic(format_args!(
                "unable to register BFD-Service ETW provider: {error}"
            ));
            None
        }
    };
    write_records_with(receiver, dropped, MAX_FILE_BYTES, |record| {
        provider
            .as_ref()
            .map_or(Ok(()), |provider| provider.emit(record))
    });
}

fn write_records_with(
    receiver: Receiver<Command>,
    dropped: &AtomicU64,
    file_limit: u64,
    mut emit: impl FnMut(&Record) -> io::Result<()>,
) {
    let mut file: Option<OutputFile> = None;
    let mut timestamp = String::with_capacity(24);
    let mut next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
    let mut reported = 0;
    loop {
        let pending = file
            .as_ref()
            .is_some_and(|output| !output.writer.buffer().is_empty());
        let command = if pending {
            receiver.recv_timeout(next_flush.saturating_duration_since(Instant::now()))
        } else {
            next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        };
        let command = match command {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(output) = &mut file {
                    flush_file(&mut output.writer);
                }
                next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let lost = dropped.load(Ordering::Relaxed);
        if lost != reported {
            text_output(
                &format!(
                    "logging dropped {} records because output could not keep up",
                    lost - reported
                ),
                &mut file,
                &mut timestamp,
            );
            reported = lost;
        }
        match command {
            Command::Text(text) => text_output(&text, &mut file, &mut timestamp),
            Command::Event(record) => {
                if let Err(error) = emit(&record) {
                    text_output(
                        &format!("unable to write BFD-Service ETW event: {error}"),
                        &mut file,
                        &mut timestamp,
                    );
                }
                if let Some(text) = &record.text {
                    text_output(text, &mut file, &mut timestamp);
                }
            }
            Command::File(next) => {
                if let Some(output) = &mut file {
                    flush_file(&mut output.writer);
                }
                file = next.map(|(next, path)| OutputFile::new(next, path, file_limit));
            }
            Command::Flush(reply) => {
                let _ = reply.send(file.as_mut().map_or(Ok(()), |output| output.writer.flush()));
            }
        }
        if Instant::now() >= next_flush {
            if let Some(output) = &mut file {
                flush_file(&mut output.writer);
            }
            next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
        }
    }
    if let Some(output) = &mut file {
        flush_file(&mut output.writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(miri))]
    #[test]
    fn blocked_etw_bounds_queue_flush_and_logger_shutdown() {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (done_tx, done) = mpsc::channel();
        let (entered_tx, entered) = mpsc::sync_channel(1);
        let (resume, resume_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished) = mpsc::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let thread = thread::spawn(move || {
            write_records_with(receiver, &worker_dropped, MAX_FILE_BYTES, |_| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                Ok(())
            });
            let _ = done_tx.send(());
            let _ = finished_tx.send(());
        });
        let mut log = Logger {
            worker: Arc::new(Worker {
                sender: Some(sender),
                shutdown: Mutex::new(Shutdown { done, thread }),
                dropped,
            }),
        };
        log.service_started();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            log.flush(Duration::from_millis(20)).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        for _ in 0..1024 {
            log.log("output remains blocked");
        }
        assert!(log.dropped_records() > 0);
        let started = Instant::now();
        drop(log);
        let elapsed = started.elapsed();
        resume.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[cfg(not(miri))]
    fn captured_logger(events: Arc<Mutex<Vec<(u16, u8)>>>, fail_etw: bool) -> Logger {
        captured_logger_with_limit(events, fail_etw, MAX_FILE_BYTES)
    }

    #[cfg(not(miri))]
    fn captured_logger_with_limit(
        events: Arc<Mutex<Vec<(u16, u8)>>>,
        fail_etw: bool,
        file_limit: u64,
    ) -> Logger {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (done_tx, done) = mpsc::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let thread = thread::spawn(move || {
            write_records_with(receiver, &worker_dropped, file_limit, |record| {
                events.lock().unwrap().push(record.identity());
                if fail_etw {
                    Err(io::Error::other("synthetic ETW failure"))
                } else {
                    Ok(())
                }
            });
            let _ = done_tx.send(());
        });
        Logger {
            worker: Arc::new(Worker {
                sender: Some(sender),
                shutdown: Mutex::new(Shutdown { done, thread }),
                dropped,
            }),
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn bgp_client_events_reach_etw_with_file_disabled_and_mirror_enabled_file() {
        for file_enabled in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let mut options =
                Options::new("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
            options.log_to_file = file_enabled;
            options.log_file_path = directory.path().join("output/trace.log");
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut log = captured_logger(Arc::clone(&events), false);
            log.open_file(&options).unwrap();
            log.bgp_control_message("Site 🐢", "Stop", "failed: RPC server unavailable", false);
            log.bgp_control_message(
                "Site 🐢",
                "Start",
                "RPC requests are succeeding again",
                true,
            );
            log.flush(Duration::from_secs(2)).unwrap();
            assert_eq!(*events.lock().unwrap(), [(302, 2), (303, 4)]);
            if file_enabled {
                let contents = fs::read_to_string(&options.log_file_path).unwrap();
                assert!(contents.contains("event_id=302 level=Error"));
                assert!(contents.contains("event_id=303 level=Information"));
                assert!(contents.contains("method=Stop failed: RPC server unavailable"));
                assert_eq!(contents.lines().count(), 2);
            } else {
                assert!(!options.log_file_path.parent().unwrap().exists());
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn state_and_diagnostic_records_reach_both_outputs_and_zero_is_silent() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let mut session = Session::from_config(options.clone().into_validated().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut log = captured_logger(Arc::clone(&events), false);
        log.open_file(&options).unwrap();
        for state in [State::AdminDown, State::Down, State::Init, State::Up] {
            session.state = state;
            log.session_event(
                SessionEvent::StateChanged,
                &options,
                &session,
                State::Up,
                42,
            );
        }
        for code in 0..=9 {
            log.diagnostic_event(&options, &session, Origin::Remote, code, State::Up);
        }
        log.flush(Duration::from_secs(2)).unwrap();
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 12);
        let contents = fs::read_to_string(&options.log_file_path).unwrap();
        assert_eq!(contents.lines().count(), 12);
        for ((id, level), line) in events.iter().zip(contents.lines()) {
            let level = if *level == 2 {
                "Error"
            } else if *level == 3 {
                "Warning"
            } else {
                "Information"
            };
            assert!(
                line.contains(&format!("event_id={id} level={level}")),
                "{line}"
            );
            let timestamp = line.split_once(' ').unwrap().0;
            assert_eq!(timestamp.len(), 24);
            assert!(timestamp.ends_with('Z'));
        }
        assert!(!contents.contains("event_id=200"));
        assert!(!contents.contains("diagnostic_code=0 diagnostic="));
    }

    #[cfg(not(miri))]
    #[test]
    fn etw_failure_does_not_suppress_file_events_and_disabled_file_stays_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        let session = Session::from_config(options.clone().into_validated().unwrap());
        options.log_file_path = directory.path().join("new-folder/trace.log");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut log = captured_logger(Arc::clone(&events), true);
        log.open_file(&options).unwrap();
        log.session_event(
            SessionEvent::StateChanged,
            &options,
            &session,
            State::Down,
            0,
        );
        log.flush(Duration::from_secs(2)).unwrap();
        assert!(!options.log_file_path.parent().unwrap().exists());
        options.log_to_file = true;
        log.open_file(&options).unwrap();
        log.session_event(
            SessionEvent::StateChanged,
            &options,
            &session,
            State::Down,
            0,
        );
        log.flush(Duration::from_secs(2)).unwrap();
        let text = fs::read_to_string(&options.log_file_path).unwrap();
        assert!(text.contains("synthetic ETW failure"));
        assert!(text.contains("event_id=102 level=Information"));
        assert_eq!(*events.lock().unwrap(), [(102, 4), (102, 4)]);
    }
    #[cfg(not(miri))]
    #[test]
    fn service_state_events_also_write_the_enabled_file() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::new("127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap());
        options.multihop = true;
        options.discriminator = Some(7);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let auth = options.validate().unwrap();
        let mut session = Session::new(options.clone(), auth).unwrap();
        session.state = State::Up;
        let mut logger = Logger::open(&options).unwrap();
        logger.session_event(
            SessionEvent::StateChanged,
            &options,
            &session,
            State::Init,
            99,
        );
        logger.flush(Duration::from_secs(2)).unwrap();
        let text = fs::read_to_string(&options.log_file_path).unwrap();
        assert!(text.contains("event_id=102 level=Information"), "{text}");
        assert!(text.contains("state=Up"), "{text}");
    }
    #[cfg(not(miri))]
    #[test]
    fn cloned_loggers_share_ordered_file_output_and_flush_completion() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let mut logger = Logger::open(&options).unwrap();
        let mut cloned = logger.clone();
        logger.log("engine message");
        cloned.log("BGP message");
        drop(cloned);
        logger.flush(Duration::from_secs(2)).unwrap();
        let contents = fs::read_to_string(&options.log_file_path).unwrap();
        let messages: Vec<_> = contents
            .lines()
            .map(|line| line.split_once(' ').unwrap().1)
            .collect();
        assert_eq!(messages, ["engine message", "BGP message"]);
        assert_eq!(logger.dropped_records(), 0);
    }
    #[test]
    #[cfg(not(miri))]
    fn buffered_file_output_flushes_on_timeout_reconfiguration_and_drop() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("first.log");
        let mut logger = Logger::open(&options).unwrap();
        logger.log("visible without explicit flush");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let text = fs::read_to_string(&options.log_file_path).unwrap();
            if text.contains("visible without explicit flush") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "buffered records must become visible"
            );
            thread::sleep(Duration::from_millis(10));
        }
        logger.log("before file switch");
        let first_path = options.log_file_path.clone();
        options.log_file_path = directory.path().join("second.log");
        logger.open_file(&options).unwrap();
        logger.log("after file switch\nsecond line\n");
        drop(logger);
        assert!(fs::read_to_string(first_path)
            .unwrap()
            .contains("before file switch"));
        let second = fs::read_to_string(&options.log_file_path).unwrap();
        assert!(second.contains("after file switch") && second.contains("second line"));
        let lines: Vec<_> = second.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(&lines[0][..24], &lines[1][..24]);
        assert_eq!(&lines[0][..24], &lines[2][..24]);
    }

    #[cfg(not(miri))]
    #[test]
    fn full_file_rotates_to_one_backup_and_output_continues() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut log = captured_logger_with_limit(events, false, 256);
        log.open_file(&options).unwrap();
        // Each 77-byte line counts toward the limit; rotate before a fourth line.
        for index in 0..42 {
            log.log(format_args!("record {index:02} {}", "x".repeat(40)));
        }
        log.flush(Duration::from_secs(2)).unwrap();
        let mut backup = options.log_file_path.clone().into_os_string();
        backup.push(".1");
        let current = fs::read_to_string(&options.log_file_path).unwrap();
        let previous = fs::read_to_string(&backup).unwrap();
        assert!(current.contains("record 41"), "{current}");
        assert!(current.contains("record 39"), "{current}");
        assert!(previous.contains("record 38"), "{previous}");
        // Both files stay strictly within the limit; older backups are replaced.
        for text in [&current, &previous] {
            assert!(text.len() <= 256, "{}", text.len());
        }
        assert!(!previous.contains("record 00"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[cfg(not(miri))]
    #[test]
    fn denied_rename_bounds_the_file_preserves_etw_and_recovers() {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let session = Session::from_config(options.clone().into_validated().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut log = captured_logger_with_limit(Arc::clone(&events), false, 512);
        log.open_file(&options).unwrap();
        log.flush(Duration::from_secs(2)).unwrap();
        // A permitted read-only user can share writes while denying rename/delete.
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&options.log_file_path)
            .unwrap();
        for _ in 0..100 {
            log.session_event(
                SessionEvent::StateChanged,
                &options,
                &session,
                State::Up,
                42,
            );
        }
        log.flush(Duration::from_secs(2)).unwrap();
        assert_eq!(events.lock().unwrap().len(), 100);
        assert!(fs::metadata(&options.log_file_path).unwrap().len() <= 512);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        drop(blocker);
        drop(log);

        // Exercise bounded retries without sleeping for the production interval.
        let file = OpenOptions::new()
            .append(true)
            .open(&options.log_file_path)
            .unwrap();
        let mut output = OutputFile::new(file, options.log_file_path.clone(), 512);
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&options.log_file_path)
            .unwrap();
        assert!(!output.prepare_line(512));
        drop(blocker);
        // Releasing the reader does not bypass the retry interval.
        assert!(!output.prepare_line(512));
        output.retry_rotation_at = Some(Instant::now());
        assert!(output.prepare_line(512));
        output.writer.write_all(&[b'x'; 512]).unwrap();
        output.length = 512;
        output.writer.flush().unwrap();
        assert_eq!(fs::metadata(&options.log_file_path).unwrap().len(), 512);
    }

    #[cfg(not(miri))]
    #[test]
    fn failed_reopen_never_appends_to_the_backup_and_retries_only_the_open() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.log");
        fs::write(&path, [b'x'; 256]).unwrap();
        let file = OpenOptions::new().append(true).open(&path).unwrap();
        let mut output = OutputFile::new(file, path.clone(), 256);
        // Inject the failure after the real rename, rather than mocking rotation.
        assert!(output
            .rotate_with(|_| Err(io::Error::other("reopen denied")))
            .is_err());
        let backup = directory.path().join("trace.log.1");
        assert!(output.renamed);
        for _ in 0..100 {
            assert!(!output.prepare_line(64));
        }
        assert!(!path.exists());
        assert_eq!(fs::read(&backup).unwrap(), [b'x'; 256]);
        output.retry_rotation_at = Some(Instant::now());
        assert!(output.prepare_line(64));
        output.writer.write_all(&[b'y'; 64]).unwrap();
        output.length += 64;
        output.writer.flush().unwrap();
        assert_eq!(fs::read(&path).unwrap(), [b'y'; 64]);
        assert_eq!(fs::read(&backup).unwrap(), [b'x'; 256]);
        assert!(!output.renamed);
    }

    #[cfg(not(miri))]
    #[test]
    fn oversized_lines_and_preexisting_full_files_cannot_exceed_the_ceiling() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.log");
        fs::write(&path, [b'x'; 256]).unwrap();
        let file = OpenOptions::new().append(true).open(&path).unwrap();
        let mut output = Some(OutputFile::new(file, path.clone(), 256));
        let mut timestamp = String::new();
        text_output(&"🦀".repeat(100), &mut output, &mut timestamp);
        assert_eq!(fs::metadata(&path).unwrap().len(), 256);
        text_output("short line\nanother", &mut output, &mut timestamp);
        output.as_mut().unwrap().writer.flush().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("short line") && text.contains("another"));
        assert!(text.len() <= 256);
        assert_eq!(
            fs::read(directory.path().join("trace.log.1")).unwrap(),
            [b'x'; 256]
        );
    }

    #[test]
    fn message_limit_preserves_utf8_boundaries() {
        let mut text = BoundedText(String::new());
        write!(
            &mut text,
            "{}{}",
            "a".repeat(MAX_TEXT_BYTES - 1),
            "🦀".repeat(100)
        )
        .unwrap();
        assert_eq!(text.0.len(), MAX_TEXT_BYTES - 1);
        assert!(text.0.is_char_boundary(text.0.len()));
    }
}
