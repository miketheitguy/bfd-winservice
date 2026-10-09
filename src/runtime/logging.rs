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
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const QUEUE_CAPACITY: usize = 256;
const MAX_TEXT_BYTES: usize = 16_384;
const SHUTDOWN_WAIT: Duration = Duration::from_millis(500);
const FILE_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

enum Command {
    Text(String),
    Event(Record),
    File(Option<File>),
    Flush(mpsc::Sender<io::Result<()>>),
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
    pub(super) console: bool,
}

impl Logger {
    /// Starts the output worker before registry loading.
    ///
    /// # Errors
    /// Returns a thread creation error. ETW registration failures are diagnostic only.
    pub fn new(console: bool) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (done_tx, done) = mpsc::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let thread = thread::Builder::new()
            .name("bfd-log".into())
            .spawn(move || {
                write_records(receiver, console, &worker_dropped);
                let _ = done_tx.send(());
            })?;
        Ok(Self {
            console,
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
        let mut logger = Self::new(options.console)?;
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
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&options.log_file_path)?,
            )
        } else {
            None
        };
        self.send_control(Command::File(file))
    }

    /// Waits for preceding records and flushes the file, within the supplied deadline.
    /// BFD execution doesn't call this method.
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
    /// on UTF-8 character boundaries. File lines use ISO-8601 UTC with a trailing Z;
    /// STDOUT uses Unix milliseconds, sampled by the writer.
    ///
    /// ```no_run
    /// use bfd_winservice::runtime::Logger;
    /// let mut log = Logger::new(true)?;
    /// log.log("BFD initialization started");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn log(&mut self, message: impl Display) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{message}");
        self.enqueue(Command::Text(text.0));
    }
    /// Queues successful engine startup.
    pub fn service_started(&mut self) {
        self.log(format_args!(
            "service started mode={}",
            if self.console { "console" } else { "service" }
        ));
        if !self.console {
            self.enqueue(Command::Event(Record::service_started(self.console)));
        }
    }
    /// Queues completed shutdown; zero indicates success.
    pub fn service_stopped(&mut self, exit_code: u32) {
        self.log(format_args!("service stopped exit_code={exit_code}"));
        if !self.console {
            self.enqueue(Command::Event(Record::service_stopped(
                self.console,
                exit_code,
            )));
        }
    }
    /// Queues a startup/runtime error without authentication data.
    pub fn service_failed(&mut self, error: impl Display) {
        let mut text = BoundedText(String::new());
        let _ = write!(&mut text, "{error}");
        self.log(format_args!("service failed: {}", text.0));
        if !self.console {
            self.enqueue(Command::Event(Record::service_failed(
                self.console,
                &text.0,
            )));
        }
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
        if !self.console {
            self.enqueue(Command::Event(Record::authentication_failed(
                options,
                session,
                source,
                &reason.to_string(),
            )));
        }
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

fn text_output(
    message: &str,
    console: bool,
    stdout_failed: &mut bool,
    file: &mut Option<BufWriter<File>>,
    timestamp: &mut String,
) {
    if let Some(file) = file {
        utc_timestamp(timestamp);
        for line in message.split('\n') {
            if let Err(error) = writeln!(file, "{timestamp} {line}") {
                diagnostic(format_args!("unable to write BFD file log: {error}"));
                break;
            }
        }
        // Keep file output visible before a console pipe can block the worker.
        if console {
            flush_file(file);
        }
    }
    if console && !*stdout_failed {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        if let Err(error) = writeln!(io::stdout().lock(), "{timestamp} {message}") {
            *stdout_failed = true;
            diagnostic(format_args!("unable to write BFD console log: {error}"));
        }
    }
}

fn flush_file(file: &mut BufWriter<File>) {
    if let Err(error) = file.flush() {
        diagnostic(format_args!("unable to flush BFD file log: {error}"));
    }
}

fn write_records(receiver: Receiver<Command>, console: bool, dropped: &AtomicU64) {
    let provider = if console {
        None
    } else {
        match Provider::register() {
            Ok(provider) => Some(provider),
            Err(error) => {
                diagnostic(format_args!(
                    "unable to register BFD-Service ETW provider: {error}"
                ));
                None
            }
        }
    };
    write_records_with(receiver, console, dropped, |record| {
        provider
            .as_ref()
            .map_or(Ok(()), |provider| provider.emit(record))
    });
}

fn write_records_with(
    receiver: Receiver<Command>,
    console: bool,
    dropped: &AtomicU64,
    mut emit: impl FnMut(&Record) -> io::Result<()>,
) {
    let mut file: Option<BufWriter<File>> = None;
    let mut timestamp = String::with_capacity(24);
    let mut next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
    let mut stdout_failed = false;
    let mut reported = 0;
    loop {
        let pending = file.as_ref().is_some_and(|file| !file.buffer().is_empty());
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
                if let Some(file) = &mut file {
                    flush_file(file);
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
                console,
                &mut stdout_failed,
                &mut file,
                &mut timestamp,
            );
            reported = lost;
        }
        match command {
            Command::Text(text) => text_output(
                &text,
                console,
                &mut stdout_failed,
                &mut file,
                &mut timestamp,
            ),
            Command::Event(record) => {
                if !console {
                    if let Err(error) = emit(&record) {
                        text_output(
                            &format!("unable to write BFD-Service ETW event: {error}"),
                            console,
                            &mut stdout_failed,
                            &mut file,
                            &mut timestamp,
                        );
                    }
                }
                if let Some(text) = &record.text {
                    text_output(text, console, &mut stdout_failed, &mut file, &mut timestamp);
                }
            }
            Command::File(next) => {
                if let Some(file) = &mut file {
                    flush_file(file);
                }
                file = next.map(BufWriter::new);
            }
            Command::Flush(reply) => {
                let _ = reply.send(file.as_mut().map_or(Ok(()), Write::flush));
            }
        }
        if Instant::now() >= next_flush {
            if let Some(file) = &mut file {
                flush_file(file);
            }
            next_flush = Instant::now() + FILE_FLUSH_INTERVAL;
        }
    }
    if let Some(file) = &mut file {
        flush_file(file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(miri))]
    fn captured_logger(
        console: bool,
        events: Arc<Mutex<Vec<(u16, u8)>>>,
        fail_etw: bool,
    ) -> Logger {
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (done_tx, done) = mpsc::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        let thread = thread::spawn(move || {
            write_records_with(receiver, console, &worker_dropped, |record| {
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
            console,
            worker: Arc::new(Worker {
                sender: Some(sender),
                shutdown: Mutex::new(Shutdown { done, thread }),
                dropped,
            }),
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
        let mut log = captured_logger(false, Arc::clone(&events), false);
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
        let mut log = captured_logger(false, Arc::clone(&events), true);
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
        let second = fs::read_to_string(options.log_file_path).unwrap();
        assert!(second.contains("after file switch") && second.contains("second line"));
        let lines: Vec<_> = second.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(&lines[0][..24], &lines[1][..24]);
        assert_eq!(&lines[0][..24], &lines[2][..24]);
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
