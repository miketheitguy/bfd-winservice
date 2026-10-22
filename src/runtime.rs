//! Windows BFD packet/timer loop, logging, and optional background BGP control.
use crate::{
    bgp::Controller,
    config::{load_sbfd_settings, Options, SessionType, SettingsWatch, Timing, ValidatedOptions},
    error::ConfigError,
    event_log::{Origin, SessionEvent},
    packet::{AuthConfig, Diagnostic, State},
    seamless::Reflector,
    session::{ReceiveError, Session, Transmission},
    transport::{is_transient, Datagram, Transport},
};
use std::{
    collections::HashMap,
    fmt::Write as _,
    io,
    net::IpAddr,
    os::windows::io::BorrowedHandle,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, TryRecvError},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};
use windows_sys::Win32::{Foundation::SYSTEMTIME, System::SystemInformation::GetSystemTime};

mod logging;
mod privileges;
pub(crate) mod state;
pub mod status;
pub use crate::service_identity::verify_bfd_service_identity;
pub use crate::transport::StopSignal;
pub use logging::Logger;
#[cfg(test)]
pub(crate) use privileges::drop_rpc_privileges;
pub use privileges::verify_service_privileges;
pub(crate) use privileges::REQUIRED_PRIVILEGE;
pub use state::StateObserver;
use state::StatePublisher;
pub use status::{RejectionReason, StatusObserver, StatusSnapshot};
use status::{StatusPublisher, StatusTelemetry};

/// Loops also wake at least once per second, independent of protocol timers.
const MAX_IDLE_WAIT: Duration = Duration::from_secs(1);
const FAULT_RETRY_MIN: Duration = Duration::from_millis(10);
const FAULT_RETRY_MAX: Duration = Duration::from_millis(250);
/// Warnings about sustained faults or suppression repeat at most this often.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);
/// Session, peer, and diagnostic events written per second before suppression.
const EVENTS_PER_SECOND: u32 = 32;
/// S-BFD replies per second to any one source address, bounding reflection.
const REPLIES_PER_SOURCE: u32 = 1000;
/// Distinct sources tracked per second; further new sources wait for the next second.
const TRACKED_SOURCES: usize = 4096;

#[derive(Clone, Copy)]
enum StopRequest<'a> {
    Channel(&'a Receiver<()>),
    Event(&'a StopSignal),
}

impl StopRequest<'_> {
    fn is_requested(self) -> bool {
        match self {
            Self::Channel(receiver) => !matches!(receiver.try_recv(), Err(TryRecvError::Empty)),
            Self::Event(signal) => signal.is_requested(),
        }
    }

    fn wait(
        self,
        transport: &Transport,
        timeout: Duration,
        notify: Option<BorrowedHandle<'_>>,
    ) -> io::Result<()> {
        match self {
            Self::Channel(_) => transport.wait_readable(timeout.min(Duration::from_millis(10))),
            Self::Event(signal) => transport.wait_stoppable(timeout, signal, notify),
        }
    }

    /// Sleeps without waking for socket events, pacing retries after socket faults.
    fn pause(self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Channel(_) => {
                thread::sleep(timeout.min(Duration::from_millis(10)));
                Ok(())
            }
            Self::Event(signal) => signal.wait(timeout),
        }
    }
}

/// Paces retries after transient socket faults, such as an adapter reset, so a
/// persistent fault neither ends the engine nor spins its thread. Protocol timers
/// keep running, so detection still expires while the path is unusable.
#[derive(Default)]
struct SocketFaults {
    count: u64,
    delay: Duration,
    last_report: Option<Instant>,
}

impl SocketFaults {
    fn next_delay(&mut self) -> Duration {
        let delay = self.delay.max(FAULT_RETRY_MIN);
        self.delay = (delay * 2).min(FAULT_RETRY_MAX);
        self.count = self.count.saturating_add(1);
        delay
    }

    /// Records a fault and pauses until the retry delay or `limit`, whichever is sooner.
    fn pause(
        &mut self,
        stop: StopRequest<'_>,
        error: &io::Error,
        limit: Duration,
        log: &mut Logger,
    ) -> io::Result<()> {
        let delay = self.next_delay();
        if due(&mut self.last_report, Instant::now(), REPORT_INTERVAL) {
            log.service_warning(format_args!(
                "transient BFD socket failure; retrying while protocol timers continue: {error}"
            ));
        }
        stop.pause(delay.min(limit))
    }

    fn recovered(&mut self, log: &mut Logger) {
        if self.count != 0 {
            log.log(format_args!(
                "BFD socket recovered after {} transient failures",
                self.count
            ));
            *self = Self::default();
        }
    }
}

/// Bounds session event output when spoofed or flapping traffic changes reported
/// state on every packet. Suppressed counts are reported at most once a minute.
#[derive(Default)]
struct EventBudget {
    window: Option<Instant>,
    used: u32,
    suppressed: u64,
    last_report: Option<Instant>,
}

impl EventBudget {
    fn admit(&mut self, now: Instant) -> bool {
        if self
            .window
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(1))
        {
            self.window = Some(now);
            self.used = 0;
        }
        if self.used < EVENTS_PER_SECOND {
            self.used += 1;
            true
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            false
        }
    }

    /// Takes the suppressed count when a report is due, or unconditionally when forced.
    fn take_report(&mut self, now: Instant, force: bool) -> Option<u64> {
        if self.suppressed == 0 || !force && !due(&mut self.last_report, now, REPORT_INTERVAL) {
            return None;
        }
        self.last_report = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Limits S-BFD replies per source address and second. A spoofed request names
/// its victim as the source, so a per-source limit bounds reflected traffic.
#[derive(Default)]
struct ReplyLimiter {
    window: Option<Instant>,
    replies: HashMap<IpAddr, u32>,
    withheld: u64,
}

impl ReplyLimiter {
    fn admit(&mut self, source: IpAddr, now: Instant) -> bool {
        if self
            .window
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(1))
        {
            self.window = Some(now);
            self.replies.clear();
        }
        let tracked = self.replies.len();
        let admitted = match self.replies.get_mut(&source) {
            Some(count) if *count < REPLIES_PER_SOURCE => {
                *count += 1;
                true
            }
            None if tracked < TRACKED_SOURCES => {
                self.replies.insert(source, 1);
                true
            }
            _ => false,
        };
        if !admitted {
            self.withheld = self.withheld.saturating_add(1);
        }
        admitted
    }
}

/// How live S-BFD settings changes are detected.
enum LiveSettings {
    /// Classical or programmatic sessions have no live registry settings.
    None,
    /// A registry change notification signals the engine's wait.
    Notify(SettingsWatch),
    /// Notification is unavailable, so settings are read once per second.
    Poll,
}

impl LiveSettings {
    fn event(&self) -> Option<BorrowedHandle<'_>> {
        match self {
            Self::Notify(watch) => Some(watch.event()),
            Self::None | Self::Poll => None,
        }
    }
}

/// Read the Windows UTC clock without applying the local timezone.
#[allow(unsafe_code)] // GetSystemTime is the sole FFI operation in this module.
fn utc_timestamp(text: &mut String) {
    let mut time = SYSTEMTIME::default();
    // SAFETY: time is a valid, writable SYSTEMTIME that remains alive throughout
    // the synchronous call. GetSystemTime initializes its fields with UTC values.
    unsafe { GetSystemTime(&mut time) };
    text.clear();
    write!(
        text,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds,
    )
    .expect("formatting into a String cannot fail");
}

/// One validated session, its UDP sockets, and any configured BGP worker.
pub struct Engine {
    // Drop the publication before sockets/providers so retained readers cannot
    // report a live state while an engine that never ran is being torn down.
    state_publisher: StatePublisher,
    status_publisher: StatusPublisher,
    status_telemetry: StatusTelemetry,
    options: ValidatedOptions,
    timing: Timing,
    sbfd_admin_down: bool,
    session: Session,
    transport: Transport,
    bgp: Option<Controller>,
    reflector: Option<Reflector>,
    last_peer_report: Option<(State, u8, u32)>,
    live_settings: LiveSettings,
    settings_retry: bool,
    last_settings_error: Option<Instant>,
    events: EventBudget,
    shutdown_progress: ShutdownProgress,
}

/// Reports the AdminDown announcement period chosen when the engine stops, so a
/// service supervisor can include that bounded period in its stop budget.
#[derive(Clone, Default)]
pub struct ShutdownProgress(Arc<AtomicU64>);

impl ShutdownProgress {
    /// Returns the announcement period, or zero before shutdown begins.
    pub fn announcement(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }

    fn record(&self, period: Duration) {
        let millis = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
        self.0.store(millis, Ordering::Relaxed);
    }
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
        for warning in options.security_warnings() {
            log.service_warning(warning);
        }
        let live_settings = if options.registry_backed
            && options.session_type != SessionType::Classical
        {
            match SettingsWatch::open() {
                Ok(watch) => LiveSettings::Notify(watch),
                Err(error) => {
                    log.log(format_args!(
                            "registry change notification is unavailable; reading S-BFD settings each second: {error}"
                        ));
                    LiveSettings::Poll
                }
            }
        } else {
            LiveSettings::None
        };
        let now = Instant::now();
        let status_telemetry = StatusTelemetry::new(now, SystemTime::now(), &options);
        let initial_status =
            status_telemetry.snapshot(&session, &options, options.timing(), transport.source_port);
        Ok(Self {
            state_publisher: StatePublisher::new(session.state()),
            status_publisher: StatusPublisher::new(
                initial_status,
                status_telemetry.revision(),
                now,
            ),
            status_telemetry,
            timing: options.timing(),
            sbfd_admin_down: options.sbfd_admin_down,
            options,
            session,
            transport,
            bgp,
            reflector,
            last_peer_report: None,
            live_settings,
            settings_retry: false,
            last_settings_error: None,
            events: EventBudget::default(),
            shutdown_progress: ShutdownProgress::default(),
        })
    }
    /// Returns a shared, read-only view of the current local BFD state.
    pub fn state_observer(&self) -> StateObserver {
        self.state_publisher.observer()
    }

    /// Returns immutable administrative snapshots. Recorded changes publish at
    /// most every 100 ms; an unchanged engine republishes its view each second.
    /// Queries read shared `Arc` snapshots without requesting packet-loop work.
    pub fn status_observer(&self) -> StatusObserver {
        self.status_publisher.observer()
    }

    fn publish_status(&mut self, now: Instant) {
        let revision = self.status_telemetry.revision();
        if self.status_publisher.is_due(revision, now) {
            self.status_telemetry.calibrate(now, SystemTime::now());
            let snapshot = self.status_telemetry.snapshot(
                &self.session,
                &self.options,
                self.timing,
                self.transport.source_port,
            );
            self.status_publisher.publish(snapshot, revision, now);
        }
    }

    /// Returns a handle that reports the AdminDown announcement period at shutdown.
    pub fn shutdown_progress(&self) -> ShutdownProgress {
        self.shutdown_progress.clone()
    }

    /// Admits one session event within the per-second budget. Administrative
    /// events bypass the budget so shutdown is always recorded.
    fn event_admitted(&mut self, administrative: bool, log: &mut Logger) -> bool {
        let now = Instant::now();
        let admitted = administrative || self.events.admit(now);
        self.report_suppressed_events(now, false, log);
        admitted
    }

    fn report_suppressed_events(&mut self, now: Instant, force: bool, log: &mut Logger) {
        if let Some(count) = self.events.take_report(now, force) {
            log.service_warning(format_args!(
                "suppressed {count} BFD session events that exceeded {EVENTS_PER_SECOND} per second"
            ));
        }
    }

    fn state_changed(&mut self, previous: State, log: &mut Logger) {
        if previous == self.session.state() {
            return;
        }
        self.status_telemetry.transition(
            self.session.state(),
            self.session.diagnostic(),
            Instant::now(),
        );
        self.state_publisher.publish(self.session.state());
        if let Some(bgp) = &self.bgp {
            // Administrative disablement must allow the BGP adjacency (RFC 5882
            // section 4.1). The controller releases its Stop on local AdminDown;
            // peer_report_changed handles the peer's AdminDown separately.
            if !self.session.down_by_peer_admin() {
                bgp.state_changed(previous, self.session.state);
            }
        }
        let administrative = self.session.state() == State::AdminDown;
        if self.event_admitted(administrative, log) {
            log.session_event(
                SessionEvent::StateChanged,
                &self.options,
                &self.session,
                previous,
                self.session.remote_discriminator,
            );
        }
        // Up retains historical classical diagnostics; it doesn't report a new failure.
        if matches!(self.session.state(), State::Down | State::AdminDown)
            && self.event_admitted(administrative, log)
        {
            log.diagnostic_event(
                &self.options,
                &self.session,
                Origin::Local,
                self.session.diagnostic() as u8,
                previous,
            );
        }
    }
    fn peer_communication_changed(
        &mut self,
        communicating: bool,
        previous: State,
        remote_discriminator: u32,
        log: &mut Logger,
    ) {
        if !self.event_admitted(false, log) {
            return;
        }
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

    fn peer_report_changed(&mut self, log: &mut Logger) {
        let state = self.session.remote_state();
        let diagnostic = self.session.remote_diagnostic();
        let discriminator = self.session.remote_discriminator();
        if state == State::AdminDown {
            if let Some(bgp) = &self.bgp {
                // RFC 5882 section 4.1: BFD disabled at the peer must allow BGP.
                bgp.peer_admin_down();
            }
        }
        let previous = self
            .last_peer_report
            .filter(|report| report.2 == discriminator);
        if previous.is_none_or(|report| report.0 != state) && self.event_admitted(false, log) {
            log.session_event(
                SessionEvent::PeerStateChanged,
                &self.options,
                &self.session,
                previous.map_or(state, |report| report.0),
                discriminator,
            );
        }
        // Only diagnostics 1-8 have events; reserved values must not consume the budget.
        if (1..=8).contains(&diagnostic)
            && previous.is_none_or(|report| {
                report.1 != diagnostic
                    || report.0 != state && matches!(state, State::Down | State::AdminDown)
            })
            && self.event_admitted(false, log)
        {
            log.diagnostic_event(
                &self.options,
                &self.session,
                Origin::Remote,
                diagnostic,
                previous.map_or(state, |report| report.0),
            );
        }
        self.last_peer_report = Some((state, diagnostic, discriminator));
    }

    fn set_reflector_admin_down(&mut self, admin_down: bool, log: &mut Logger) {
        let Some(reflector) = &mut self.reflector else {
            return;
        };
        if self.sbfd_admin_down == admin_down {
            return;
        }
        let previous = self.session.state();
        reflector.set_admin_down(admin_down);
        self.sbfd_admin_down = admin_down;
        self.session.state = reflector.state();
        self.session.diagnostic = if admin_down {
            Diagnostic::AdminDown
        } else {
            Diagnostic::None
        };
        self.state_changed(previous, log);
    }
    fn transmit(&mut self, kind: Transmission, log: &mut Logger, last_error: &mut Option<Instant>) {
        let now = Instant::now();
        let packet = self.session.prepare_packet(kind, now);
        if let Err(error) = self.transport.send(&packet.data) {
            self.status_telemetry.socket_error(&error, now);
            if last_error.is_none_or(|last| now.duration_since(last) >= Duration::from_secs(1)) {
                log.log(format_args!(
                    "send to {} failed: {error}",
                    self.options.peer
                ));
                *last_error = Some(now);
            }
        } else {
            self.session.record_transmission(&packet);
            self.status_telemetry.sent(now);
        }
    }

    /// Applies live S-BFD timers without resetting protocol state.
    ///
    /// # Errors
    /// Rejects classical sessions, which use startup-only local settings, and
    /// overlapping transmitted initiator Poll changes.
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
        self.reload_sbfd_settings_from(log, load_sbfd_settings);
    }

    fn reload_sbfd_settings_from(
        &mut self,
        log: &mut Logger,
        read: impl FnOnce(&Options) -> io::Result<(Timing, bool)>,
    ) {
        if !self.options.registry_backed || self.options.session_type == SessionType::Classical {
            return;
        }
        let result = read(&self.options).and_then(|(timing, admin_down)| {
            if self.timing != timing {
                self.set_timing(timing)?;
                log.log("S-BFD timing settings reloaded");
            }
            self.set_reflector_admin_down(admin_down, log);
            Ok(())
        });
        self.status_telemetry
            .configuration_reload(result.is_ok(), Instant::now());
        if let Err(error) = result {
            self.settings_retry = true;
            if due(
                &mut self.last_settings_error,
                Instant::now(),
                REPORT_INTERVAL,
            ) {
                log.log(format_args!(
                    "S-BFD settings reload rejected; retrying: {error}"
                ));
            }
        } else {
            self.settings_retry = false;
            self.last_settings_error = None;
        }
    }

    /// Reloads live S-BFD settings after a registry change notification, or once
    /// per second when notification is unavailable. A failed notification falls
    /// back to polling rather than leaving later changes unapplied.
    fn refresh_settings(&mut self, now: Instant, next_poll: &mut Instant, log: &mut Logger) {
        let due = match &self.live_settings {
            LiveSettings::None => return,
            LiveSettings::Notify(watch) => match watch.take_change() {
                Ok(changed) => changed,
                Err(error) => {
                    log.log(format_args!(
                        "registry change notification failed; reading S-BFD settings each second: {error}"
                    ));
                    self.live_settings = LiveSettings::Poll;
                    true
                }
            },
            LiveSettings::Poll => now >= *next_poll,
        };
        self.refresh_settings_from(now, next_poll, due, log, load_sbfd_settings);
    }

    fn refresh_settings_from(
        &mut self,
        now: Instant,
        next_poll: &mut Instant,
        changed: bool,
        log: &mut Logger,
        read: impl FnOnce(&Options) -> io::Result<(Timing, bool)>,
    ) {
        if changed || self.settings_retry && now >= *next_poll {
            self.reload_sbfd_settings_from(log, read);
            *next_poll = now + Duration::from_secs(1);
        }
    }

    /// Bounds a wait so the fallback settings read and the idle wakeup still occur.
    /// Unpublished events shorten the status deadline to the publication interval.
    fn idle_wait(&self, now: Instant, next_poll: Instant) -> Duration {
        let status_wait = self
            .status_publisher
            .deadline(self.status_telemetry.revision())
            .saturating_duration_since(now);
        if self.settings_retry {
            return next_poll
                .saturating_duration_since(now)
                .min(MAX_IDLE_WAIT)
                .min(status_wait);
        }
        let wait = match self.live_settings {
            LiveSettings::Poll => next_poll.saturating_duration_since(now).min(MAX_IDLE_WAIT),
            LiveSettings::None | LiveSettings::Notify(_) => MAX_IDLE_WAIT,
        };
        wait.min(status_wait)
    }

    /// Waits for traffic, a timer, Stop, or a settings change. A transient socket
    /// fault reported by the wait pauses the loop instead of ending the engine.
    fn wait_for_traffic(
        &mut self,
        stop: StopRequest<'_>,
        timeout: Duration,
        faults: &mut SocketFaults,
        log: &mut Logger,
    ) -> io::Result<()> {
        match stop.wait(&self.transport, timeout, self.live_settings.event()) {
            Ok(()) => {
                faults.recovered(log);
                Ok(())
            }
            Err(error) if is_transient(&error) => {
                self.status_telemetry.socket_error(&error, Instant::now());
                faults.pause(stop, &error, timeout, log)
            }
            Err(error) => {
                self.status_telemetry.socket_error(&error, Instant::now());
                Err(error)
            }
        }
    }

    fn log_rejection(
        &mut self,
        datagram: &Datagram,
        error: ReceiveError,
        log: &mut Logger,
        last_discard: &mut Option<Instant>,
        last_auth_failure: &mut Option<Instant>,
    ) {
        let now = Instant::now();
        self.status_telemetry.rejected(
            match &error {
                ReceiveError::Authentication(reason) => RejectionReason::Authentication(*reason),
                ReceiveError::Packet(reason) => RejectionReason::Packet(*reason),
            },
            now,
        );
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

    fn run_reflector(&mut self, stop: StopRequest<'_>, log: &mut Logger) -> io::Result<()> {
        let mut datagram = Datagram::default();
        // Also applies any change made before the settings watch was armed.
        self.reload_sbfd_settings(log);
        let mut next_settings_poll = Instant::now() + Duration::from_secs(1);
        let mut last_error = None;
        let mut last_discard = None;
        let mut last_auth_failure = None;
        let mut last_withheld_report = None;
        let mut faults = SocketFaults::default();
        let mut replies = ReplyLimiter::default();
        let result = loop {
            if stop.is_requested() {
                break Ok(());
            }
            let now = Instant::now();
            self.refresh_settings(now, &mut next_settings_poll, log);
            // Settings reloads can record events after the loop's time sample.
            self.publish_status(Instant::now());
            match self.transport.receive_into(&mut datagram) {
                Ok(()) => {
                    faults.recovered(log);
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
                        // Requests over a source's reply limit are withheld, not answered.
                        Ok(_) if !replies.admit(datagram.source.ip(), now) => {
                            self.status_telemetry.received(datagram.source, now);
                            self.status_telemetry.withheld();
                        }
                        Ok(reply) => {
                            self.status_telemetry.received(datagram.source, now);
                            if let Err(error) =
                                self.transport.send_reply(&reply, &datagram, &self.options)
                            {
                                self.status_telemetry.socket_error(&error, now);
                                if log_due(&mut last_error, now) {
                                    log.log(format_args!(
                                        "S-BFD reply to {} failed: {error}",
                                        datagram.source
                                    ));
                                }
                            } else {
                                self.status_telemetry.sent(now);
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
                    if replies.withheld != 0 && due(&mut last_withheld_report, now, REPORT_INTERVAL)
                    {
                        report_withheld(&mut replies, log);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let wait = self.idle_wait(Instant::now(), next_settings_poll);
                    if let Err(error) = self.wait_for_traffic(stop, wait, &mut faults, log) {
                        break Err(error);
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidData
                        || error.raw_os_error() == Some(10040) =>
                {
                    self.status_telemetry
                        .rejected(RejectionReason::InvalidDatagram, now);
                }
                Err(error) if is_transient(&error) => {
                    self.status_telemetry.socket_error(&error, now);
                    let limit = self.idle_wait(Instant::now(), next_settings_poll);
                    if let Err(error) = faults.pause(stop, &error, limit, log) {
                        break Err(error);
                    }
                }
                Err(error) => {
                    self.status_telemetry.socket_error(&error, now);
                    break Err(error);
                }
            }
            // One request per pass keeps Stop and settings reload responsive under load.
        };
        if replies.withheld != 0 {
            report_withheld(&mut replies, log);
        }
        result
    }
    /// Run until a stop message/channel disconnect or fatal receive/wait error.
    /// Transient network faults, such as an adapter reset, pause socket use with
    /// a bounded backoff while timers continue; they don't end the engine.
    ///
    /// On exit, set AdminDown, announce shutdown when the role permits it, and
    /// wait for BGP cleanup. Send failures are logged, not returned. The BGP
    /// controller is consumed during cleanup; construct a new engine to restart.
    ///
    /// # Errors
    /// Returns fatal receive/wait errors or BGP cleanup failures. If both fail,
    /// the receive/wait error takes precedence.
    pub fn run(&mut self, stop: &Receiver<()>, log: &mut Logger) -> io::Result<()> {
        self.run_inner(StopRequest::Channel(stop), log)
    }

    /// Runs with a native stop signal, sleeping until a packet, timer, or Stop arrives.
    /// Performs the same protocol announcement and BGP cleanup as `run`.
    ///
    /// # Errors
    /// Returns receive, native wait, or BGP cleanup failures.
    pub fn run_until(&mut self, stop: &StopSignal, log: &mut Logger) -> io::Result<()> {
        self.run_inner(StopRequest::Event(stop), log)
    }

    fn run_inner(&mut self, stop: StopRequest<'_>, log: &mut Logger) -> io::Result<()> {
        let result = if self.reflector.is_some() {
            self.run_reflector(stop, log)
        } else {
            self.run_session(stop, log)
        };
        // Status is unavailable as soon as protocol processing exits, even while
        // bounded shutdown announcements or BGP cleanup are still running.
        self.status_publisher.close();
        // RFC 5880 section 6.8.16 and RFC 5882 section 8 recommend at least one
        // Detection Time. Measure both directions before AdminDown, then apply
        // the configured operational limit so a peer cannot delay Stop indefinitely.
        let grace = if result.is_ok()
            && self.options.session_type == SessionType::Classical
            && self.session.communicating()
        {
            self.session
                .detection_time()
                .max(self.session.peer_detection_time())
        } else {
            Duration::ZERO
        };
        let limit = Duration::from_millis(u64::from(self.options.max_shutdown_announce_ms));
        if grace > limit {
            log.service_warning(format_args!(
                "AdminDown announcement period {grace:?} exceeds MaxShutdownAnnounceMs; limiting it to {limit:?}. The peer may detect a failure before learning of this administrative stop"
            ));
        }
        let grace = grace.min(limit);
        self.shutdown_progress.record(grace);
        let previous = self.session.state;
        self.session.admin_down();
        // Local AdminDown releases any Stop that BFD imposed on BGP.
        self.state_changed(previous, log);
        self.report_suppressed_events(Instant::now(), true, log);
        let announcements = self.announce_shutdown(grace, log);
        // Finish the latest action, including a Start that releases BFD's Stop,
        // and propagate failure before completion.
        let shutdown = self.bgp.take().map_or(Ok(()), Controller::shutdown);
        self.state_publisher.close();
        result.and(announcements).and(shutdown)
    }

    fn announce_shutdown(&mut self, grace: Duration, log: &mut Logger) -> io::Result<()> {
        let mut datagram = Datagram::default();
        let mut last_error = None;
        let mut last_tx = Instant::now();
        if self.session.can_transmit() {
            self.transmit(Transmission::StateChange, log, &mut last_error);
        }
        let deadline = Instant::now() + grace;
        let mut next_tx = last_tx + self.session.jittered_interval();
        let mut last_discard = None;
        let mut last_auth_failure = None;
        while Instant::now() < deadline {
            let now = Instant::now();
            self.session.expire(now);
            if self.session.periodic_enabled() && now >= next_tx {
                self.transmit(Transmission::Periodic, log, &mut last_error);
                last_tx = now;
                next_tx = now + self.session.jittered_interval();
            }
            match self.transport.receive_into(&mut datagram) {
                Ok(()) => {
                    let interval = self.session.transmit_interval();
                    // AdminDown updates authenticated peer parameters without
                    // restarting detection or the local state machine.
                    let result = datagram
                        .validate(&self.options)
                        .map_err(ReceiveError::Packet)
                        .and_then(|()| self.session.receive_checked(&datagram.data, now));
                    if let Err(error) = result {
                        self.log_rejection(
                            &datagram,
                            error,
                            log,
                            &mut last_discard,
                            &mut last_auth_failure,
                        );
                    } else {
                        self.peer_report_changed(log);
                    }
                    if interval != self.session.transmit_interval() {
                        next_tx = last_tx + self.session.jittered_interval();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    let mut wait = deadline.saturating_duration_since(now);
                    if self.session.periodic_enabled() {
                        wait = wait.min(next_tx.saturating_duration_since(now));
                    }
                    if let Some(detection) = self.session.detection_deadline() {
                        wait = wait.min(detection.saturating_duration_since(now));
                    }
                    match self.transport.wait_readable(wait) {
                        Err(error) if is_transient(&error) => {
                            end_announcements(&error, log);
                            return Ok(());
                        }
                        result => result?,
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidData
                        || error.raw_os_error() == Some(10040) => {}
                // Announcements are best effort; a faulted path must not delay Stop.
                Err(error) if is_transient(&error) => {
                    end_announcements(&error, log);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn run_session(&mut self, stop: StopRequest<'_>, log: &mut Logger) -> io::Result<()> {
        let mut datagram = Datagram::default();
        let mut next_periodic_tx = Instant::now();
        let mut last_periodic_tx = None;
        let mut last_error = None;
        let mut last_discard = None;
        let mut last_auth_failure = None;
        let mut faults = SocketFaults::default();
        // Also applies any change made before the settings watch was armed.
        self.reload_sbfd_settings(log);
        let mut next_settings_poll = Instant::now() + Duration::from_secs(1);
        loop {
            if stop.is_requested() {
                break;
            }
            let now = Instant::now();
            let previous = self.session.state;
            let remote_discriminator = self.session.remote_discriminator;
            let communicating = self.session.communicating();
            let old_interval = self.session.transmit_interval();
            self.refresh_settings(now, &mut next_settings_poll, log);
            if self.session.state() != State::AdminDown
                && self
                    .session
                    .detection_deadline()
                    .is_some_and(|deadline| now >= deadline)
            {
                self.status_telemetry.detection_timeout();
            }
            let state_changed = self.session.expire(now);
            if communicating && !self.session.communicating() {
                self.last_peer_report = None;
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
            // Checked on every pass, before receive's flood-path `continue`.
            // Protocol expiry and required transmissions take precedence.
            // Transmissions above record a newer time than the loop's sample.
            self.publish_status(Instant::now());
            let before_interval = self.session.transmit_interval();
            let before_enabled = self.session.periodic_enabled();
            let mut fault = None;
            match self.transport.receive_into(&mut datagram) {
                Ok(()) => {
                    faults.recovered(log);
                    let received_at = Instant::now();
                    let previous = self.session.state;
                    let communicating = self.session.communicating();
                    let received = datagram
                        .validate(&self.options)
                        .map_err(ReceiveError::Packet)
                        .and_then(|()| self.session.receive_checked(&datagram.data, received_at));
                    match received {
                        Ok(result) => {
                            self.status_telemetry.received_session(
                                &self.session,
                                datagram.source,
                                received_at,
                            );
                            self.peer_report_changed(log);
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
                    self.status_telemetry
                        .rejected(RejectionReason::InvalidDatagram, now);
                    continue;
                }
                // Detection timers continue; an unusable path expires the session.
                Err(error) if is_transient(&error) => {
                    self.status_telemetry.socket_error(&error, now);
                    fault = Some(error);
                }
                Err(error) => {
                    self.status_telemetry.socket_error(&error, now);
                    return Err(error);
                }
            }
            let now = Instant::now();
            let mut wait = self.idle_wait(now, next_settings_poll);
            if self.session.periodic_enabled() {
                wait = wait.min(next_periodic_tx.saturating_duration_since(now));
            }
            if let Some(deadline) = self.session.detection_deadline() {
                wait = wait.min(deadline.saturating_duration_since(now));
            }
            match fault {
                Some(error) => faults.pause(stop, &error, wait, log)?,
                None => self.wait_for_traffic(stop, wait, &mut faults, log)?,
            }
        }
        Ok(())
    }
}

fn end_announcements(error: &io::Error, log: &mut Logger) {
    log.log(format_args!(
        "AdminDown announcements ended after a transient socket failure: {error}"
    ));
}

fn report_withheld(replies: &mut ReplyLimiter, log: &mut Logger) {
    log.service_warning(format_args!(
        "S-BFD reflector withheld {} replies to sources exceeding {REPLIES_PER_SOURCE} per second",
        std::mem::take(&mut replies.withheld)
    ));
}

/// Returns true, recording `now`, when `interval` has passed since the last true result.
fn due(last: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
    if last.is_none_or(|last| now.duration_since(last) >= interval) {
        *last = Some(now);
        true
    } else {
        false
    }
}

fn log_due(last: &mut Option<Instant>, now: Instant) -> bool {
    due(last, now, Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(miri))]
    use std::fs;

    #[cfg(not(miri))]
    #[test]
    fn periodic_transmissions_precede_their_status_capture() {
        let mut options = Options::new(
            "127.0.0.114".parse().unwrap(),
            "127.0.0.115".parse().unwrap(),
        );
        options.multihop = true;
        let mut log = Logger::new().unwrap();
        let mut engine = Engine::from_config(options.into_validated().unwrap(), &mut log).unwrap();
        let observer = engine.status_observer();
        let stop = StopSignal::new().unwrap();
        let snapshot = std::thread::scope(|scope| {
            let worker = scope.spawn(|| engine.run_until(&stop, &mut log));
            let deadline = Instant::now() + Duration::from_secs(5);
            let snapshot = loop {
                let snapshot = observer.snapshot();
                // The first send is coalesced into the initial publication. A
                // later periodic send can make a publication immediately due.
                if snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.packets_sent_successfully >= 2)
                {
                    break snapshot;
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            stop.signal().unwrap();
            worker.join().unwrap().unwrap();
            snapshot
        })
        .expect("engine did not publish two successful transmissions");
        assert!(
            snapshot.publication.sent.unwrap() <= snapshot.publication.captured,
            "publication capture precedes its successful transmission"
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn status_deadline_bounds_idle_wait_and_transitions_are_coalesced() {
        let options = Options::reflector("127.0.0.88".parse().unwrap(), 99)
            .into_validated()
            .unwrap();
        let mut log = Logger::new().unwrap();
        let mut engine = Engine::from_config(options, &mut log).unwrap();
        let observer = engine.status_observer();
        let original = observer.snapshot().unwrap();
        let created = engine
            .status_publisher
            .deadline(engine.status_telemetry.revision())
            - status::REFRESH_INTERVAL;
        let poll = created + Duration::from_secs(10);
        // An unchanged engine sleeps until the one-second refresh.
        assert_eq!(
            engine.idle_wait(created + Duration::from_millis(50), poll),
            Duration::from_millis(950)
        );
        // An unpublished change shortens the wait to the publication interval.
        engine.set_reflector_admin_down(true, &mut log);
        assert_eq!(
            engine.idle_wait(created + Duration::from_millis(50), poll),
            Duration::from_millis(50)
        );
        engine.publish_status(created + Duration::from_millis(99));
        assert!(Arc::ptr_eq(&original, &observer.snapshot().unwrap()));
        assert_eq!(engine.state_observer().current(), Some(State::AdminDown));
        let first = created + status::PUBLICATION_INTERVAL;
        engine.publish_status(first);
        assert_eq!(observer.snapshot().unwrap().local_state, State::AdminDown);
        let published = observer.snapshot().unwrap();
        // Changes inside one interval are coalesced into the next publication.
        engine.set_reflector_admin_down(false, &mut log);
        engine.publish_status(first + Duration::from_millis(99));
        assert!(Arc::ptr_eq(&published, &observer.snapshot().unwrap()));
        engine.publish_status(first + status::PUBLICATION_INTERVAL);
        assert_eq!(observer.snapshot().unwrap().local_state, State::Up);
        assert_eq!(original.local_state, State::Up);
        drop(engine);
        assert!(observer.snapshot().is_none());
    }

    #[cfg(not(miri))]
    #[test]
    fn notified_timing_change_retries_after_poll_without_another_notification() {
        let mut options = Options::new(
            "127.0.0.112".parse().unwrap(),
            "127.0.0.113".parse().unwrap(),
        );
        options.session_type = SessionType::SbfdInitiator;
        options.remote_discriminator = Some(99);
        options.discriminator = Some(7);
        options.registry_backed = true;
        let auth = options.validate().unwrap();
        let reflector = Reflector::new(Options::reflector(options.peer, 99), auth.clone()).unwrap();
        let mut log = Logger::new().unwrap();
        let mut engine = Engine::open(options, auth, &mut log).unwrap();
        let now = Instant::now();
        for step in 0..3 {
            let time = now + Duration::from_millis(step * 100);
            let request = engine.session.packet_at(false, time);
            engine
                .session
                .receive(&reflector.respond(&request).unwrap(), time)
                .unwrap();
        }
        let first = Timing::new(500_000, 300_000, 3).unwrap();
        let latest = Timing::new(700_000, 300_000, 3).unwrap();
        let mut retry_at = now;
        engine.refresh_settings_from(now, &mut retry_at, true, &mut log, |_| Ok((first, false)));
        let poll = engine
            .session
            .packet_at(false, now + Duration::from_millis(400));
        engine.refresh_settings_from(now, &mut retry_at, true, &mut log, |_| Ok((latest, false)));
        assert!(engine.settings_retry);
        assert_eq!(engine.timing, first);
        engine.refresh_settings_from(now, &mut retry_at, false, &mut log, |_| {
            panic!("retry must be paced")
        });
        engine
            .session
            .receive(
                &reflector.respond(&poll).unwrap(),
                now + Duration::from_millis(410),
            )
            .unwrap();
        let request = engine
            .session
            .packet_at(false, now + Duration::from_millis(500));
        engine
            .session
            .receive(
                &reflector.respond(&request).unwrap(),
                now + Duration::from_millis(510),
            )
            .unwrap();
        engine.refresh_settings_from(retry_at, &mut retry_at, false, &mut log, |_| {
            Ok((latest, false))
        });
        assert!(!engine.settings_retry);
        assert_eq!(engine.timing, latest);
        engine.refresh_settings_from(
            now + Duration::from_secs(5),
            &mut retry_at,
            false,
            &mut log,
            |_| panic!("successful notified settings must not resume polling"),
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn reflector_maintenance_and_shutdown_use_state_and_diagnostic_events() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::reflector("127.0.0.104".parse().unwrap(), 99);
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let auth = options.validate().unwrap();
        let mut log = Logger::open(&options).unwrap();
        let mut engine = Engine::open(options.clone(), auth, &mut log).unwrap();
        let observer = engine.state_observer();
        assert_eq!(observer.current(), Some(State::Up));
        engine.set_reflector_admin_down(true, &mut log);
        assert_eq!(observer.current(), Some(State::AdminDown));
        engine.set_reflector_admin_down(true, &mut log); // No duplicate event.
        engine.set_reflector_admin_down(false, &mut log);
        assert_eq!(observer.current(), Some(State::Up));
        let (stop, receiver) = std::sync::mpsc::channel();
        drop(stop);
        engine.run(&receiver, &mut log).unwrap();
        assert_eq!(observer.current(), None);
        log.flush(Duration::from_secs(2)).unwrap();
        let text = fs::read_to_string(&options.log_file_path).unwrap();
        assert_eq!(
            text.matches("event_id=106 level=Information").count(),
            2,
            "{text}"
        );
        assert_eq!(
            text.matches("event_id=207 level=Warning").count(),
            2,
            "{text}"
        );
        assert_eq!(
            text.matches("event_id=102 level=Information").count(),
            1,
            "{text}"
        );
        assert!(!text.contains("event_id=200"));
    }

    #[cfg(not(miri))]
    #[test]
    fn retained_failure_diagnostic_does_not_make_recovery_a_warning() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::new(
            "127.0.0.102".parse().unwrap(),
            "127.0.0.103".parse().unwrap(),
        );
        options.multihop = true;
        options.log_to_file = true;
        options.log_file_path = directory.path().join("trace.log");
        let auth = options.validate().unwrap();
        let mut log = Logger::open(&options).unwrap();
        let mut engine = Engine::open(options.clone(), auth, &mut log).unwrap();
        engine.session.diagnostic = Diagnostic::DetectionExpired;
        engine.state_changed(State::Up, &mut log);
        engine.session.state = State::Up;
        engine.state_changed(State::Down, &mut log);
        engine.state_changed(State::Up, &mut log);
        log.flush(Duration::from_secs(2)).unwrap();
        let text = fs::read_to_string(&options.log_file_path).unwrap();
        assert_eq!(
            text.matches("event_id=201 level=Warning").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches("event_id=102 level=Information").count(),
            1,
            "{text}"
        );
        assert!(text.contains("state=Up diagnostic=DetectionExpired"));
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

        options.log_to_file = true;
        options.log_file_path = blocked.join("trace.log");

        assert!(Logger::open(&options).is_err());
        assert_eq!(fs::read(blocked).unwrap(), b"existing contents");
    }

    #[test]
    fn socket_fault_retries_back_off_to_a_bounded_delay_and_reset_on_recovery() {
        let mut faults = SocketFaults::default();
        let delays: Vec<_> = (0..8).map(|_| faults.next_delay()).collect();
        assert_eq!(
            delays,
            [10, 20, 40, 80, 160, 250, 250, 250].map(Duration::from_millis)
        );
        assert_eq!(faults.count, 8);
        let mut log = Logger::new().unwrap();
        faults.recovered(&mut log);
        assert_eq!(faults.count, 0);
        assert_eq!(faults.next_delay(), FAULT_RETRY_MIN);
    }

    #[test]
    fn stop_only_pause_is_not_shortened_by_readable_sockets_and_ends_on_stop() {
        let stop = StopSignal::new().unwrap();
        let started = Instant::now();
        StopRequest::Event(&stop)
            .pause(Duration::from_millis(50))
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(45));
        stop.signal().unwrap();
        let started = Instant::now();
        StopRequest::Event(&stop)
            .pause(Duration::from_secs(5))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn session_events_are_bounded_per_second_and_suppression_is_reported_rarely() {
        let now = Instant::now();
        let mut budget = EventBudget::default();
        for _ in 0..EVENTS_PER_SECOND {
            assert!(budget.admit(now));
        }
        assert!(!budget.admit(now + Duration::from_millis(999)));
        assert!(!budget.admit(now + Duration::from_millis(999)));
        assert_eq!(budget.take_report(now, false), Some(2));
        assert!(!budget.admit(now + Duration::from_millis(999)));
        // Another report waits for the interval unless shutdown forces it.
        assert_eq!(
            budget.take_report(now + Duration::from_secs(1), false),
            None
        );
        assert!(budget.admit(now + Duration::from_secs(1)));
        assert_eq!(
            budget.take_report(now + Duration::from_secs(2), true),
            Some(1)
        );
        assert_eq!(budget.take_report(now + REPORT_INTERVAL * 2, true), None);
    }

    #[test]
    fn reflector_replies_are_limited_per_source_and_tracked_source_count() {
        let now = Instant::now();
        let mut limiter = ReplyLimiter::default();
        let victim: IpAddr = "192.0.2.10".parse().unwrap();
        for _ in 0..REPLIES_PER_SOURCE {
            assert!(limiter.admit(victim, now));
        }
        assert!(!limiter.admit(victim, now));
        assert!(limiter.admit("192.0.2.11".parse().unwrap(), now));
        assert_eq!(limiter.withheld, 1);
        assert!(limiter.admit(victim, now + Duration::from_secs(1)));

        let mut limiter = ReplyLimiter::default();
        for index in 0..TRACKED_SOURCES {
            let address = std::net::Ipv6Addr::from(u128::try_from(index).unwrap() + 1);
            assert!(limiter.admit(address.into(), now));
        }
        assert!(!limiter.admit(victim, now));
        assert!(limiter.admit(victim, now + Duration::from_secs(1)));
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
