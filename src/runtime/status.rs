//! Immutable administrative snapshots published without reader locks.
#![forbid(unsafe_code)]

use crate::{
    config::{Mode, SessionType, Timing, ValidatedOptions},
    error::{AuthError, PacketError},
    packet::{AuthType, Diagnostic, State},
    session::Session,
};
use arc_swap::ArcSwapOption;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    num::NonZeroU128,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

/// Minimum spacing between publications that carry new telemetry. Changes
/// are coalesced without allocating per packet; scheduling can delay publication.
pub(crate) const PUBLICATION_INTERVAL: Duration = Duration::from_millis(100);
/// Nominal refresh interval for an unchanged engine. Scheduling can delay it;
/// readers use capture age rather than treating the interval as a hard deadline.
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Rejection classification that contains no packet contents or key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// Structural, transport, or protocol validation failed.
    Packet(PacketError),
    /// Authentication failed before the session accepted the packet.
    Authentication(AuthError),
    /// The socket returned truncated data or invalid ancillary metadata.
    InvalidDatagram,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(reason) => reason.fmt(formatter),
            Self::Authentication(reason) => reason.fmt(formatter),
            Self::InvalidDatagram => formatter.write_str("invalid datagram or ancillary metadata"),
        }
    }
}

/// One coherent observation of BFD protocol state and non-secret configuration.
/// Counters belong to this engine instance and saturate at `u64::MAX`.
/// Optional peer/session fields are absent until observed or when inapplicable
/// to a stateless reflector. Peer reports remain historical after expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StatusSnapshot {
    /// Internal capture metadata is published atomically with the protocol view.
    pub(crate) publication: Publication,
    /// Configured local IP address bound by the BFD transport.
    pub local_address: IpAddr,
    /// Configured peer IP address; `None` for a stateless reflector.
    pub peer_address: Option<IpAddr>,
    /// Source IP address and UDP port of the last accepted packet; `None` before reception.
    pub last_accepted_source: Option<SocketAddr>,
    /// Configured Windows interface index; `None` when no interface is specified.
    pub interface_index: Option<u32>,
    /// Actual local UDP source port, including an automatically allocated port.
    pub local_source_port: u16,
    /// UDP destination/listen port selected by the protocol role and transport profile.
    pub control_port: u16,
    /// Classical session, S-BFD initiator, or stateless S-BFD reflector role.
    pub session_type: SessionType,
    /// Configured single-hop or multihop transport profile.
    pub transport_mode: Mode,
    /// True when the classical session waits for a validated peer packet before transmitting.
    pub passive: bool,
    /// True when a classical single-hop session identifies its neighbor by interface.
    pub point_to_point: bool,
    /// Configured additional S-BFD response sources or reflector source allowlist.
    pub allowed_peers: Arc<[IpAddr]>,
    /// Configured minimum received TTL/hop limit; `None` when unspecified.
    /// Classical single-hop packets separately require a value of 255.
    pub min_ttl: Option<u8>,
    /// Nonzero local session or reflector discriminator.
    pub local_discriminator: u32,
    /// Active learned classical discriminator or configured S-BFD target discriminator.
    /// `None` for reflectors and for classical peers whose identifier is unknown or expired.
    pub remote_discriminator: Option<u32>,
    /// Local protocol state, or reflector entity availability, at publication.
    pub local_state: State,
    /// Last accepted peer state, retained after expiry; `None` before reception or for reflectors.
    pub remote_state: Option<State>,
    /// Local protocol diagnostic at publication; classical recovery can retain a prior failure.
    pub local_diagnostic: Diagnostic,
    /// Last accepted peer diagnostic code, including reserved values, retained after expiry.
    /// `None` before reception or for stateless reflectors.
    pub remote_diagnostic: Option<u8>,
    /// True when a valid peer response is within the detection window; `None` for reflectors.
    pub communicating: Option<bool>,
    /// UTC time when the local state began, including the initial state at engine creation.
    pub state_since_utc: SystemTime,
    /// UTC time of the last transition to Up; `None` before such a transition.
    pub last_up_utc: Option<SystemTime>,
    /// UTC time of the last transition to Down or AdminDown; `None` before either transition.
    pub last_down_utc: Option<SystemTime>,
    /// Diagnostic recorded at the last Down/AdminDown transition; `None` before either transition.
    pub last_down_reason: Option<Diagnostic>,
    /// UTC time of the last accepted packet, retained after expiry; `None` before reception.
    pub last_valid_receive_utc: Option<SystemTime>,
    /// UTC time of the last successful packet send; `None` before a successful send.
    pub last_successful_send_utc: Option<SystemTime>,
    /// Active configured minimum transmit interval as a duration, before jitter.
    pub configured_min_tx_interval: Duration,
    /// Active configured minimum receive interval, or S-BFD initiator round-trip budget.
    pub configured_min_rx_interval: Duration,
    /// Configured transmit interval outside Up, before peer negotiation, backoff, and jitter.
    pub startup_tx_interval: Duration,
    /// Active local detection multiplier; `None` for reflectors, which copy each request's value.
    pub local_detect_multiplier: Option<u8>,
    /// Last accepted peer detection multiplier, retained after expiry.
    /// `None` before reception or for stateless reflectors.
    pub remote_detect_multiplier: Option<u8>,
    /// Last accepted peer minimum transmit duration, retained after expiry.
    /// `None` before reception or for stateless reflectors.
    pub remote_min_tx_interval: Option<Duration>,
    /// Last accepted peer minimum receive duration, retained after expiry; zero can suppress traffic.
    /// `None` before reception or for stateless reflectors.
    pub remote_min_rx_interval: Option<Duration>,
    /// Effective negotiated transmit duration, including backoff, before jitter.
    /// `None` for stateless reflectors.
    pub effective_tx_interval: Option<Duration>,
    /// Protocol detection duration under the active timing policy; `None` for reflectors.
    pub detection_time: Option<Duration>,
    /// True when the role and peer parameters permit periodic transmissions; false for reflectors.
    pub periodic_transmit_enabled: bool,
    /// True when a local Poll sequence awaits completion; `None` for stateless reflectors.
    pub poll_pending: Option<bool>,
    /// Accepted packet count, including reflector requests whose replies are withheld.
    pub packets_received_accepted: u64,
    /// Successful packet send count, including reflector replies and session notifications.
    pub packets_sent_successfully: u64,
    /// Total rejected packet count across authentication, malformed, protocol, and transport checks.
    pub packets_rejected: u64,
    /// Packet count rejected by authentication checks.
    pub authentication_failures: u64,
    /// Malformed packet or invalid/truncated datagram count.
    pub malformed_packets: u64,
    /// Packet count rejected by protocol role, state, or session-identifier checks.
    pub protocol_rejections: u64,
    /// Packet count rejected by source, destination, interface, port, or TTL/hop-limit checks.
    pub transport_validation_failures: u64,
    /// Count of send, receive, and socket-wait errors, excluding malformed datagrams.
    pub socket_errors: u64,
    /// Protocol detection-deadline expiry count, including S-BFD retries while Down.
    pub detection_timeouts: u64,
    /// Count of local transitions to Up; initial reflector availability does not count.
    pub up_transitions: u64,
    /// Accepted reflector requests withheld by the per-source reply limit; zero for other roles.
    pub replies_withheld: u64,
    /// Reason for the last rejected packet; `None` before a rejection.
    pub last_rejection_reason: Option<RejectionReason>,
    /// UTC time of the last rejected packet; `None` before a rejection.
    pub last_rejection_utc: Option<SystemTime>,
    /// Native Windows error code for the last socket error; `None` if absent or unavailable.
    pub last_socket_error_code: Option<i32>,
    /// UTC time of the last socket error; `None` before an error.
    pub last_socket_error_utc: Option<SystemTime>,
    /// Configured authentication mechanism; no key material is included.
    pub authentication_type: AuthType,
    /// Configured authentication key identifier; `None` when authentication is disabled.
    pub authentication_key_id: Option<u8>,
    /// UTC time of the last live configuration reload attempt; `None` before an attempt.
    pub last_configuration_reload_utc: Option<SystemTime>,
    /// Whether the last live configuration reload succeeded; `None` before an attempt.
    pub last_configuration_reload_succeeded: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Publication {
    pub(crate) instance: NonZeroU128,
    pub(crate) sequence: u64,
    pub(crate) started: Instant,
    pub(crate) captured: Instant,
    pub(crate) utc: SystemTime,
    pub(crate) received: Option<Instant>,
    pub(crate) sent: Option<Instant>,
}

/// Clonable read-only handle that cannot hold a lock on the BFD packet loop.
#[derive(Clone, Debug)]
pub struct StatusObserver {
    value: Arc<ArcSwapOption<StatusSnapshot>>,
}

impl StatusObserver {
    /// Returns an owned immutable snapshot, or `None` after engine shutdown/drop.
    /// Retaining the returned `Arc` never prevents another snapshot publication.
    pub fn snapshot(&self) -> Option<Arc<StatusSnapshot>> {
        self.value.load_full()
    }
}

/// Publishes changed telemetry at most every [`PUBLICATION_INTERVAL`]. Ordinary
/// updates use existing engine wakes, bounded by [`REFRESH_INTERVAL`]. Important
/// changes retain the earlier wake; readers never request a publication.
pub(crate) struct StatusPublisher {
    observer: StatusObserver,
    last_publish: Instant,
    published_revision: u64,
    closed: bool,
    sequence: u64,
}

impl StatusPublisher {
    pub(crate) fn new(mut snapshot: StatusSnapshot, revision: u64, now: Instant) -> Self {
        snapshot.publication.sequence = 1;
        snapshot.publication.captured = now;
        Self {
            observer: StatusObserver {
                value: Arc::new(ArcSwapOption::from(Some(Arc::new(snapshot)))),
            },
            last_publish: now,
            published_revision: revision,
            closed: false,
            sequence: 1,
        }
    }

    pub(crate) fn observer(&self) -> StatusObserver {
        self.observer.clone()
    }

    /// Returns the earliest eligible publication time for this revision.
    /// Eligibility alone does not require a separate packet-loop wake.
    pub(crate) fn deadline(&self, revision: u64) -> Instant {
        self.last_publish
            + if revision == self.published_revision {
                REFRESH_INTERVAL
            } else {
                PUBLICATION_INTERVAL
            }
    }

    /// Ordinary counters can wait for protocol work, but must not postpone the
    /// refresh. State/configuration changes retain the shorter publication wake.
    pub(crate) fn wake_deadline(&self, priority_change: bool) -> Instant {
        self.last_publish
            + if priority_change {
                PUBLICATION_INTERVAL
            } else {
                REFRESH_INTERVAL
            }
    }

    pub(crate) fn is_due(&self, revision: u64, now: Instant) -> bool {
        !self.closed && now >= self.deadline(revision)
    }

    pub(crate) fn publish(
        &mut self,
        mut snapshot: StatusSnapshot,
        revision: u64,
        now: Instant,
    ) -> bool {
        if !self.is_due(revision, now) {
            return false;
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        snapshot.publication.sequence = self.sequence;
        snapshot.publication.captured = now;
        // Refreshes carry new capture metadata even when protocol values match.
        self.observer.value.store(Some(Arc::new(snapshot)));
        // Skip missed periods: an engine delayed by scheduling publishes once,
        // then waits another full interval rather than allocating catch-up bursts.
        self.last_publish = now;
        self.published_revision = revision;
        true
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.observer.value.store(None);
    }
}

impl Drop for StatusPublisher {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerReport {
    discriminator: u32,
    state: State,
    diagnostic: u8,
    min_tx_us: u32,
    min_rx_us: u32,
    detect_mult: u8,
}

/// Packet activity records a monotonic time without sampling the wall clock.
/// Publication resolves pending UTC values and preserves resolved history.
#[derive(Clone, Copy)]
struct RecordedTime {
    instant: Instant,
    utc: Option<SystemTime>,
}

impl RecordedTime {
    fn pending(instant: Instant) -> Self {
        Self { instant, utc: None }
    }

    fn calibrated(&self, now: Instant, utc: SystemTime) -> SystemTime {
        self.utc.unwrap_or_else(|| {
            if self.instant <= now {
                utc.checked_sub(now.duration_since(self.instant))
                    .unwrap_or(utc)
            } else {
                utc.checked_add(self.instant.duration_since(now))
                    .unwrap_or(utc)
            }
        })
    }

    fn resolve(&mut self, now: Instant, utc: SystemTime) {
        if self.utc.is_none() {
            self.utc = Some(self.calibrated(now, utc));
        }
    }
}

/// Single-owner telemetry. Packet processing changes only scalars and existing
/// monotonic clock samples; allocation and UTC conversion occur at publication.
/// Every recorded event advances `revision`, which schedules the next publication.
pub(crate) struct StatusTelemetry {
    instance: NonZeroU128,
    started: Instant,
    revision: u64,
    priority_change: bool,
    anchor: Instant,
    anchor_utc: SystemTime,
    allowed_peers: Arc<[IpAddr]>,
    state_since: RecordedTime,
    last_up: Option<RecordedTime>,
    last_down: Option<RecordedTime>,
    last_down_reason: Option<Diagnostic>,
    last_received: Option<RecordedTime>,
    last_sent: Option<RecordedTime>,
    last_source: Option<SocketAddr>,
    peer_report: Option<PeerReport>,
    packets_received_accepted: u64,
    packets_sent_successfully: u64,
    packets_rejected: u64,
    authentication_failures: u64,
    malformed_packets: u64,
    protocol_rejections: u64,
    transport_validation_failures: u64,
    socket_errors: u64,
    detection_timeouts: u64,
    up_transitions: u64,
    replies_withheld: u64,
    last_rejection_reason: Option<RejectionReason>,
    last_rejection: Option<RecordedTime>,
    last_socket_error_code: Option<i32>,
    last_socket_error: Option<RecordedTime>,
    last_configuration_reload: Option<RecordedTime>,
    last_configuration_reload_succeeded: Option<bool>,
}

impl StatusTelemetry {
    pub(crate) fn new(now: Instant, utc: SystemTime, options: &ValidatedOptions) -> Self {
        Self {
            instance: NonZeroU128::new(rand::random()).unwrap_or(NonZeroU128::MIN),
            started: now,
            revision: 0,
            priority_change: false,
            anchor: now,
            anchor_utc: utc,
            allowed_peers: Arc::from(options.allowed_peers.as_slice()),
            state_since: RecordedTime {
                instant: now,
                utc: Some(utc),
            },
            last_up: None,
            last_down: None,
            last_down_reason: None,
            last_received: None,
            last_sent: None,
            last_source: None,
            peer_report: None,
            packets_received_accepted: 0,
            packets_sent_successfully: 0,
            packets_rejected: 0,
            authentication_failures: 0,
            malformed_packets: 0,
            protocol_rejections: 0,
            transport_validation_failures: 0,
            socket_errors: 0,
            detection_timeouts: 0,
            up_transitions: 0,
            replies_withheld: 0,
            last_rejection_reason: None,
            last_rejection: None,
            last_socket_error_code: None,
            last_socket_error: None,
            last_configuration_reload: None,
            last_configuration_reload_succeeded: None,
        }
    }

    fn utc(&self, time: RecordedTime) -> SystemTime {
        time.calibrated(self.anchor, self.anchor_utc)
    }

    /// Identifies the recorded events; it changes whenever a snapshot would.
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn priority_change(&self) -> bool {
        self.priority_change
    }

    /// A protocol/administrative change needs the shorter publication wake.
    /// This flag never changes a BFD transmission or detection deadline.
    pub(crate) fn prioritize(&mut self) {
        self.changed();
        self.priority_change = true;
    }

    /// Only the engine owner clears priority after storing a coherent snapshot.
    pub(crate) fn published(&mut self) {
        self.priority_change = false;
    }

    fn changed(&mut self) {
        // Only equality matters, so wrapping cannot hide a change in practice.
        self.revision = self.revision.wrapping_add(1);
    }

    /// Resolve newly recorded event times using one wall-clock observation per
    /// publication. A later clock correction never rewrites resolved history.
    pub(crate) fn calibrate(&mut self, now: Instant, utc: SystemTime) {
        self.anchor = now;
        self.anchor_utc = utc;
        self.state_since.resolve(now, utc);
        for time in [
            self.last_up.as_mut(),
            self.last_down.as_mut(),
            self.last_received.as_mut(),
            self.last_sent.as_mut(),
            self.last_rejection.as_mut(),
            self.last_socket_error.as_mut(),
            self.last_configuration_reload.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            time.resolve(now, utc);
        }
    }

    pub(crate) fn received(&mut self, source: SocketAddr, now: Instant) {
        self.changed();
        if self.last_source != Some(source) {
            self.prioritize();
        }
        self.packets_received_accepted = self.packets_received_accepted.saturating_add(1);
        self.last_received = Some(RecordedTime::pending(now));
        self.last_source = Some(source);
    }

    pub(crate) fn received_session(&mut self, session: &Session, source: SocketAddr, now: Instant) {
        self.received(source, now);
        let (min_tx_us, min_rx_us, detect_mult) = session.remote_timing();
        let report = PeerReport {
            discriminator: session.remote_discriminator(),
            state: session.remote_state(),
            diagnostic: session.remote_diagnostic(),
            min_tx_us,
            min_rx_us,
            detect_mult,
        };
        if self.peer_report != Some(report) {
            self.prioritize();
        }
        self.peer_report = Some(report);
    }

    pub(crate) fn sent(&mut self, now: Instant) {
        self.changed();
        self.packets_sent_successfully = self.packets_sent_successfully.saturating_add(1);
        self.last_sent = Some(RecordedTime::pending(now));
    }

    pub(crate) fn transition(&mut self, state: State, diagnostic: Diagnostic, now: Instant) {
        self.prioritize();
        self.state_since = RecordedTime::pending(now);
        match state {
            State::Up => {
                self.last_up = Some(RecordedTime::pending(now));
                self.up_transitions = self.up_transitions.saturating_add(1);
            }
            State::Down | State::AdminDown => {
                self.last_down = Some(RecordedTime::pending(now));
                self.last_down_reason = Some(diagnostic);
            }
            State::Init => {}
        }
    }

    pub(crate) fn withheld(&mut self) {
        self.changed();
        self.replies_withheld = self.replies_withheld.saturating_add(1);
    }

    pub(crate) fn detection_timeout(&mut self) {
        self.prioritize();
        self.detection_timeouts = self.detection_timeouts.saturating_add(1);
    }

    pub(crate) fn rejected(&mut self, reason: RejectionReason, now: Instant) {
        self.changed();
        self.packets_rejected = self.packets_rejected.saturating_add(1);
        self.last_rejection_reason = Some(reason);
        self.last_rejection = Some(RecordedTime::pending(now));
        match reason {
            RejectionReason::Authentication(_) => {
                self.authentication_failures = self.authentication_failures.saturating_add(1)
            }
            RejectionReason::InvalidDatagram => {
                self.malformed_packets = self.malformed_packets.saturating_add(1)
            }
            RejectionReason::Packet(reason) => {
                use PacketError::*;
                let counter = match reason {
                    UnexpectedPeer
                    | SourcePort
                    | InvalidSeamlessSource
                    | SeamlessResponsePort
                    | DisallowedResponse
                    | SeamlessRequestPort
                    | DisallowedRequest
                    | WrongDestination
                    | WrongInterface
                    | MissingTtl
                    | SingleHopTtl
                    | MinimumTtl => &mut self.transport_validation_failures,
                    TruncatedHeader
                    | UnsupportedVersion
                    | InvalidLength
                    | ZeroDetectMultiplier
                    | UnsupportedMultipoint
                    | PollAndFinal
                    | ZeroSenderDiscriminator
                    | ZeroReceiverDiscriminator
                    | ZeroDesiredTx => &mut self.malformed_packets,
                    _ => &mut self.protocol_rejections,
                };
                *counter = counter.saturating_add(1);
            }
        }
    }

    pub(crate) fn socket_error(&mut self, error: &io::Error, now: Instant) {
        self.changed();
        if self.last_socket_error.is_none() || self.last_socket_error_code != error.raw_os_error() {
            self.prioritize();
        }
        self.socket_errors = self.socket_errors.saturating_add(1);
        self.last_socket_error_code = error.raw_os_error();
        self.last_socket_error = Some(RecordedTime::pending(now));
    }

    pub(crate) fn configuration_reload(&mut self, succeeded: bool, now: Instant) {
        self.prioritize();
        self.last_configuration_reload = Some(RecordedTime::pending(now));
        self.last_configuration_reload_succeeded = Some(succeeded);
    }

    pub(crate) fn snapshot(
        &self,
        session: &Session,
        options: &ValidatedOptions,
        timing: Timing,
        source_port: u16,
    ) -> StatusSnapshot {
        let reflector = options.session_type == SessionType::SbfdReflector;
        let peer = self.peer_report;
        StatusSnapshot {
            publication: Publication {
                instance: self.instance,
                sequence: 0,
                started: self.started,
                captured: self.anchor,
                utc: self.anchor_utc,
                received: self.last_received.map(|time| time.instant),
                sent: self.last_sent.map(|time| time.instant),
            },
            local_address: options.local,
            peer_address: (!reflector).then_some(options.peer),
            last_accepted_source: self.last_source,
            interface_index: options.interface_index,
            local_source_port: source_port,
            control_port: options.control_port(),
            session_type: options.session_type,
            transport_mode: options.mode,
            passive: options.passive,
            point_to_point: options.point_to_point,
            allowed_peers: Arc::clone(&self.allowed_peers),
            min_ttl: options.min_ttl,
            local_discriminator: session.local_discriminator(),
            remote_discriminator: (!reflector && session.remote_discriminator() != 0)
                .then(|| session.remote_discriminator()),
            local_state: session.state(),
            remote_state: peer.map(|report| report.state),
            local_diagnostic: session.diagnostic(),
            remote_diagnostic: peer.map(|report| report.diagnostic),
            communicating: (!reflector).then(|| session.communicating()),
            state_since_utc: self.utc(self.state_since),
            last_up_utc: self.last_up.map(|time| self.utc(time)),
            last_down_utc: self.last_down.map(|time| self.utc(time)),
            last_down_reason: self.last_down_reason,
            last_valid_receive_utc: self.last_received.map(|time| self.utc(time)),
            last_successful_send_utc: self.last_sent.map(|time| self.utc(time)),
            configured_min_tx_interval: Duration::from_micros(u64::from(timing.min_tx_us)),
            configured_min_rx_interval: Duration::from_micros(u64::from(timing.min_rx_us)),
            startup_tx_interval: Duration::from_micros(u64::from(options.startup_tx_us)),
            local_detect_multiplier: (!reflector).then_some(timing.detect_mult),
            remote_detect_multiplier: peer.map(|report| report.detect_mult),
            remote_min_tx_interval: peer
                .map(|report| Duration::from_micros(u64::from(report.min_tx_us))),
            remote_min_rx_interval: peer
                .map(|report| Duration::from_micros(u64::from(report.min_rx_us))),
            effective_tx_interval: (!reflector).then(|| session.transmit_interval()),
            detection_time: (!reflector).then(|| session.detection_time()),
            periodic_transmit_enabled: session.periodic_enabled(),
            poll_pending: (!reflector).then(|| session.polling()),
            packets_received_accepted: self.packets_received_accepted,
            packets_sent_successfully: self.packets_sent_successfully,
            packets_rejected: self.packets_rejected,
            authentication_failures: self.authentication_failures,
            malformed_packets: self.malformed_packets,
            protocol_rejections: self.protocol_rejections,
            transport_validation_failures: self.transport_validation_failures,
            socket_errors: self.socket_errors,
            detection_timeouts: self.detection_timeouts,
            up_transitions: self.up_transitions,
            replies_withheld: self.replies_withheld,
            last_rejection_reason: self.last_rejection_reason,
            last_rejection_utc: self.last_rejection.map(|time| self.utc(time)),
            last_socket_error_code: self.last_socket_error_code,
            last_socket_error_utc: self.last_socket_error.map(|time| self.utc(time)),
            authentication_type: options.auth,
            authentication_key_id: (options.auth != AuthType::None).then_some(options.auth_key_id),
            last_configuration_reload_utc: self
                .last_configuration_reload
                .map(|time| self.utc(time)),
            last_configuration_reload_succeeded: self.last_configuration_reload_succeeded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Options,
        packet::{test_packet, AuthConfig, AuthType},
        session::Session,
    };

    fn fixture() -> (ValidatedOptions, Session, StatusTelemetry, Instant) {
        let mut options =
            Options::new("127.0.0.80".parse().unwrap(), "127.0.0.81".parse().unwrap());
        options.multihop = true;
        options.discriminator = Some(7);
        let options = options.into_validated().unwrap();
        let session = Session::from_config(options.clone());
        let now = Instant::now();
        let telemetry = StatusTelemetry::new(
            now,
            SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            &options,
        );
        (options, session, telemetry, now)
    }

    #[test]
    fn changes_publish_after_100_ms_and_unchanged_views_refresh_each_second_without_bursts() {
        let (options, session, mut telemetry, now) = fixture();
        let view = |telemetry: &StatusTelemetry| {
            telemetry.snapshot(&session, &options, options.timing(), 52001)
        };
        let mut publisher = StatusPublisher::new(view(&telemetry), telemetry.revision(), now);
        let observer = publisher.observer();
        let original = observer.snapshot().unwrap();
        assert_eq!(PUBLICATION_INTERVAL, Duration::from_millis(100));
        assert_eq!(REFRESH_INTERVAL, Duration::from_secs(1));
        assert_eq!(
            publisher.deadline(telemetry.revision()),
            now + REFRESH_INTERVAL
        );

        // Changes wait for the publication interval rather than allocating per packet.
        for milliseconds in 0..100 {
            let at = now + Duration::from_millis(milliseconds);
            telemetry.sent(at);
            assert!(!publisher.publish(view(&telemetry), telemetry.revision(), at));
            assert!(Arc::ptr_eq(&original, &observer.snapshot().unwrap()));
        }
        let revision = telemetry.revision();
        let changed = now + PUBLICATION_INTERVAL;
        assert_eq!(publisher.deadline(revision), changed);
        assert!(publisher.publish(view(&telemetry), revision, changed));
        let updated = observer.snapshot().unwrap();
        assert_eq!(updated.packets_sent_successfully, 100);
        assert_eq!(original.packets_sent_successfully, 0);

        // Without new events the next publication is the one-second refresh,
        // which stores a new immutable snapshot with unchanged values.
        assert_eq!(publisher.deadline(revision), changed + REFRESH_INTERVAL);
        let before_refresh = changed + REFRESH_INTERVAL - Duration::from_millis(1);
        assert!(!publisher.publish(view(&telemetry), revision, before_refresh));
        assert!(publisher.publish(view(&telemetry), revision, changed + REFRESH_INTERVAL));
        let refreshed = observer.snapshot().unwrap();
        assert!(!Arc::ptr_eq(&updated, &refreshed));
        assert_eq!(updated.local_state, refreshed.local_state);
        assert_eq!(
            updated.packets_sent_successfully,
            refreshed.packets_sent_successfully
        );
        assert_ne!(updated.publication.sequence, refreshed.publication.sequence);
        assert_eq!(updated.publication.instance, refreshed.publication.instance);

        // A delayed engine publishes once, then waits a full interval.
        let late = changed + Duration::from_secs(10);
        telemetry.sent(late);
        assert!(publisher.publish(view(&telemetry), telemetry.revision(), late));
        assert!(!publisher.publish(view(&telemetry), telemetry.revision(), late));
        telemetry.sent(late);
        assert_eq!(
            publisher.deadline(telemetry.revision()),
            late + PUBLICATION_INTERVAL
        );
    }

    #[test]
    fn routine_packets_do_not_request_wakes_but_peer_and_state_changes_do() {
        let (_, mut session, mut telemetry, now) = fixture();
        let source = "127.0.0.81:52002".parse().unwrap();
        telemetry.received_session(&session, source, now);
        assert!(telemetry.priority_change());
        telemetry.published();
        let revision = telemetry.revision();
        telemetry.received_session(&session, source, now);
        telemetry.sent(now);
        telemetry.withheld();
        telemetry.rejected(RejectionReason::InvalidDatagram, now);
        assert_ne!(telemetry.revision(), revision);
        assert!(!telemetry.priority_change());

        let new_source = "127.0.0.81:52003".parse().unwrap();
        telemetry.received_session(&session, new_source, now);
        assert!(telemetry.priority_change());
        telemetry.published();
        session.remote_discriminator = 77;
        telemetry.received_session(&session, new_source, now);
        assert!(telemetry.priority_change());
        telemetry.published();

        telemetry.transition(State::Up, Diagnostic::None, now);
        assert!(telemetry.priority_change());
        telemetry.published();
        telemetry.detection_timeout();
        assert!(telemetry.priority_change());
        telemetry.published();
        telemetry.configuration_reload(true, now);
        assert!(telemetry.priority_change());
        telemetry.published();
        let error = io::Error::from_raw_os_error(10051);
        telemetry.socket_error(&error, now);
        assert!(telemetry.priority_change());
        telemetry.published();
        telemetry.socket_error(&error, now);
        assert!(!telemetry.priority_change());
        telemetry.socket_error(&io::Error::from_raw_os_error(10050), now);
        assert!(telemetry.priority_change());
    }

    #[test]
    fn every_recorded_event_advances_the_revision_but_publication_work_does_not() {
        let (options, session, mut telemetry, now) = fixture();
        let mut revision = telemetry.revision();
        let mut assert_changed = |telemetry: &StatusTelemetry, event: &str| {
            assert_ne!(
                telemetry.revision(),
                revision,
                "{event} must schedule publication"
            );
            revision = telemetry.revision();
        };
        let source = "127.0.0.81:52002".parse().unwrap();
        telemetry.received(source, now);
        assert_changed(&telemetry, "received");
        telemetry.received_session(&session, source, now);
        assert_changed(&telemetry, "received_session");
        telemetry.sent(now);
        assert_changed(&telemetry, "sent");
        telemetry.transition(State::Up, Diagnostic::None, now);
        assert_changed(&telemetry, "transition");
        telemetry.withheld();
        assert_changed(&telemetry, "withheld");
        telemetry.detection_timeout();
        assert_changed(&telemetry, "detection_timeout");
        telemetry.rejected(RejectionReason::InvalidDatagram, now);
        assert_changed(&telemetry, "rejected");
        telemetry.socket_error(&io::Error::from_raw_os_error(10051), now);
        assert_changed(&telemetry, "socket_error");
        telemetry.configuration_reload(true, now);
        assert_changed(&telemetry, "configuration_reload");
        telemetry.calibrate(now, SystemTime::now());
        let _ = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            telemetry.revision(),
            revision,
            "publication must not reschedule itself"
        );
        telemetry.revision = u64::MAX;
        telemetry.sent(now);
        assert_eq!(
            telemetry.revision(),
            0,
            "the revision wraps instead of overflowing"
        );
    }

    #[test]
    #[ignore = "measurement; run with: cargo test-release --lib publication_cost -- --ignored --nocapture"]
    fn publication_cost_on_the_engine_thread_is_bounded() {
        let (options, session, mut telemetry, now) = fixture();
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
        let mut publisher = StatusPublisher::new(snapshot, telemetry.revision(), now);
        let observer = publisher.observer();
        let running = std::sync::atomic::AtomicBool::new(true);
        const ROUNDS: u32 = 200_000;
        let elapsed = std::thread::scope(|scope| {
            // Readers retain snapshots independently of the publisher.
            for _ in 0..4 {
                let observer = observer.clone();
                let running = &running;
                scope.spawn(move || {
                    while running.load(std::sync::atomic::Ordering::Relaxed) {
                        std::hint::black_box(observer.snapshot());
                    }
                });
            }
            let started = Instant::now();
            for round in 1..=ROUNDS {
                // Exactly the engine's due-path work: calibrate, build, store.
                let at = now + PUBLICATION_INTERVAL * round;
                telemetry.sent(at);
                telemetry.calibrate(at, SystemTime::now());
                let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
                assert!(publisher.publish(
                    std::hint::black_box(snapshot),
                    telemetry.revision(),
                    at
                ));
            }
            let elapsed = started.elapsed();
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            elapsed
        });
        let each = elapsed / ROUNDS;
        println!(
            "PUBLICATION_COST: {each:?} per snapshot; {:?} per second at 100 ms",
            each * 10
        );
        assert!(
            each < Duration::from_micros(100),
            "publication took {each:?}"
        );
    }

    #[test]
    fn close_and_drop_clear_availability_but_retained_snapshots_remain_readable() {
        let (options, session, telemetry, now) = fixture();
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
        let mut publisher = StatusPublisher::new(snapshot.clone(), 0, now);
        let observer = publisher.observer();
        let retained = observer.snapshot().unwrap();
        publisher.close();
        assert!(observer.snapshot().is_none());
        assert!(!publisher.publish(snapshot, 1, now + Duration::from_secs(1)));
        assert_eq!(retained.local_state, State::Down);
        let publisher = StatusPublisher::new((*retained).clone(), 0, now);
        let observer = publisher.observer();
        drop(publisher);
        assert!(observer.snapshot().is_none());
    }

    #[test]
    fn rejected_packets_do_not_refresh_valid_communication_and_expiry_keeps_history() {
        let (options, mut session, mut telemetry, now) = fixture();
        let peer = test_packet(State::Init);
        let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        session.receive(&peer.encode(&auth, 0), now).unwrap();
        telemetry.received_session(&session, "127.0.0.81:52002".parse().unwrap(), now);
        telemetry.transition(session.state(), session.diagnostic(), now);
        telemetry.rejected(
            RejectionReason::Authentication(AuthError::DigestMismatch),
            now + Duration::from_millis(10),
        );
        telemetry.rejected(
            RejectionReason::Packet(PacketError::WrongInterface),
            now + Duration::from_millis(20),
        );
        let expiry = session.detection_deadline().unwrap();
        assert!(session.expire(expiry));
        telemetry.detection_timeout();
        telemetry.transition(session.state(), session.diagnostic(), expiry);
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(snapshot.local_state, State::Down);
        assert_eq!(snapshot.remote_state, Some(State::Init));
        assert_eq!(snapshot.remote_discriminator, None);
        assert_eq!(
            snapshot.remote_min_rx_interval,
            Some(Duration::from_micros(u64::from(peer.required_min_rx_us)))
        );
        assert_eq!(
            snapshot.last_valid_receive_utc,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(100))
        );
        assert_eq!(
            snapshot.last_accepted_source,
            Some("127.0.0.81:52002".parse().unwrap())
        );
        assert_eq!(snapshot.communicating, Some(false));
        assert_eq!(
            snapshot.last_down_reason,
            Some(Diagnostic::DetectionExpired)
        );
        assert_eq!(snapshot.packets_received_accepted, 1);
        assert_eq!(snapshot.packets_rejected, 2);
        assert_eq!(snapshot.authentication_failures, 1);
        assert_eq!(snapshot.transport_validation_failures, 1);
        assert_eq!(snapshot.up_transitions, 1);
        assert_eq!(snapshot.detection_timeouts, 1);
    }

    #[test]
    fn reflector_has_no_peer_session_state_or_detection_timers() {
        let options = Options::reflector("127.0.0.82".parse().unwrap(), 99)
            .into_validated()
            .unwrap();
        let session = Session::from_config(options.clone());
        let now = Instant::now();
        let mut telemetry = StatusTelemetry::new(now, SystemTime::UNIX_EPOCH, &options);
        telemetry.received("127.0.0.83:52002".parse().unwrap(), now);
        telemetry.sent(now);
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 7784);
        assert_eq!(snapshot.local_state, State::Up);
        assert_eq!(snapshot.peer_address, None);
        assert_eq!(snapshot.remote_state, None);
        assert_eq!(snapshot.remote_discriminator, None);
        assert_eq!(snapshot.remote_detect_multiplier, None);
        assert_eq!(snapshot.local_detect_multiplier, None);
        assert_eq!(snapshot.remote_min_tx_interval, None);
        assert_eq!(snapshot.remote_min_rx_interval, None);
        assert_eq!(snapshot.communicating, None);
        assert_eq!(snapshot.effective_tx_interval, None);
        assert_eq!(snapshot.detection_time, None);
        assert_eq!(snapshot.poll_pending, None);
        assert!(!snapshot.periodic_transmit_enabled);
        assert_eq!(snapshot.packets_received_accepted, 1);
        assert_eq!(snapshot.packets_sent_successfully, 1);
    }

    #[test]
    fn counters_saturate_and_rejections_preserve_their_category() {
        let (_, _, mut telemetry, now) = fixture();
        telemetry.packets_rejected = u64::MAX;
        telemetry.authentication_failures = u64::MAX;
        telemetry.packets_sent_successfully = u64::MAX;
        telemetry.rejected(RejectionReason::Authentication(AuthError::Required), now);
        telemetry.sent(now);
        assert_eq!(telemetry.packets_rejected, u64::MAX);
        assert_eq!(telemetry.authentication_failures, u64::MAX);
        assert_eq!(telemetry.packets_sent_successfully, u64::MAX);
        telemetry.rejected(RejectionReason::InvalidDatagram, now);
        telemetry.rejected(
            RejectionReason::Packet(PacketError::WrongDiscriminator),
            now,
        );
        assert_eq!(telemetry.malformed_packets, 1);
        assert_eq!(telemetry.protocol_rejections, 1);
    }

    #[test]
    fn active_timing_reload_and_socket_failures_are_reported_without_secrets() {
        let mut options =
            Options::new("127.0.0.84".parse().unwrap(), "127.0.0.85".parse().unwrap());
        options.session_type = SessionType::SbfdInitiator;
        options.remote_discriminator = Some(99);
        options.auth = AuthType::MeticulousSha1;
        options.auth_key_id = 9;
        options.auth_key = Some("status-secret-key".into());
        let options = options.into_validated().unwrap();
        let mut session = Session::from_config(options.clone());
        let now = Instant::now();
        let mut telemetry = StatusTelemetry::new(now, SystemTime::UNIX_EPOCH, &options);
        let timing = Timing::new(500_000, 300_000, 4).unwrap();
        session.set_timing(timing).unwrap();
        telemetry.configuration_reload(true, now + Duration::from_millis(100));
        telemetry.socket_error(
            &io::Error::from_raw_os_error(10051),
            now + Duration::from_millis(200),
        );
        let snapshot = telemetry.snapshot(&session, &options, timing, 52001);
        assert_eq!(snapshot.remote_discriminator, Some(99));
        assert_eq!(snapshot.authentication_type, AuthType::MeticulousSha1);
        assert_eq!(snapshot.authentication_key_id, Some(9));
        assert_eq!(
            snapshot.configured_min_tx_interval,
            Duration::from_millis(500)
        );
        assert_eq!(
            snapshot.configured_min_rx_interval,
            Duration::from_millis(300)
        );
        assert_eq!(snapshot.local_detect_multiplier, Some(4));
        assert_eq!(snapshot.last_configuration_reload_succeeded, Some(true));
        assert_eq!(
            snapshot.last_configuration_reload_utc,
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(100))
        );
        assert_eq!(snapshot.last_socket_error_code, Some(10051));
        assert_eq!(snapshot.socket_errors, 1);
        let text = format!("{snapshot:?}");
        assert!(!text.contains("status-secret-key"));
        for omitted in [
            "snapshot_age",
            "receive_age_at_capture",
            "publish_interval",
            "bgp_control_enabled",
            "captured_at_utc",
            "schema_version",
            "service_status",
            "auth_key_hex",
        ] {
            assert!(!text.contains(omitted), "unexpected public field {omitted}");
        }
    }

    #[test]
    fn initiator_maintenance_snapshot_honors_the_one_second_transmit_floor() {
        let mut options =
            Options::new("127.0.0.89".parse().unwrap(), "127.0.0.90".parse().unwrap());
        options.session_type = SessionType::SbfdInitiator;
        options.discriminator = Some(7);
        options.remote_discriminator = Some(99);
        options.min_tx_us = 100_000;
        options.min_rx_us = 100_000;
        let options = options.into_validated().unwrap();
        let mut session = Session::from_config(options.clone());
        let reflector_options = Options::reflector(options.peer, 99)
            .into_validated()
            .unwrap();
        let mut reflector = crate::seamless::Reflector::from_config(&reflector_options).unwrap();
        let now = Instant::now();
        let mut telemetry = StatusTelemetry::new(now, SystemTime::UNIX_EPOCH, &options);
        let request = session.packet_at(false, now);
        session
            .receive(&reflector.respond(&request).unwrap(), now)
            .unwrap();
        assert_eq!(session.state(), State::Up);
        reflector.set_admin_down(true);
        let received_at = now + Duration::from_millis(10);
        let request = session.packet_at(false, received_at);
        session
            .receive(&reflector.respond(&request).unwrap(), received_at)
            .unwrap();
        telemetry.received_session(
            &session,
            options.address(options.peer, options.control_port()),
            received_at,
        );
        let detection_time = session.detection_time();
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(snapshot.remote_state, Some(State::AdminDown));
        assert_eq!(snapshot.local_state, State::Down);
        assert_eq!(snapshot.effective_tx_interval, Some(Duration::from_secs(1)));
        assert_eq!(snapshot.detection_time, Some(detection_time));
        for _ in 0..100 {
            assert!(session.jittered_interval() >= Duration::from_secs(1));
        }
    }

    #[test]
    fn publication_clock_corrections_update_new_events_and_preserve_history() {
        let (options, session, mut telemetry, now) = fixture();
        let start_utc = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        telemetry.received(
            "127.0.0.81:52002".parse().unwrap(),
            now + Duration::from_millis(500),
        );
        telemetry.calibrate(
            now + Duration::from_secs(1),
            start_utc + Duration::from_secs(1),
        );
        let first = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            first.last_valid_receive_utc,
            Some(start_utc + Duration::from_millis(500))
        );

        // A forward correction while idle must not rewrite the published event.
        telemetry.calibrate(
            now + Duration::from_secs(2),
            start_utc + Duration::from_secs(62),
        );
        let corrected_idle = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            corrected_idle.last_valid_receive_utc,
            first.last_valid_receive_utc
        );
        assert_eq!(corrected_idle.state_since_utc, first.state_since_utc);

        telemetry.sent(now + Duration::from_millis(2500));
        telemetry.calibrate(
            now + Duration::from_secs(3),
            start_utc + Duration::from_secs(63),
        );
        let after_send = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            after_send.last_successful_send_utc,
            Some(start_utc + Duration::from_millis(62500))
        );
        assert_eq!(
            after_send.last_valid_receive_utc,
            first.last_valid_receive_utc
        );

        // A backward correction refines a new receive at the next publication.
        telemetry.received(
            "127.0.0.81:52002".parse().unwrap(),
            now + Duration::from_millis(3500),
        );
        telemetry.calibrate(
            now + Duration::from_secs(4),
            start_utc + Duration::from_secs(4),
        );
        let after_receive = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            after_receive.last_valid_receive_utc,
            Some(start_utc + Duration::from_millis(3500))
        );
        assert_eq!(
            after_receive.last_successful_send_utc,
            after_send.last_successful_send_utc
        );
        telemetry.calibrate(
            now + Duration::from_secs(5),
            start_utc - Duration::from_secs(10),
        );
        let later_idle = telemetry.snapshot(&session, &options, options.timing(), 52001);
        assert_eq!(
            later_idle.last_valid_receive_utc,
            after_receive.last_valid_receive_utc
        );
        assert_eq!(
            later_idle.last_successful_send_utc,
            after_send.last_successful_send_utc
        );
    }

    #[test]
    fn concurrent_queries_observe_whole_immutable_snapshots() {
        let (options, session, telemetry, now) = fixture();
        let snapshot = telemetry.snapshot(&session, &options, options.timing(), 52001);
        let mut publisher = StatusPublisher::new(snapshot.clone(), 0, now);
        let observer = publisher.observer();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let observer = observer.clone();
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        if let Some(snapshot) = observer.snapshot() {
                            assert_eq!(
                                snapshot.packets_sent_successfully,
                                snapshot.packets_received_accepted
                            );
                        }
                    }
                });
            }
            for generation in 1..=100 {
                let mut next = snapshot.clone();
                next.packets_received_accepted = generation;
                next.packets_sent_successfully = generation;
                assert!(publisher.publish(next, generation, now + Duration::from_secs(generation)));
            }
        });
    }
}
