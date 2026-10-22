//! Classical RFC 5880 BFD and stateful RFC 7880 S-BFD initiation.
//!
//! The caller supplies monotonic receive/expiry times and handles transport I/O.
//! Discriminators, initial authentication sequences, and transmit jitter use randomness.
use crate::error::{AuthError, ConfigError, PacketError};
use rand::Rng;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::{
    config::{Mode, Options, ProtocolRole, SessionType, Timing, ValidatedOptions},
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
};

/// Ordinary congestion backoff stops doubling at 30 seconds. For a slower
/// negotiated base, allow one doubling so loss still reduces traffic (RFC 5880
/// section 7 and RFC 7880 section 8.2), bounded by the u32 wire interval.
const MAX_BACKOFF_TX_US: u32 = 30_000_000;

// Local keyed-SHA1 policy, not an RFC-mandated interval. Never extend this
// lifetime when reusing a packet; the next send at/after expiry advances once.
const KEYED_SHA1_REUSE: Duration = Duration::from_secs(1);

/// One validated classical or S-BFD initiator session, driven by its caller.
/// Reflector options provide logging context; use Reflector for stateless replies.
pub struct Session {
    pub(crate) state: State,
    pub(crate) diagnostic: Diagnostic,
    pub(crate) local_discriminator: u32,
    pub(crate) remote_discriminator: u32,
    poll: Poll,
    options: ValidatedOptions,
    timing: Timing,
    auth: AuthConfig,
    remote_state: State,
    remote_diagnostic: u8,
    remote_demand: bool,
    remote_min_rx_us: u32,
    remote_min_tx_us: u32,
    remote_detect_mult: u8,
    last_received: Option<Instant>,
    last_valid: Option<Instant>,
    received_auth_seq: Option<u32>,
    transmit_auth_seq: u32,
    cached_sha1: Option<PreparedPacket>,
    sent_auth_sequences: VecDeque<(u32, Instant)>,
    first_transmitted: Option<Instant>,
    communicating: bool,
    congestion_backoff: u8,
    congestion_floor_us: u32,
    pending_final: bool,
}

/// A Final can acknowledge only a transmitted Poll. Quiet requires a subsequent
/// non-Final packet before another live timer change (RFC 5880 section 6.8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Poll {
    Idle,
    Pending(Option<u32>),
    Sent(Option<u32>),
    Quiet,
}

impl Poll {
    fn held_tx(self) -> Option<u32> {
        match self {
            Self::Pending(tx) | Self::Sent(tx) => tx,
            _ => None,
        }
    }

    fn request(&mut self, held_tx: Option<u32>) {
        *self = Self::Pending(self.held_tx().or(held_tx));
    }

    fn receive(&mut self, final_bit: bool) {
        match (*self, final_bit) {
            (Self::Sent(_), true) => *self = Self::Quiet,
            (Self::Quiet, false) => *self = Self::Idle,
            _ => {}
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Transmission {
    Periodic,
    Final,
    StateChange,
}

/// Owned wire bytes, borrowed for socket I/O and committed only on success.
#[derive(Clone)]
pub(crate) struct PreparedPacket {
    pub(crate) data: crate::packet::PacketBuffer,
    control: ControlPacket,
    sequence: u32,
    generated_at: Instant,
}

/// Effects of accepting a control packet; no response has been transmitted yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    /// Send a Final reply independently of the periodic transmit schedule.
    pub reply_final: bool,
    /// The local BFD state changed while processing this packet.
    pub state_changed: bool,
}

/// Public rejection classification for callers and operational logging.
/// Reasons never contain packet or key bytes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiveError {
    /// A structural, transport, or protocol-role check failed.
    #[error("{0}")]
    Packet(#[from] PacketError),
    /// Authentication failed before any session state was changed.
    #[error("{0}")]
    Authentication(#[from] AuthError),
}

impl Session {
    /// Create a session only from valid, matching configuration and authentication.
    ///
    /// # Errors
    /// Returns an error for invalid options or mismatched authentication settings.
    pub fn new(options: Options, auth: AuthConfig) -> Result<Self, ConfigError> {
        let options = options.into_validated()?;
        if options.authentication() != &auth {
            return Err(ConfigError::AuthenticationMismatch);
        }
        Ok(Self::from_config(options))
    }

    /// Constructs a session from a validated snapshot without repeating validation.
    pub fn from_config(options: ValidatedOptions) -> Self {
        let auth = options.authentication().clone();
        let timing = options.timing();
        let local_discriminator = options
            .discriminator
            .unwrap_or_else(|| rand::thread_rng().gen_range(1..=u32::MAX));
        Self {
            state: if options.session_type == SessionType::SbfdReflector {
                if options.sbfd_admin_down {
                    State::AdminDown
                } else {
                    State::Up
                }
            } else {
                State::Down
            },
            diagnostic: if options.session_type == SessionType::SbfdReflector
                && options.sbfd_admin_down
            {
                Diagnostic::AdminDown
            } else {
                Diagnostic::None
            },
            local_discriminator,
            remote_discriminator: match options.role() {
                ProtocolRole::Initiator {
                    remote_discriminator,
                } => remote_discriminator.get(),
                _ => 0,
            },
            poll: Poll::Idle,
            options,
            timing,
            auth,
            remote_state: State::Down,
            remote_diagnostic: 0,
            remote_demand: false,
            remote_min_rx_us: 1,
            remote_min_tx_us: 1_000_000,
            remote_detect_mult: 1,
            last_received: None,
            last_valid: None,
            received_auth_seq: None,
            transmit_auth_seq: rand::random(),
            cached_sha1: None,
            sent_auth_sequences: VecDeque::new(),
            first_transmitted: None,
            communicating: false,
            congestion_backoff: 0,
            congestion_floor_us: 0,
            pending_final: false,
        }
    }

    /// Return the current local BFD state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Returns the local failure or shutdown reason. Classical recovery retains it;
    /// an S-BFD transition back to Up clears it under the initiator's local policy.
    pub fn diagnostic(&self) -> Diagnostic {
        self.diagnostic
    }

    /// Return the immutable, nonzero local session identifier.
    pub fn local_discriminator(&self) -> u32 {
        self.local_discriminator
    }

    /// Returns the learned classical peer identifier, or zero if unknown/expired.
    /// An S-BFD initiator retains its provisioned reflector identifier across expiry.
    pub fn remote_discriminator(&self) -> u32 {
        self.remote_discriminator
    }

    /// Return whether a local Poll sequence is pending.
    pub fn polling(&self) -> bool {
        matches!(self.poll, Poll::Pending(_) | Poll::Sent(_))
    }

    /// Returns whether a valid response has arrived within the detection window.
    /// Configured S-BFD discriminators remain known even when this is false.
    pub fn communicating(&self) -> bool {
        self.communicating
    }

    /// Returns the last accepted peer state; Down before any accepted packet.
    pub fn remote_state(&self) -> State {
        self.remote_state
    }

    /// Returns the last accepted peer diagnostic; zero before reception.
    /// Reserved diagnostic values remain available without becoming a local reason.
    pub fn remote_diagnostic(&self) -> u8 {
        self.remote_diagnostic
    }

    /// Last accepted advertised timing, copied into telemetry before expiry can
    /// reset the session's operational receive interval.
    #[cfg(windows)]
    pub(crate) fn remote_timing(&self) -> (u32, u32, u8) {
        (
            self.remote_min_tx_us,
            self.remote_min_rx_us,
            self.remote_detect_mult,
        )
    }

    /// Returns whether the session is Down because the peer signalled AdminDown,
    /// for example when its BFD service stopped. RFC 5882 section 3.2 treats this
    /// as administrative rather than a path failure.
    pub(crate) fn down_by_peer_admin(&self) -> bool {
        self.state == State::Down
            && self.diagnostic == Diagnostic::NeighborDown
            && self.remote_state == State::AdminDown
    }

    /// Applies S-BFD timing settings while retaining state and discriminators.
    /// Wire timing changes start a Poll when the initiator is Up. A TX increase
    /// is advertised immediately but takes effect only after its Final reply.
    ///
    /// # Errors
    /// Rejects classical sessions and overlapping transmitted Poll changes.
    /// After a Final, a non-Final response must arrive before another wire change.
    pub fn set_timing(&mut self, timing: Timing) -> Result<(), ConfigError> {
        if self.options.session_type == SessionType::Classical {
            return Err(ConfigError::ClassicalTimingUpdate);
        }
        let wire_change = self.state == State::Up
            && self.options.session_type == SessionType::SbfdInitiator
            && (self.timing.min_tx_us != timing.min_tx_us
                || self.timing.detect_mult != timing.detect_mult);
        if wire_change && matches!(self.poll, Poll::Sent(_) | Poll::Quiet) {
            return Err(ConfigError::PollInProgress);
        }
        let old_tx = self.effective_min_tx_us();
        self.timing.min_tx_us = timing.min_tx_us;
        self.timing.min_rx_us = timing.min_rx_us;
        self.timing.detect_mult = timing.detect_mult;
        if wire_change {
            self.poll
                .request((self.desired_min_tx_us() > old_tx).then_some(old_tx));
        }
        Ok(())
    }

    /// Returns the Up rate, or the greater of the startup and Up rates otherwise.
    /// S-BFD and unanswered classical multihop probes double their interval up
    /// to the greater of 30 seconds and twice the base interval, bounded by
    /// the wire format's maximum interval.
    pub fn desired_min_tx_us(&self) -> u32 {
        let interval = if self.state == State::Up {
            self.timing.min_tx_us
        } else {
            self.options.startup_tx_us.max(self.timing.min_tx_us)
        };
        if self.options.session_type == SessionType::SbfdInitiator
            || self.options.mode == Mode::Multihop && self.state != State::Up
        {
            let base = if self.congestion_backoff == 0 {
                interval
            } else if self.options.session_type == SessionType::Classical {
                interval.max(self.congestion_floor_us)
            } else {
                interval.max(self.remote_min_rx_us)
            };
            let limit = MAX_BACKOFF_TX_US.max(base.saturating_mul(2));
            base.saturating_mul(1u32 << self.congestion_backoff.min(31))
                .min(limit)
        } else {
            interval
        }
    }

    fn effective_min_tx_us(&self) -> u32 {
        let desired = self.desired_min_tx_us();
        if self.state == State::Up {
            desired.min(self.poll.held_tx().unwrap_or(desired))
        } else {
            desired
        }
    }

    /// Negotiated TX interval before jitter, whether or not traffic is enabled.
    pub fn transmit_interval(&self) -> Duration {
        Duration::from_micros(u64::from(
            self.effective_min_tx_us().max(self.remote_min_rx_us),
        ))
    }

    /// Returns the classical peer multiplier times max(local RX, peer TX).
    /// S-BFD uses local multiplier times transmit interval, plus the RTT budget.
    pub fn detection_time(&self) -> Duration {
        if self.options.session_type == SessionType::SbfdInitiator {
            // MinRxUs is the round-trip budget even though the wire RX field is zero.
            return self.transmit_interval() * u32::from(self.timing.detect_mult)
                + Duration::from_micros(u64::from(self.timing.min_rx_us));
        }
        Duration::from_micros(
            u64::from(self.timing.min_rx_us.max(self.remote_min_tx_us))
                * u64::from(self.remote_detect_mult),
        )
    }

    /// Returns the peer's Detection Time for this system's packets: the local
    /// multiplier times the negotiated transmit interval.
    pub(crate) fn peer_detection_time(&self) -> Duration {
        self.transmit_interval() * u32::from(self.timing.detect_mult)
    }

    /// Returns the receive-expiry deadline, if monitoring has begun.
    /// S-BFD starts detection after its first generated probe; classical BFD
    /// requires a validated peer packet first. AdminDown reception still starts
    /// peer-discriminator expiry, without enabling liveness detection.
    pub fn detection_deadline(&self) -> Option<Instant> {
        if self.options.session_type == SessionType::SbfdInitiator {
            return self
                .last_received
                .or(self.first_transmitted)
                .map(|last| last + self.detection_time());
        }
        // Also wake in Down to forget the remote discriminator after one Detection Time.
        self.last_valid
            .filter(|_| self.remote_discriminator != 0)
            .map(|last| last + self.detection_time())
    }

    /// Active/passive role gate; does not apply periodic Demand/zero-RX suppression.
    pub fn can_transmit(&self) -> bool {
        self.options.session_type != SessionType::SbfdReflector
            && (!self.options.passive || self.remote_discriminator != 0)
    }

    /// Returns whether periodic probes are enabled for this role.
    /// Classical peers can suppress periodic traffic through Demand or zero RX;
    /// S-BFD initiators continue probing and reflectors never probe periodically.
    pub fn periodic_enabled(&self) -> bool {
        if self.options.session_type == SessionType::SbfdInitiator {
            return true;
        }
        self.can_transmit()
            && !(self.remote_min_rx_us == 0
                || self.remote_demand
                    && self.state == State::Up
                    && self.remote_state == State::Up
                    && !self.polling())
    }

    pub(crate) fn minimum_transmit_interval(&self) -> Duration {
        if self.options.session_type == SessionType::SbfdInitiator
            && self.remote_state == State::AdminDown
        {
            Duration::from_secs(1)
        } else {
            Duration::ZERO
        }
    }

    /// Sample 75-100% of the negotiated interval (75-90% for multiplier 1).
    /// This calculates an interval even when periodic transmission is disabled.
    pub fn jittered_interval(&self) -> Duration {
        let upper = if self.timing.detect_mult == 1 {
            9000
        } else {
            10000
        };
        let factor = rand::thread_rng().gen_range(7500..=upper);
        let interval =
            Duration::from_nanos((self.transmit_interval().as_nanos() * factor / 10000) as u64);
        interval.max(self.minimum_transmit_interval())
    }

    /// Validate and apply a control packet using the supplied monotonic receipt time.
    ///
    /// The caller must first validate transport addresses, port, interface, and TTL.
    /// Authentication and discriminator checks precede any session mutation.
    /// Accepted packets in AdminDown can update peer parameters and sequence tracking,
    /// but do not refresh the detection timer or request a Final reply.
    ///
    /// # Errors
    /// Rejects malformed, wrong-session, or incorrectly authenticated packets without
    /// changing session state, timers, or sequence tracking.
    pub fn receive(&mut self, data: &[u8], now: Instant) -> Result<Received, ReceiveError> {
        self.receive_checked(data, now)
    }

    /// Preserve the rejection stage so runtime logging does not classify errors
    /// by comparing human-readable messages.
    pub(crate) fn receive_checked(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<Received, ReceiveError> {
        if self.options.session_type == SessionType::SbfdInitiator {
            return self.receive_seamless(data, now);
        }
        if self.options.session_type == SessionType::SbfdReflector {
            return Err(ReceiveError::Packet(PacketError::UseReflector));
        }
        let decoded = crate::packet::DecodedPacket::decode(data).map_err(ReceiveError::Packet)?;
        let packet = &decoded.control;
        if packet.your_discriminator != 0 && packet.your_discriminator != self.local_discriminator {
            return Err(ReceiveError::Packet(PacketError::WrongDiscriminator));
        }
        // RFC 6.8.1 permits resynchronization after twice the Detection Time.
        let last_seq = if self
            .last_valid
            .is_some_and(|last| now.saturating_duration_since(last) >= self.detection_time() * 2)
        {
            None
        } else {
            self.received_auth_seq
        };
        // RFC 5880 section 6.8.6: authentication must succeed before learning
        // peer state, refreshing detection, or processing Poll/Final. A rejected
        // packet is discarded without a response, even if it carries Poll.
        let sequence = self
            .auth
            .verify_decoded(&decoded, last_seq)
            .map_err(ReceiveError::Authentication)?;
        let previous_state = self.state;
        let previous_tx = self.desired_min_tx_us();
        self.received_auth_seq = sequence;
        self.last_valid = Some(now);
        self.remote_discriminator = packet.my_discriminator;
        self.remote_state = packet.state;
        self.remote_diagnostic = packet.diagnostic;
        self.remote_demand = packet.demand;
        self.remote_min_rx_us = packet.required_min_rx_us;
        self.remote_min_tx_us = packet.desired_min_tx_us;
        self.remote_detect_mult = packet.detect_mult;
        self.poll.receive(packet.final_bit);
        if self.state == State::AdminDown {
            return Ok(Received {
                reply_final: false,
                state_changed: false,
            });
        }
        self.congestion_backoff = 0;
        self.congestion_floor_us = 0;
        self.first_transmitted = None;
        if packet.state == State::AdminDown {
            if self.state != State::Down {
                self.state = State::Down;
                self.diagnostic = Diagnostic::NeighborDown;
            }
        } else {
            match (self.state, packet.state) {
                (State::Down, State::Down) => self.state = State::Init,
                (State::Down, State::Init) | (State::Init, State::Init | State::Up) => {
                    self.state = State::Up
                }
                (State::Up, State::Down) => {
                    self.state = State::Down;
                    self.diagnostic = Diagnostic::NeighborDown;
                }
                _ => {}
            }
        }
        if previous_tx != self.desired_min_tx_us() {
            self.poll.request(None);
        }
        self.last_received = Some(now);
        self.communicating = true;
        if previous_state != self.state {
            self.cached_sha1 = None;
        }
        Ok(Received {
            reply_final: packet.poll,
            state_changed: previous_state != self.state,
        })
    }

    /// Apply receive expiry and return whether the local state changed.
    ///
    /// Classical BFD clears the remote discriminator after one detection time and
    /// authentication tracking after two. S-BFD retains its configured target,
    /// clears outstanding sequences, and doubles its probing backoff on timeout.
    /// Classical multihop also backs off when discovery or detection expires.
    /// Returns false if the local state did not change.
    pub fn expire(&mut self, now: Instant) -> bool {
        if self.options.session_type == SessionType::SbfdInitiator {
            let Some(deadline) = self.detection_deadline() else {
                return false;
            };
            if now < deadline {
                return false;
            }
            self.communicating = false;
            self.last_received = None;
            self.first_transmitted = Some(now);
            self.sent_auth_sequences.clear();
            self.congestion_backoff = self.congestion_backoff.saturating_add(1).min(31);
            let changed = self.state == State::Up;
            if self.state != State::AdminDown {
                self.state = State::Down;
                self.diagnostic = Diagnostic::DetectionExpired;
                self.poll = Poll::Idle;
            }
            return changed;
        }
        let detection = self.detection_time();
        let valid_elapsed = self
            .last_valid
            .map(|last| now.saturating_duration_since(last));
        if valid_elapsed.is_some_and(|elapsed| elapsed >= detection * 2) {
            self.received_auth_seq = None;
        }
        let old_tx = self.desired_min_tx_us();
        let old_interval_us = self.effective_min_tx_us().max(self.remote_min_rx_us);
        let peer_expired = self.remote_discriminator != 0
            && valid_elapsed.is_some_and(|elapsed| elapsed >= detection);
        if peer_expired {
            self.remote_discriminator = 0;
            // RFC 5880 section 6.8.18 recommends resetting a stale RX limit.
            self.remote_min_rx_us = 1;
        }
        let detection_expired = self
            .last_received
            .is_some_and(|last| now.saturating_duration_since(last) >= detection);
        let changed = detection_expired && matches!(self.state, State::Init | State::Up);
        if detection_expired {
            self.communicating = false;
        }
        if changed {
            self.state = State::Down;
            self.diagnostic = Diagnostic::DetectionExpired;
            self.cached_sha1 = None;
        }
        let retry_expired = self.state == State::Down
            && self.first_transmitted.is_some_and(|first| {
                now.saturating_duration_since(first)
                    >= self.transmit_interval() * u32::from(self.timing.detect_mult)
            });
        if self.options.mode == Mode::Multihop
            && self.state != State::AdminDown
            && (peer_expired || retry_expired)
        {
            if self.congestion_backoff == 0 {
                // Resetting the peer's stale RX limit must not accelerate retries.
                self.congestion_floor_us = old_interval_us;
            }
            self.congestion_backoff = self.congestion_backoff.saturating_add(1).min(31);
            self.first_transmitted = Some(now);
        }
        if old_tx != self.desired_min_tx_us() {
            self.poll.request(None);
        }
        changed
    }

    /// Set AdminDown locally and clear Poll; performs no transport or BGP I/O.
    pub fn admin_down(&mut self) {
        if self.state != State::AdminDown {
            self.cached_sha1 = None;
        }
        self.state = State::AdminDown;
        self.diagnostic = Diagnostic::AdminDown;
        self.poll = Poll::Idle;
    }

    /// Encode the current state and record the generated packet as transmitted.
    ///
    /// A Final packet clears the wire Poll bit without completing the local Poll
    /// sequence. This method performs no I/O or transmission-permission check.
    /// Use Reflector::respond instead for the S-BFD reflector role.
    pub fn packet(&mut self, final_bit: bool) -> Vec<u8> {
        self.packet_at(final_bit, Instant::now())
    }

    /// Encodes a control packet using a monotonic generation time for S-BFD tracking.
    /// Keyed responses must match an unconsumed generated sequence before its expiry.
    /// Classical keyed SHA1 reuses unchanged packets for less than one second;
    /// content/state changes or expiry advance its sequence on the next packet.
    /// S-BFD probes and meticulous modes retain per-packet sequence progression.
    /// Unlike the runtime's prepare/commit path, this records generation even if
    /// a later socket send fails.
    pub fn packet_at(&mut self, final_bit: bool, now: Instant) -> Vec<u8> {
        let kind = if final_bit {
            Transmission::Final
        } else {
            Transmission::Periodic
        };
        let packet = self.prepare_packet(kind, now);
        self.record_transmission(&packet);
        packet.data.to_vec()
    }

    /// Prepares wire bytes without changing sequence, Poll, or probe tracking.
    /// State notifications keep Poll clear; periodic packets carry pending Polls.
    pub(crate) fn prepare_packet(&self, kind: Transmission, now: Instant) -> PreparedPacket {
        let seamless = self.options.session_type == SessionType::SbfdInitiator;
        let final_bit = matches!(kind, Transmission::Final) || seamless && self.pending_final;
        let packet = ControlPacket {
            diagnostic: self.diagnostic as u8,
            state: self.state,
            poll: self.polling() && !matches!(kind, Transmission::StateChange) && !final_bit,
            final_bit,
            control_plane_independent: false,
            demand: seamless,
            detect_mult: self.timing.detect_mult,
            my_discriminator: self.local_discriminator,
            your_discriminator: self.remote_discriminator,
            desired_min_tx_us: self.desired_min_tx_us(),
            required_min_rx_us: if seamless { 0 } else { self.timing.min_rx_us },
            required_min_echo_rx_us: 0,
        };
        if let Some(cached) = &self.cached_sha1 {
            if cached.control == packet
                && now
                    .checked_duration_since(cached.generated_at)
                    .is_some_and(|age| age < KEYED_SHA1_REUSE)
            {
                return PreparedPacket {
                    generated_at: now,
                    ..cached.clone()
                };
            }
        }
        PreparedPacket {
            data: packet.encode_buffer(&self.auth, self.transmit_auth_seq),
            control: packet,
            sequence: self.transmit_auth_seq,
            generated_at: now,
        }
    }

    pub(crate) fn record_transmission(&mut self, packet: &PreparedPacket) {
        if packet.control.final_bit {
            self.pending_final = false;
        }
        if packet.control.poll {
            self.poll = Poll::Sent(self.poll.held_tx());
        }
        let seamless = self.options.session_type == SessionType::SbfdInitiator;
        if self.options.session_type == SessionType::Classical
            && self.auth.kind() == AuthType::KeyedSha1
            && self
                .cached_sha1
                .as_ref()
                .is_none_or(|cached| cached.sequence != packet.sequence)
        {
            // Cache only committed wire bytes, never keys or unsent state. A
            // hit keeps the original generation time, bounding sequence reuse.
            self.cached_sha1 = Some(packet.clone());
        }
        if seamless || self.options.mode == Mode::Multihop {
            self.first_transmitted.get_or_insert(packet.generated_at);
        }
        if seamless
            && matches!(
                self.auth.kind(),
                AuthType::MeticulousMd5 | AuthType::KeyedSha1 | AuthType::MeticulousSha1
            )
        {
            // Bound memory even if callers generate packets faster than the runtime.
            if self.sent_auth_sequences.len() == 1024 {
                self.sent_auth_sequences.pop_front();
            }
            self.sent_auth_sequences
                .push_back((packet.sequence, packet.generated_at));
        }
        // Reserve the next sequence after this committed packet. Classical
        // keyed SHA1 can reuse the cached previous packet until it changes/ages.
        self.transmit_auth_seq = packet.sequence.wrapping_add(1);
    }

    fn receive_seamless(&mut self, data: &[u8], now: Instant) -> Result<Received, ReceiveError> {
        let decoded = crate::packet::DecodedPacket::decode(data).map_err(ReceiveError::Packet)?;
        let packet = &decoded.control;
        if packet.your_discriminator != self.local_discriminator
            || packet.my_discriminator != self.remote_discriminator
        {
            return Err(ReceiveError::Packet(
                PacketError::WrongSeamlessDiscriminator,
            ));
        }
        if packet.demand || !matches!(packet.state, State::Up | State::AdminDown) {
            return Err(ReceiveError::Packet(PacketError::InvalidReflectorState));
        }
        let sequence = self
            .auth
            .verify_decoded(&decoded, None)
            .map_err(ReceiveError::Authentication)?;
        let sequence_index = if let Some(sequence) = sequence {
            Some(
                self.sent_auth_sequences
                    .iter()
                    .position(|(sent, time)| {
                        *sent == sequence
                            && now.saturating_duration_since(*time) < self.detection_time()
                    })
                    .ok_or(ReceiveError::Authentication(
                        AuthError::SequenceNotOutstanding,
                    ))?,
            )
        } else {
            None
        };
        if let Some(index) = sequence_index {
            self.sent_auth_sequences.remove(index);
        }
        let previous = self.state;
        let old_tx = self.desired_min_tx_us();
        self.remote_state = packet.state;
        self.remote_diagnostic = packet.diagnostic;
        self.remote_min_rx_us = packet.required_min_rx_us;
        self.remote_min_tx_us = packet.desired_min_tx_us;
        self.remote_detect_mult = packet.detect_mult;
        self.congestion_backoff = 0;
        self.poll.receive(packet.final_bit);
        if self.state != State::AdminDown {
            self.state = if packet.state == State::Up {
                State::Up
            } else {
                State::Down
            };
            // Maintenance replies prove reachability; they are not a detection failure.
            if self.state != previous {
                self.diagnostic = if packet.state == State::Up {
                    Diagnostic::None
                } else {
                    Diagnostic::NeighborDown
                };
            }
            self.last_received = Some(now);
            self.communicating = true;
            self.pending_final |= packet.poll;
            if self.state == State::Up && old_tx != self.desired_min_tx_us() {
                self.poll.request(None);
            }
        }
        Ok(Received {
            reply_final: false,
            state_changed: self.state != previous,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{test_packet, AuthType};

    #[test]
    fn unsent_packets_do_not_advance_sequences_or_acknowledge_polls() {
        for kind in [
            AuthType::MeticulousMd5,
            AuthType::KeyedSha1,
            AuthType::MeticulousSha1,
        ] {
            let mut session = session();
            session.auth = AuthConfig::new(kind, 0, b"secret".to_vec()).unwrap();
            session.transmit_auth_seq = u32::MAX;
            session.poll = Poll::Pending(None);
            let now = Instant::now();
            for _ in 0..100 {
                let packet = session.prepare_packet(Transmission::Periodic, now);
                assert_eq!(
                    session.auth.verify(&packet.data, None).unwrap(),
                    Some(u32::MAX)
                );
            }
            session.poll.receive(true);
            assert_eq!(session.poll, Poll::Pending(None));
            assert!(session.first_transmitted.is_none());
            let packet = session.prepare_packet(Transmission::Periodic, now);
            session.record_transmission(&packet);
            assert_eq!(session.poll, Poll::Sent(None));
            let packet = session.prepare_packet(Transmission::Periodic, now);
            let expected = if kind == AuthType::KeyedSha1 {
                u32::MAX
            } else {
                0
            };
            assert_eq!(
                session.auth.verify(&packet.data, None).unwrap(),
                Some(expected)
            );
            let packet = session.prepare_packet(Transmission::Periodic, now + KEYED_SHA1_REUSE);
            assert_eq!(session.auth.verify(&packet.data, None).unwrap(), Some(0));
        }
    }

    #[test]
    fn classical_sha1_reuses_digest_until_fixed_expiry_and_commits_only_sent_changes() {
        let mut session = session();
        session.auth = AuthConfig::new(AuthType::KeyedSha1, 9, b"secret".to_vec()).unwrap();
        session.transmit_auth_seq = u32::MAX;
        let now = Instant::now();
        let first = session.prepare_packet(Transmission::Periodic, now);
        session.record_transmission(&first);
        for millis in [1, 300, 600, 999] {
            let calls = crate::packet::DIGEST_CALLS.with(std::cell::Cell::get);
            let reused =
                session.prepare_packet(Transmission::Periodic, now + Duration::from_millis(millis));
            assert_eq!(&*reused.data, &*first.data);
            assert_eq!(
                crate::packet::DIGEST_CALLS.with(std::cell::Cell::get),
                calls
            );
            session.record_transmission(&reused);
        }
        let expired = session.prepare_packet(Transmission::Periodic, now + KEYED_SHA1_REUSE);
        assert_eq!(
            session.auth.verify(&expired.data, Some(u32::MAX)).unwrap(),
            Some(0)
        );
        // An unsent refresh reserves no sequence and cannot extend the old cache.
        let retry = session.prepare_packet(Transmission::Periodic, now + KEYED_SHA1_REUSE);
        assert_eq!(&*retry.data, &*expired.data);
        session.record_transmission(&retry);
        session.diagnostic = Diagnostic::AdminDown;
        let unsent =
            session.prepare_packet(Transmission::Periodic, now + Duration::from_millis(1100));
        assert_eq!(session.auth.verify(&unsent.data, Some(0)).unwrap(), Some(1));
        session.diagnostic = Diagnostic::None;
        let calls = crate::packet::DIGEST_CALLS.with(std::cell::Cell::get);
        let reused =
            session.prepare_packet(Transmission::Periodic, now + Duration::from_millis(1999));
        assert_eq!(&*reused.data, &*retry.data);
        assert_eq!(
            crate::packet::DIGEST_CALLS.with(std::cell::Cell::get),
            calls
        );
        let refreshed = session.prepare_packet(Transmission::Periodic, now + KEYED_SHA1_REUSE * 2);
        assert_eq!(
            session.auth.verify(&refreshed.data, Some(0)).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn classical_sha1_refreshes_for_changed_control_fields_and_final_replies() {
        type Change = (&'static str, fn(&mut Session), Transmission);
        let changes: &[Change] = &[
            ("state", Session::admin_down, Transmission::Periodic),
            (
                "diagnostic",
                |s| s.diagnostic = Diagnostic::NeighborDown,
                Transmission::Periodic,
            ),
            (
                "local discriminator",
                |s| s.local_discriminator += 1,
                Transmission::Periodic,
            ),
            (
                "remote discriminator",
                |s| s.remote_discriminator += 1,
                Transmission::Periodic,
            ),
            (
                "TX interval",
                |s| s.timing.min_tx_us += 1,
                Transmission::Periodic,
            ),
            (
                "RX interval",
                |s| s.timing.min_rx_us += 1,
                Transmission::Periodic,
            ),
            (
                "multiplier",
                |s| s.timing.detect_mult += 1,
                Transmission::Periodic,
            ),
            (
                "Poll",
                |s| s.poll = Poll::Pending(None),
                Transmission::Periodic,
            ),
            ("Final", |_| {}, Transmission::Final),
        ];
        for (name, change, transmission) in changes {
            let mut session = session();
            session.auth = AuthConfig::new(AuthType::KeyedSha1, 9, b"secret".to_vec()).unwrap();
            session.transmit_auth_seq = 100;
            session.state = State::Up;
            session.remote_discriminator = 99;
            let now = Instant::now();
            let first = session.prepare_packet(Transmission::Periodic, now);
            session.record_transmission(&first);
            change(&mut session);
            let calls = crate::packet::DIGEST_CALLS.with(std::cell::Cell::get);
            let changed = session.prepare_packet(*transmission, now);
            assert_eq!(
                crate::packet::DIGEST_CALLS.with(std::cell::Cell::get),
                calls + 1,
                "{name}"
            );
            assert_eq!(
                session.auth.verify(&changed.data, Some(100)).unwrap(),
                Some(101),
                "{name}"
            );
            assert_ne!(
                ControlPacket::decode(&first.data).unwrap(),
                ControlPacket::decode(&changed.data).unwrap(),
                "{name}"
            );
            session.record_transmission(&changed);
            // Returning to an ordinary packet after a Final is also a content change.
            if matches!(transmission, Transmission::Final) {
                let periodic = session.prepare_packet(Transmission::Periodic, now);
                assert_eq!(
                    session.auth.verify(&periodic.data, Some(101)).unwrap(),
                    Some(102)
                );
                assert!(!periodic.control.final_bit);
            }
        }
    }

    #[test]
    fn classical_sha1_state_changes_invalidate_even_when_wire_contents_return() {
        let mut session = session();
        session.auth = AuthConfig::new(AuthType::KeyedSha1, 0, b"secret".to_vec()).unwrap();
        session.transmit_auth_seq = 100;
        let now = Instant::now();
        session
            .receive(&test_packet(State::Init).encode(&session.auth, 100), now)
            .unwrap();
        session.diagnostic = Diagnostic::NeighborDown;
        let first = session.prepare_packet(Transmission::Periodic, now);
        session.record_transmission(&first);
        for (state, sequence) in [(State::Down, 101), (State::Init, 102)] {
            session
                .receive(&test_packet(state).encode(&session.auth, sequence), now)
                .unwrap();
        }
        let recovered = session.prepare_packet(Transmission::Periodic, now);
        assert_eq!(recovered.control, first.control);
        assert_eq!(
            session.auth.verify(&recovered.data, Some(100)).unwrap(),
            Some(101)
        );
    }

    #[test]
    fn unsent_seamless_final_keeps_its_reply_and_probe_tracking_pending() {
        let mut options = (*session().options).clone();
        options.mode = Mode::SingleHop;
        options.multihop = false;
        options.session_type = SessionType::SbfdInitiator;
        options.remote_discriminator = Some(99);
        options.auth = AuthType::MeticulousSha1;
        options.auth_key = Some("secret".into());
        let mut session = Session::from_config(options.into_validated().unwrap());
        session.pending_final = true;
        let packet = session.prepare_packet(Transmission::Periodic, Instant::now());
        assert!(ControlPacket::decode(&packet.data).unwrap().final_bit);
        assert!(session.pending_final);
        assert!(session.sent_auth_sequences.is_empty());
        assert!(session.detection_deadline().is_none());
        session.record_transmission(&packet);
        assert!(!session.pending_final);
        assert_eq!(session.sent_auth_sequences.len(), 1);
        assert!(session.detection_deadline().is_some());
    }

    #[test]
    fn seamless_authentication_correlates_wrapped_sequences_and_consumes_each_once() {
        for kind in [
            AuthType::MeticulousMd5,
            AuthType::KeyedSha1,
            AuthType::MeticulousSha1,
        ] {
            let mut options =
                Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
            options.session_type = SessionType::SbfdInitiator;
            options.discriminator = Some(7);
            options.remote_discriminator = Some(99);
            options.auth = kind;
            options.auth_key = Some("secret".into());
            let auth = options.validate().unwrap();
            let mut reflector_options = Options::reflector(options.peer, 99);
            reflector_options.auth = options.auth;
            reflector_options.auth_key = options.auth_key.clone();
            let reflector =
                crate::seamless::Reflector::new(reflector_options, auth.clone()).unwrap();
            let mut session = Session::new(options, auth.clone()).unwrap();
            session.transmit_auth_seq = u32::MAX;
            let now = Instant::now();
            let first = session.packet_at(false, now);
            let second = session.packet_at(false, now);
            assert_eq!(auth.verify(&first, None).unwrap(), Some(u32::MAX));
            assert_eq!(auth.verify(&second, None).unwrap(), Some(0));
            for request in [&second, &first] {
                let reply = reflector.respond(request).unwrap();
                session.receive(&reply, now).unwrap();
                assert!(session.receive(&reply, now).is_err());
            }
            assert_eq!(session.state(), State::Up);
        }
    }

    #[test]
    fn only_a_peer_admin_down_is_distinguished_from_path_failures() {
        let now = Instant::now();
        for (signal, administrative) in [(State::AdminDown, true), (State::Down, false)] {
            let mut session = session();
            session
                .receive(&wire(&test_packet(State::Init)), now)
                .unwrap();
            assert_eq!(session.state, State::Up);
            assert!(!session.down_by_peer_admin());
            session.receive(&wire(&test_packet(signal)), now).unwrap();
            assert_eq!(session.state, State::Down);
            assert_eq!(session.down_by_peer_admin(), administrative, "{signal:?}");
        }
        let mut session = session();
        session
            .receive(&wire(&test_packet(State::Init)), now)
            .unwrap();
        assert!(session.expire(now + session.detection_time()));
        assert!(!session.down_by_peer_admin());

        // An S-BFD reflector in maintenance answers AdminDown.
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.session_type = SessionType::SbfdInitiator;
        options.remote_discriminator = Some(99);
        let auth = options.validate().unwrap();
        let mut reflector =
            crate::seamless::Reflector::new(Options::reflector(options.peer, 99), auth.clone())
                .unwrap();
        let mut initiator = Session::new(options, auth).unwrap();
        let request = initiator.packet_at(false, now);
        initiator
            .receive(&reflector.respond(&request).unwrap(), now)
            .unwrap();
        assert_eq!(initiator.state, State::Up);
        reflector.set_admin_down(true);
        let request = initiator.packet_at(false, now);
        initiator
            .receive(&reflector.respond(&request).unwrap(), now)
            .unwrap();
        assert_eq!(initiator.state, State::Down);
        assert!(initiator.down_by_peer_admin());
    }

    #[test]
    fn congestion_backoff_stops_at_thirty_seconds_or_twice_a_slower_base() {
        let mut options = (*session().options).clone();
        options.mode = Mode::SingleHop;
        options.multihop = false;
        options.session_type = SessionType::SbfdInitiator;
        options.remote_discriminator = Some(99);
        let mut seamless = Session::from_config(options.into_validated().unwrap());
        let mut now = Instant::now();
        seamless.packet_at(false, now);
        let mut previous = seamless.desired_min_tx_us();
        for _ in 0..40 {
            now = seamless.detection_deadline().unwrap();
            seamless.expire(now);
            let current = seamless.desired_min_tx_us();
            assert!(current >= previous && current <= MAX_BACKOFF_TX_US);
            previous = current;
        }
        assert_eq!(seamless.transmit_interval(), Duration::from_secs(30));
        assert!(seamless.detection_time() < Duration::from_secs(30 * 4));

        // A slow peer's advertised receive limit stays the classical floor.
        let now = Instant::now();
        let mut classical = session();
        let mut peer = test_packet(State::Init);
        peer.required_min_rx_us = 60_000_000;
        classical.receive(&wire(&peer), now).unwrap();
        assert_eq!(classical.transmit_interval(), Duration::from_secs(60));
        assert!(classical.expire(now + classical.detection_time()));
        assert_eq!(classical.transmit_interval(), Duration::from_secs(120));
    }

    fn session() -> Session {
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.multihop = true;
        options.discriminator = Some(7);
        options.min_rx_us = 200000;
        options.min_tx_us = 100000;
        let auth = options.validate().unwrap();
        Session::new(options, auth).unwrap()
    }
    fn wire(packet: &ControlPacket) -> Vec<u8> {
        packet.encode(&AuthConfig::new(AuthType::None, 0, vec![]).unwrap(), 0)
    }
    #[test]
    fn constructor_rejects_invalid_options_and_mismatched_authentication() {
        let valid = (*session().options).clone();
        let no_auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        let mut invalid = valid.clone();
        invalid.detect_mult = 0;
        assert!(Session::new(invalid, no_auth.clone()).is_err());
        let mut invalid = valid.clone();
        invalid.discriminator = Some(0);
        assert!(Session::new(invalid, no_auth).is_err());
        let auth = AuthConfig::new(AuthType::MeticulousSha1, 0, b"secret".to_vec()).unwrap();
        assert!(Session::new(valid, auth).is_err());
    }
    #[test]
    fn state_machine_matches_all_local_remote_combinations() {
        let states = [State::AdminDown, State::Down, State::Init, State::Up];
        let expected = [
            [State::AdminDown; 4],
            [State::Down, State::Init, State::Up, State::Down],
            [State::Down, State::Init, State::Up, State::Up],
            [State::Down, State::Down, State::Up, State::Up],
        ];
        for (i, local) in states.iter().enumerate() {
            for (j, remote) in states.iter().enumerate() {
                let mut session = session();
                if *local == State::AdminDown {
                    session.admin_down();
                } else {
                    session.state = *local;
                }
                let mut peer = test_packet(*remote);
                peer.diagnostic = 8; // A peer's diagnostic does not become our local reason.
                let received = session.receive(&wire(&peer), Instant::now()).unwrap();
                assert_eq!(session.state, expected[i][j], "{local:?} / {remote:?}");
                assert_eq!(received.state_changed, *local != expected[i][j]);
                let diagnostic = if *local == State::AdminDown {
                    Diagnostic::AdminDown
                } else if expected[i][j] == State::Down && *local != State::Down {
                    Diagnostic::NeighborDown
                } else {
                    Diagnostic::None
                };
                assert_eq!(session.diagnostic(), diagnostic, "{local:?} / {remote:?}");
                assert_eq!(session.remote_state(), *remote);
                assert_eq!(session.remote_diagnostic(), 8);
                let data = session.packet(false);
                assert_eq!(data[0], 0x20 | diagnostic as u8);
                assert_eq!(data[1] >> 6, expected[i][j] as u8);
                assert_eq!(
                    data[1] & 0x0f,
                    0,
                    "C/A/D/M stay clear without authentication"
                );
                assert_eq!(data[3], 24);
                assert_eq!(&data[20..24], &[0; 4], "Echo is unsupported");
            }
        }
    }

    #[test]
    fn invalid_poll_final_does_not_complete_a_poll_or_refresh_state() {
        let now = Instant::now();
        let mut session = session();
        session
            .receive(&wire(&test_packet(State::Init)), now)
            .unwrap();
        let before = (
            session.state,
            session.diagnostic,
            session.poll,
            session.remote_discriminator,
            session.remote_min_rx_us,
            session.remote_min_tx_us,
            session.last_received,
            session.remote_state(),
            session.remote_diagnostic(),
        );
        let mut invalid = test_packet(State::Down);
        invalid.poll = true;
        invalid.final_bit = true;
        invalid.required_min_rx_us = 0;
        invalid.desired_min_tx_us = 9_000_000;
        invalid.diagnostic = 8;
        assert_eq!(
            session.receive_checked(&wire(&invalid), now + Duration::from_millis(1)),
            Err(ReceiveError::Packet(PacketError::PollAndFinal))
        );
        assert_eq!(
            before,
            (
                session.state,
                session.diagnostic,
                session.poll,
                session.remote_discriminator,
                session.remote_min_rx_us,
                session.remote_min_tx_us,
                session.last_received,
                session.remote_state(),
                session.remote_diagnostic(),
            )
        );
    }

    #[test]
    fn diagnostics_report_failure_and_survive_reestablishment() {
        let now = Instant::now();
        let mut session = session();
        session
            .receive(&wire(&test_packet(State::Init)), now)
            .unwrap();
        let deadline = session.detection_deadline().unwrap();
        assert!(session.expire(deadline));
        assert_eq!(session.packet(false)[0], 0x21);
        session
            .receive(&wire(&test_packet(State::AdminDown)), deadline)
            .unwrap();
        assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
        session
            .receive(&wire(&test_packet(State::Down)), deadline)
            .unwrap();
        assert_eq!(session.state(), State::Init);
        assert_eq!(session.diagnostic(), Diagnostic::DetectionExpired);
        session
            .receive(&wire(&test_packet(State::Up)), deadline)
            .unwrap();
        assert_eq!(session.packet(false)[0], 0x21);
        session
            .receive(&wire(&test_packet(State::Down)), deadline)
            .unwrap();
        assert_eq!(session.packet(false)[0], 0x23);
        session.admin_down();
        let stopped = ControlPacket::decode(&session.packet(false)).unwrap();
        assert_eq!(stopped.state, State::AdminDown);
        assert_eq!(stopped.diagnostic, 7);
        assert!(!stopped.poll && !stopped.final_bit);
    }
    #[test]
    fn handshake_negotiates_timers_and_timeout_preserves_parameters() {
        let now = Instant::now();
        let mut session = session();
        assert_eq!(session.desired_min_tx_us(), 1_000_000);
        session
            .receive(&wire(&test_packet(State::Down)), now)
            .unwrap();
        assert_eq!(session.state, State::Init);
        session
            .receive(&wire(&test_packet(State::Init)), now)
            .unwrap();
        assert_eq!(session.state, State::Up);
        assert!(session.polling());
        assert_eq!(session.transmit_interval(), Duration::from_micros(200_000));
        assert_eq!(session.detection_time(), Duration::from_micros(600_000));
        assert!(!session.expire(now + Duration::from_micros(599_999)));
        assert!(session.expire(now + Duration::from_micros(600_000)));
        assert_eq!(session.diagnostic, Diagnostic::DetectionExpired);
        assert_eq!(session.remote_discriminator, 0);
        assert_eq!(session.detection_time(), Duration::from_micros(600_000));
    }
    #[test]
    fn invalid_packets_do_not_refresh_liveness_or_change_state() {
        let mut session = session();
        let now = Instant::now();
        session
            .receive(&wire(&test_packet(State::Down)), now)
            .unwrap();
        let mut wrong = test_packet(State::Up);
        wrong.your_discriminator = 99;
        assert!(session
            .receive(&wire(&wrong), now + Duration::from_millis(500))
            .is_err());
        assert_eq!(session.state, State::Init);
        assert!(session.expire(now + Duration::from_millis(600)));
    }
    #[test]
    fn poll_replies_override_suppression_and_never_set_both_bits() {
        let mut session = session();
        let mut peer = test_packet(State::Init);
        peer.poll = true;
        peer.required_min_rx_us = 0;
        let outcome = session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(outcome.reply_final);
        assert!(!session.periodic_enabled());
        let reply = ControlPacket::decode(&session.packet(true)).unwrap();
        assert!(reply.final_bit);
        assert!(!reply.poll);
        assert!(session.polling());
        peer.poll = false;
        peer.final_bit = true;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(session.polling()); // No Poll was transmitted by the Final reply.
        assert!(ControlPacket::decode(&session.packet(false)).unwrap().poll);
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(!session.polling());
    }
    #[test]
    fn remote_demand_only_suppresses_when_both_ends_are_up() {
        let mut session = session();
        let mut peer = test_packet(State::Init);
        peer.demand = true;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(session.periodic_enabled());
        session.packet(false);
        peer.state = State::Up;
        peer.final_bit = true;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(!session.periodic_enabled());
        peer.demand = false;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(session.periodic_enabled());
    }
    #[test]
    fn passive_waits_and_jitter_obeys_multiplier_one_bounds() {
        let mut options = (*session().options).clone();
        options.passive = true;
        options.detect_mult = 1;
        let auth = options.validate().unwrap();
        let mut session = Session::new(options, auth).unwrap();
        assert!(!session.periodic_enabled());
        session.admin_down();
        assert!(!session.can_transmit());
        session.state = State::Down;
        session
            .receive(&wire(&test_packet(State::Down)), Instant::now())
            .unwrap();
        assert!(session.periodic_enabled());
        for _ in 0..100 {
            let nanos = session.jittered_interval().as_nanos();
            let base = session.transmit_interval().as_nanos();
            assert!((base * 75 / 100..=base * 90 / 100).contains(&nanos));
        }
    }
    #[test]
    fn authentication_resynchronizes_only_after_twice_detection_time() {
        let mut session = session();
        let now = Instant::now();
        let auth = AuthConfig::new(AuthType::MeticulousSha1, 0, b"secret".to_vec()).unwrap();
        session.auth = auth.clone();
        let peer = test_packet(State::Down);
        session.receive(&peer.encode(&auth, 100), now).unwrap();
        assert!(session
            .receive(&peer.encode(&auth, 0), now + Duration::from_millis(1199))
            .is_err());
        assert!(session
            .receive(&peer.encode(&auth, 0), now + Duration::from_millis(1200))
            .is_ok());
    }

    const AUTH_TYPES: [AuthType; 4] = [
        AuthType::SimplePassword,
        AuthType::MeticulousMd5,
        AuthType::KeyedSha1,
        AuthType::MeticulousSha1,
    ];

    #[test]
    fn receive_classifies_verification_failures_without_changing_session_state() {
        let now = Instant::now();
        let peer = test_packet(State::Down);
        for kind in AUTH_TYPES {
            let mut session = session();
            let auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
            session.auth = auth.clone();
            let wrong_id = AuthConfig::new(kind, 10, b"secret".to_vec()).unwrap();
            let wrong_key = AuthConfig::new(kind, 9, b"wrong!".to_vec()).unwrap();
            let other_kind = if kind == AuthType::SimplePassword {
                AuthType::MeticulousSha1
            } else {
                AuthType::SimplePassword
            };
            let wrong_type = AuthConfig::new(other_kind, 9, b"secret".to_vec()).unwrap();
            let mut invalid_length = peer.encode(&auth, 100);
            invalid_length[25] = 0;
            for (data, reason) in [
                (wire(&peer), AuthError::Required),
                (peer.encode(&wrong_id, 100), AuthError::WrongKeyId),
                (peer.encode(&wrong_type, 100), AuthError::WrongType),
                (invalid_length, AuthError::InvalidLength),
                (
                    peer.encode(&wrong_key, 100),
                    if kind == AuthType::SimplePassword {
                        AuthError::PasswordMismatch
                    } else {
                        AuthError::DigestMismatch
                    },
                ),
            ] {
                assert_eq!(
                    session.receive_checked(&data, now).err(),
                    Some(ReceiveError::Authentication(reason)),
                    "{kind:?}"
                );
                assert_eq!(session.state, State::Down);
                assert_eq!(session.remote_discriminator, 0);
                assert_eq!(session.last_received, None);
                assert_eq!(session.received_auth_seq, None);
            }
            assert_eq!(
                session.receive_checked(&[0; 24], now).err(),
                Some(ReceiveError::Packet(PacketError::UnsupportedVersion))
            );
            let mut wrong_session = peer.clone();
            wrong_session.your_discriminator = 42;
            assert_eq!(
                session.receive_checked(&wire(&wrong_session), now).err(),
                Some(ReceiveError::Packet(PacketError::WrongDiscriminator))
            );
            session
                .receive_checked(&peer.encode(&auth, 100), now)
                .unwrap();
            if kind != AuthType::SimplePassword {
                assert_eq!(
                    session.receive_checked(&peer.encode(&auth, 99), now).err(),
                    Some(ReceiveError::Authentication(AuthError::SequenceWindow))
                );
                assert_eq!(session.received_auth_seq, Some(100));
            }
        }
        let mut session = session();
        let auth = AuthConfig::new(AuthType::MeticulousSha1, 9, b"secret".to_vec()).unwrap();
        assert_eq!(
            session.receive_checked(&peer.encode(&auth, 100), now).err(),
            Some(ReceiveError::Authentication(AuthError::Unexpected))
        );
    }

    #[test]
    fn authentication_is_required_before_handshake_or_poll_reply() {
        let now = Instant::now();
        for kind in AUTH_TYPES {
            for passive in [false, true] {
                let mut session = session();
                session.auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
                let mut options = (*session.options).clone();
                options.passive = passive;
                session.options = options.into_validated().unwrap();
                for state in [State::AdminDown, State::Down, State::Init, State::Up] {
                    let mut peer = test_packet(state);
                    peer.poll = true;
                    peer.required_min_rx_us = 0;
                    peer.demand = true;
                    peer.diagnostic = 8;
                    assert_eq!(
                        session.receive(&wire(&peer), now).err(),
                        Some(ReceiveError::Authentication(AuthError::Required)),
                        "{kind:?}, passive={passive}, peer={state:?}"
                    );
                    assert_eq!(session.state, State::Down);
                    assert_eq!(session.remote_discriminator, 0);
                    assert_eq!(session.remote_state(), State::Down);
                    assert_eq!(session.remote_diagnostic(), 0);
                    assert_eq!(session.last_received, None);
                    assert_eq!(session.received_auth_seq, None);
                    assert_eq!(session.periodic_enabled(), !passive);
                }
                // Active startup advertisements still carry configured authentication.
                let advertisement = session.packet(false);
                assert!(session.auth.verify(&advertisement, None).is_ok());
                let packet = ControlPacket::decode(&advertisement).unwrap();
                assert_eq!(packet.state, State::Down);
                assert!(!packet.final_bit);

                let authenticated = test_packet(State::Down).encode(&session.auth, 100);
                assert!(session.receive(&authenticated, now).unwrap().state_changed);
                assert_eq!(session.state, State::Init);
                assert!(session.periodic_enabled());
                assert_eq!(
                    session.receive(&wire(&test_packet(State::Init)), now).err(),
                    Some(ReceiveError::Authentication(AuthError::Required))
                );
                assert_eq!(session.state, State::Init);
            }
        }
    }

    #[test]
    fn unauthenticated_packets_cannot_keep_session_up_or_change_negotiation() {
        let now = Instant::now();
        for kind in AUTH_TYPES {
            let mut session = session();
            let auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
            session.auth = auth.clone();
            session
                .receive(&test_packet(State::Init).encode(&auth, 100), now)
                .unwrap();
            assert_eq!(session.state, State::Up);
            assert!(session.polling());
            let sequence = session.received_auth_seq;
            let deadline = session.detection_deadline();
            for state in [State::AdminDown, State::Down, State::Init, State::Up] {
                for poll in [false, true] {
                    let mut peer = test_packet(state);
                    peer.poll = poll;
                    peer.final_bit = !poll;
                    peer.my_discriminator = 99;
                    peer.required_min_rx_us = 0;
                    peer.desired_min_tx_us = 10_000_000;
                    peer.detect_mult = 255;
                    peer.demand = true;
                    peer.diagnostic = 8;
                    assert_eq!(
                        session
                            .receive(&wire(&peer), now + Duration::from_millis(599))
                            .err(),
                        Some(ReceiveError::Authentication(AuthError::Required))
                    );
                    assert_eq!(session.state, State::Up);
                    assert_eq!(session.diagnostic, Diagnostic::None);
                    assert_eq!(session.remote_state(), State::Init);
                    assert_eq!(session.remote_diagnostic(), 0);
                    assert_eq!(session.remote_discriminator, 0x10203040);
                    assert!(session.polling());
                    assert!(session.periodic_enabled());
                    assert_eq!(session.received_auth_seq, sequence);
                    assert_eq!(session.last_received, Some(now));
                    assert_eq!(session.detection_deadline(), deadline);
                    assert_eq!(session.transmit_interval(), Duration::from_millis(200));
                }
            }
            assert!(!session.expire(now + Duration::from_millis(599)));
            assert!(session.expire(now + Duration::from_millis(600)));
            let down = session.packet(false);
            assert!(auth.verify(&down, None).is_ok());
            let packet = ControlPacket::decode(&down).unwrap();
            assert_eq!(packet.state, State::Down);
            assert_eq!(packet.diagnostic, Diagnostic::DetectionExpired as u8);
            assert!(!packet.final_bit);

            // Rejecting unauthenticated traffic does not prevent authenticated recovery.
            let mut peer = test_packet(State::Init);
            peer.poll = true;
            let received = session
                .receive(&peer.encode(&auth, 101), now + Duration::from_millis(601))
                .unwrap();
            assert!(received.state_changed);
            assert!(received.reply_final);
            assert_eq!(session.state, State::Up);
            let final_reply = session.packet(true);
            assert!(auth.verify(&final_reply, None).is_ok());
            assert!(ControlPacket::decode(&final_reply).unwrap().final_bit);
        }
    }
}
