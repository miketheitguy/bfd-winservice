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
    config::{Options, ProtocolRole, SessionType, Timing, ValidatedOptions},
    packet::{AuthConfig, AuthType, ControlPacket, Diagnostic, State},
};

/// One validated classical or S-BFD initiator session, driven by its caller.
/// Reflector options provide logging context; use Reflector for stateless replies.
pub struct Session {
    pub(crate) state: State,
    pub(crate) diagnostic: Diagnostic,
    pub(crate) local_discriminator: u32,
    pub(crate) remote_discriminator: u32,
    pub(crate) polling: bool,
    options: ValidatedOptions,
    timing: Timing,
    auth: AuthConfig,
    remote_state: State,
    remote_demand: bool,
    remote_min_rx_us: u32,
    remote_min_tx_us: u32,
    remote_detect_mult: u8,
    last_received: Option<Instant>,
    received_auth_seq: Option<u32>,
    transmit_auth_seq: u32,
    sent_auth_sequences: VecDeque<(u32, Instant)>,
    first_transmitted: Option<Instant>,
    communicating: bool,
    congestion_backoff: u8,
    pending_final: bool,
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
            polling: false,
            options,
            timing,
            auth,
            remote_state: State::Down,
            remote_demand: false,
            remote_min_rx_us: 1,
            remote_min_tx_us: 1_000_000,
            remote_detect_mult: 1,
            last_received: None,
            received_auth_seq: None,
            transmit_auth_seq: rand::random(),
            sent_auth_sequences: VecDeque::new(),
            first_transmitted: None,
            communicating: false,
            congestion_backoff: 0,
            pending_final: false,
        }
    }

    /// Return the current local BFD state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Returns the local failure or shutdown reason; reestablishment clears it.
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
        self.polling
    }

    /// Returns whether a valid response has arrived within the detection window.
    /// Configured S-BFD discriminators remain known even when this is false.
    pub fn communicating(&self) -> bool {
        self.communicating
    }

    /// Applies S-BFD timing settings while retaining state and discriminators.
    /// A changed transmit interval starts a Poll sequence when the initiator is Up.
    ///
    /// # Errors
    /// Rejects classical sessions; their negotiated timer updates are unsupported.
    pub fn set_timing(&mut self, timing: Timing) -> Result<(), ConfigError> {
        if self.options.session_type == SessionType::Classical {
            return Err(ConfigError::ClassicalTimingUpdate);
        }
        let old_tx = self.desired_min_tx_us();
        self.timing.min_tx_us = timing.min_tx_us;
        self.timing.min_rx_us = timing.min_rx_us;
        self.timing.detect_mult = timing.detect_mult;
        if self.state == State::Up
            && self.options.session_type == SessionType::SbfdInitiator
            && old_tx != self.desired_min_tx_us()
        {
            self.polling = true;
        }
        Ok(())
    }

    /// Returns the Up rate, or the greater of the startup and Up rates otherwise.
    /// S-BFD timeout backoff multiplies this interval with saturating arithmetic.
    pub fn desired_min_tx_us(&self) -> u32 {
        let interval = if self.state == State::Up {
            self.timing.min_tx_us
        } else {
            self.options.startup_tx_us.max(self.timing.min_tx_us)
        };
        if self.options.session_type == SessionType::SbfdInitiator {
            let base = if self.congestion_backoff == 0 {
                interval
            } else {
                interval.max(self.remote_min_rx_us)
            };
            base.saturating_mul(1u32 << self.congestion_backoff.min(31))
        } else {
            interval
        }
    }

    /// Negotiated TX interval before jitter, whether or not traffic is enabled.
    pub fn transmit_interval(&self) -> Duration {
        Duration::from_micros(u64::from(
            self.desired_min_tx_us().max(self.remote_min_rx_us),
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

    /// Returns the receive-expiry deadline, if monitoring has begun.
    /// S-BFD starts detection after its first generated probe; classical BFD
    /// requires a validated peer packet first.
    pub fn detection_deadline(&self) -> Option<Instant> {
        if self.options.session_type == SessionType::SbfdInitiator {
            return self
                .last_received
                .or(self.first_transmitted)
                .map(|last| last + self.detection_time());
        }
        // Also wake in Down to forget the remote discriminator after one Detection Time.
        self.last_received
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
                    && !self.polling)
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
        let packet = ControlPacket::decode(data).map_err(ReceiveError::Packet)?;
        if packet.your_discriminator != 0 && packet.your_discriminator != self.local_discriminator {
            return Err(ReceiveError::Packet(PacketError::WrongDiscriminator));
        }
        // RFC 6.8.1 permits resynchronization after twice the Detection Time.
        let last_seq = if self
            .last_received
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
            .verify(data, last_seq)
            .map_err(ReceiveError::Authentication)?;
        let previous_state = self.state;
        let previous_tx = self.desired_min_tx_us();
        self.received_auth_seq = sequence;
        self.remote_discriminator = packet.my_discriminator;
        self.remote_state = packet.state;
        self.remote_demand = packet.demand;
        self.remote_min_rx_us = packet.required_min_rx_us;
        self.remote_min_tx_us = packet.desired_min_tx_us;
        self.remote_detect_mult = packet.detect_mult;
        if packet.final_bit {
            self.polling = false;
        }
        if self.state == State::AdminDown {
            return Ok(Received {
                reply_final: false,
                state_changed: false,
            });
        }
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
        if self.state == State::Up && previous_state != State::Up {
            self.diagnostic = Diagnostic::None;
        }
        if previous_tx != self.desired_min_tx_us() {
            self.polling = true;
        }
        self.last_received = Some(now);
        self.communicating = true;
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
                self.polling = false;
            }
            return changed;
        }
        let Some(last) = self.last_received else {
            return false;
        };
        let elapsed = now.saturating_duration_since(last);
        if elapsed >= self.detection_time() * 2 {
            self.received_auth_seq = None;
        }
        if elapsed < self.detection_time() {
            return false;
        }
        self.remote_discriminator = 0;
        self.communicating = false;
        if matches!(self.state, State::Init | State::Up) {
            let old_tx = self.desired_min_tx_us();
            self.state = State::Down;
            self.diagnostic = Diagnostic::DetectionExpired;
            if old_tx != self.desired_min_tx_us() {
                self.polling = true;
            }
            return true;
        }
        false
    }

    /// Set AdminDown locally and clear Poll; performs no transport or BGP I/O.
    pub fn admin_down(&mut self) {
        self.state = State::AdminDown;
        self.diagnostic = Diagnostic::AdminDown;
        self.polling = false;
    }

    /// Encode the current state, reserving an authentication sequence on every call.
    ///
    /// A Final packet clears the wire Poll bit without completing the local Poll
    /// sequence. This method performs no I/O or transmission-permission check.
    /// Use Reflector::respond instead for the S-BFD reflector role.
    pub fn packet(&mut self, final_bit: bool) -> Vec<u8> {
        self.packet_at(final_bit, Instant::now())
    }

    /// Encodes a control packet using a monotonic generation time for S-BFD tracking.
    /// Keyed responses must match an unconsumed generated sequence before its expiry.
    /// Generating a packet reserves its sequence even if a later socket send fails.
    pub fn packet_at(&mut self, final_bit: bool, now: Instant) -> Vec<u8> {
        self.encode_packet_at(final_bit, true, now)
    }

    /// Announces a classical state change without adding an unscheduled Poll.
    /// The pending Poll sequence remains active for periodic transmissions.
    pub(crate) fn state_change_packet(&mut self) -> Vec<u8> {
        self.encode_packet_at(false, false, Instant::now())
    }

    fn encode_packet_at(&mut self, final_bit: bool, include_poll: bool, now: Instant) -> Vec<u8> {
        let seamless = self.options.session_type == SessionType::SbfdInitiator;
        let final_bit = final_bit || seamless && self.pending_final;
        if final_bit {
            self.pending_final = false;
        }
        let packet = ControlPacket {
            diagnostic: self.diagnostic as u8,
            state: self.state,
            poll: self.polling && include_poll && !final_bit,
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
        let data = packet.encode(&self.auth, self.transmit_auth_seq);
        if seamless {
            self.first_transmitted.get_or_insert(now);
            if matches!(
                self.auth.kind(),
                AuthType::KeyedMd5
                    | AuthType::MeticulousMd5
                    | AuthType::KeyedSha1
                    | AuthType::MeticulousSha1
            ) {
                // Bound memory even if callers generate packets faster than the runtime.
                if self.sent_auth_sequences.len() == 1024 {
                    self.sent_auth_sequences.pop_front();
                }
                self.sent_auth_sequences
                    .push_back((self.transmit_auth_seq, now));
            }
        }
        // Reserve the next sequence for each generated packet, even if sending fails.
        // Incrementing per transmitted packet is also legal for non-meticulous auth.
        self.transmit_auth_seq = self.transmit_auth_seq.wrapping_add(1);
        data
    }

    fn receive_seamless(&mut self, data: &[u8], now: Instant) -> Result<Received, ReceiveError> {
        let packet = ControlPacket::decode(data).map_err(ReceiveError::Packet)?;
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
            .verify(data, None)
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
        self.remote_min_rx_us = packet.required_min_rx_us;
        self.remote_min_tx_us = packet.desired_min_tx_us;
        self.remote_detect_mult = packet.detect_mult;
        self.congestion_backoff = 0;
        if packet.final_bit {
            self.polling = false;
        }
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
                self.polling = true;
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
    fn seamless_authentication_correlates_wrapped_sequences_and_consumes_each_once() {
        let mut options = Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        options.session_type = SessionType::SbfdInitiator;
        options.discriminator = Some(7);
        options.remote_discriminator = Some(99);
        options.auth = AuthType::MeticulousSha1;
        options.auth_key = Some("secret".into());
        let auth = options.validate().unwrap();
        let mut reflector_options = Options::reflector(options.peer, 99);
        reflector_options.auth = options.auth;
        reflector_options.auth_key = options.auth_key.clone();
        let reflector = crate::seamless::Reflector::new(reflector_options, auth.clone()).unwrap();
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
            session.polling,
            session.remote_discriminator,
            session.remote_min_rx_us,
            session.remote_min_tx_us,
            session.last_received,
        );
        let mut invalid = test_packet(State::Down);
        invalid.poll = true;
        invalid.final_bit = true;
        invalid.required_min_rx_us = 0;
        invalid.desired_min_tx_us = 9_000_000;
        assert_eq!(
            session.receive_checked(&wire(&invalid), now + Duration::from_millis(1)),
            Err(ReceiveError::Packet(PacketError::PollAndFinal))
        );
        assert_eq!(
            before,
            (
                session.state,
                session.diagnostic,
                session.polling,
                session.remote_discriminator,
                session.remote_min_rx_us,
                session.remote_min_tx_us,
                session.last_received,
            )
        );
    }

    #[test]
    fn diagnostics_report_failure_and_clear_on_reestablishment() {
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
        assert_eq!(session.packet(false)[0], 0x20);
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
        assert!(session.polling);
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
        assert!(session.polling);
        peer.poll = false;
        peer.final_bit = true;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(!session.polling);
    }
    #[test]
    fn remote_demand_only_suppresses_when_both_ends_are_up() {
        let mut session = session();
        let mut peer = test_packet(State::Init);
        peer.demand = true;
        session.receive(&wire(&peer), Instant::now()).unwrap();
        assert!(session.periodic_enabled());
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

    const AUTH_TYPES: [AuthType; 5] = [
        AuthType::SimplePassword,
        AuthType::KeyedMd5,
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
                    assert_eq!(
                        session.receive(&wire(&peer), now).err(),
                        Some(ReceiveError::Authentication(AuthError::Required)),
                        "{kind:?}, passive={passive}, peer={state:?}"
                    );
                    assert_eq!(session.state, State::Down);
                    assert_eq!(session.remote_discriminator, 0);
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
            assert!(session.polling);
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
                    assert_eq!(
                        session
                            .receive(&wire(&peer), now + Duration::from_millis(599))
                            .err(),
                        Some(ReceiveError::Authentication(AuthError::Required))
                    );
                    assert_eq!(session.state, State::Up);
                    assert_eq!(session.diagnostic, Diagnostic::None);
                    assert_eq!(session.remote_discriminator, 0x10203040);
                    assert!(session.polling);
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
