//! Asynchronous BFD state, timers, and authentication tracking based on RFC 5880.
//!
//! The caller supplies monotonic receive/expiry times and handles transport I/O.
//! Discriminators, initial authentication sequences, and transmit jitter use randomness.
use rand::Rng;
use std::time::{Duration, Instant};

use crate::{
    config::Options,
    packet::{AuthConfig, ControlPacket, Diagnostic, State},
};

/// One validated BFD session; callers drive packet reception and expiry.
pub struct Session {
    pub(crate) state: State,
    pub(crate) diagnostic: Diagnostic,
    pub(crate) local_discriminator: u32,
    pub(crate) remote_discriminator: u32,
    pub(crate) polling: bool,
    options: Options,
    auth: AuthConfig,
    remote_state: State,
    remote_demand: bool,
    remote_min_rx_us: u32,
    remote_min_tx_us: u32,
    remote_detect_mult: u8,
    last_received: Option<Instant>,
    received_auth_seq: Option<u32>,
    transmit_auth_seq: u32,
}

/// Effects of accepting a control packet; no response has been transmitted yet.
pub struct Received {
    /// Send a Final reply independently of the periodic transmit schedule.
    pub reply_final: bool,
    /// The local BFD state changed while processing this packet.
    pub state_changed: bool,
}

/// Internal rejection classification for logging; public callers retain the
/// existing static-string error API. Reasons never contain packet/key bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiveError {
    Packet(&'static str),
    Authentication(&'static str),
}

impl ReceiveError {
    fn reason(self) -> &'static str {
        match self {
            Self::Packet(reason) | Self::Authentication(reason) => reason,
        }
    }
}

impl Session {
    /// Create a session only from valid, matching configuration and authentication.
    ///
    /// # Errors
    /// Returns an error for invalid options or mismatched authentication settings.
    pub fn new(mut options: Options, auth: AuthConfig) -> Result<Self, String> {
        if options.validate()? != auth {
            return Err("session authentication does not match its configured settings".into());
        }
        let local_discriminator = options
            .discriminator
            .unwrap_or_else(|| rand::thread_rng().gen_range(1..=u32::MAX));
        Ok(Self {
            state: State::Down,
            diagnostic: Diagnostic::None,
            local_discriminator,
            remote_discriminator: 0,
            polling: false,
            options,
            auth,
            remote_state: State::Down,
            remote_demand: false,
            remote_min_rx_us: 1,
            remote_min_tx_us: 1_000_000,
            remote_detect_mult: 1,
            last_received: None,
            received_auth_seq: None,
            transmit_auth_seq: rand::random(),
        })
    }

    /// Return the current local BFD state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Return the reason for the most recent state change.
    pub fn diagnostic(&self) -> Diagnostic {
        self.diagnostic
    }

    /// Return the immutable, nonzero local session identifier.
    pub fn local_discriminator(&self) -> u32 {
        self.local_discriminator
    }

    /// Return the learned peer identifier, or zero if unknown or expired.
    pub fn remote_discriminator(&self) -> u32 {
        self.remote_discriminator
    }

    /// Return whether a local Poll sequence is pending.
    pub fn polling(&self) -> bool {
        self.polling
    }

    /// Advertised desired TX interval: configured Up rate, otherwise the greater
    /// of the configured startup and Up rates (including AdminDown).
    pub fn desired_min_tx_us(&self) -> u32 {
        if self.state == State::Up {
            self.options.min_tx_us
        } else {
            self.options.startup_tx_us.max(self.options.min_tx_us)
        }
    }

    /// Negotiated TX interval before jitter, whether or not traffic is enabled.
    pub fn transmit_interval(&self) -> Duration {
        Duration::from_micros(u64::from(
            self.desired_min_tx_us().max(self.remote_min_rx_us),
        ))
    }

    /// Peer multiplier times the greater of local required RX and peer desired TX.
    pub fn detection_time(&self) -> Duration {
        Duration::from_micros(
            u64::from(self.options.min_rx_us.max(self.remote_min_tx_us))
                * u64::from(self.remote_detect_mult),
        )
    }

    /// Next receive-expiry deadline while a remote discriminator is known.
    pub fn detection_deadline(&self) -> Option<Instant> {
        // Also wake in Down to forget the remote discriminator after one Detection Time.
        self.last_received
            .filter(|_| self.remote_discriminator != 0)
            .map(|last| last + self.detection_time())
    }

    /// Active/passive role gate; does not apply periodic Demand/zero-RX suppression.
    pub fn can_transmit(&self) -> bool {
        !self.options.passive || self.remote_discriminator != 0
    }

    /// Whether the role and peer Demand/required RX settings allow periodic traffic.
    pub fn periodic_enabled(&self) -> bool {
        self.can_transmit()
            && !(self.remote_min_rx_us == 0
                || self.remote_demand
                    && self.state == State::Up
                    && self.remote_state == State::Up
                    && !self.polling)
    }

    /// Sample 75-100% of the negotiated interval (75-90% for multiplier 1).
    /// This calculates an interval even when periodic transmission is disabled.
    pub fn jittered_interval(&self) -> Duration {
        let upper = if self.options.detect_mult == 1 {
            9000
        } else {
            10000
        };
        let factor = rand::thread_rng().gen_range(7500..=upper);
        Duration::from_nanos((self.transmit_interval().as_nanos() * factor / 10000) as u64)
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
    pub fn receive(&mut self, data: &[u8], now: Instant) -> Result<Received, &'static str> {
        self.receive_checked(data, now)
            .map_err(ReceiveError::reason)
    }

    /// Preserve the rejection stage so runtime logging does not classify errors
    /// by comparing human-readable messages.
    pub(crate) fn receive_checked(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<Received, ReceiveError> {
        let packet = ControlPacket::decode(data).map_err(ReceiveError::Packet)?;
        if packet.your_discriminator != 0 && packet.your_discriminator != self.local_discriminator {
            return Err(ReceiveError::Packet(
                "receiver discriminator does not identify this session",
            ));
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
        Ok(Received {
            reply_final: packet.poll,
            state_changed: previous_state != self.state,
        })
    }

    /// Apply receive expiry and return whether the local state changed.
    ///
    /// Clears the remote discriminator after one detection time and authentication
    /// sequence tracking after two. Returns false if only that tracking changed.
    /// Peer timer parameters are retained; Init/Up transition to Down.
    pub fn expire(&mut self, now: Instant) -> bool {
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
    pub fn packet(&mut self, final_bit: bool) -> Vec<u8> {
        let packet = ControlPacket {
            diagnostic: self.diagnostic as u8,
            state: self.state,
            poll: self.polling && !final_bit,
            final_bit,
            control_plane_independent: false,
            demand: false,
            detect_mult: self.options.detect_mult,
            my_discriminator: self.local_discriminator,
            your_discriminator: self.remote_discriminator,
            desired_min_tx_us: self.desired_min_tx_us(),
            required_min_rx_us: self.options.min_rx_us,
            required_min_echo_rx_us: 0,
        };
        let data = packet.encode(&self.auth, self.transmit_auth_seq);
        // Reserve the next sequence for each generated packet, even if sending fails.
        // Incrementing per transmitted packet is also legal for non-meticulous auth.
        self.transmit_auth_seq = self.transmit_auth_seq.wrapping_add(1);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{test_packet, AuthType};

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
        let valid = session().options;
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
                session.state = *local;
                session
                    .receive(&wire(&test_packet(*remote)), Instant::now())
                    .unwrap();
                assert_eq!(session.state, expected[i][j], "{local:?} / {remote:?}");
            }
        }
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
        let mut session = session();
        session.options.passive = true;
        session.options.detect_mult = 1;
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
                (wire(&peer), "authentication required"),
                (
                    peer.encode(&wrong_id, 100),
                    "authentication key ID mismatch",
                ),
                (
                    peer.encode(&wrong_type, 100),
                    "authentication type mismatch",
                ),
                (invalid_length, "invalid authentication length"),
                (
                    peer.encode(&wrong_key, 100),
                    if kind == AuthType::SimplePassword {
                        "password mismatch"
                    } else {
                        "authentication digest mismatch"
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
                Some(ReceiveError::Packet("unsupported version"))
            );
            let mut wrong_session = peer.clone();
            wrong_session.your_discriminator = 42;
            assert_eq!(
                session.receive_checked(&wire(&wrong_session), now).err(),
                Some(ReceiveError::Packet(
                    "receiver discriminator does not identify this session"
                ))
            );
            session
                .receive_checked(&peer.encode(&auth, 100), now)
                .unwrap();
            if kind != AuthType::SimplePassword {
                assert_eq!(
                    session.receive_checked(&peer.encode(&auth, 99), now).err(),
                    Some(ReceiveError::Authentication(
                        "authentication sequence outside receive window"
                    ))
                );
                assert_eq!(session.received_auth_seq, Some(100));
            }
        }
        let mut session = session();
        let auth = AuthConfig::new(AuthType::MeticulousSha1, 9, b"secret".to_vec()).unwrap();
        assert_eq!(
            session.receive_checked(&peer.encode(&auth, 100), now).err(),
            Some(ReceiveError::Authentication(
                "unexpected authenticated packet"
            ))
        );
    }

    #[test]
    fn authentication_is_required_before_handshake_or_poll_reply() {
        let now = Instant::now();
        for kind in AUTH_TYPES {
            for passive in [false, true] {
                let mut session = session();
                session.auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
                session.options.passive = passive;
                for state in [State::AdminDown, State::Down, State::Init, State::Up] {
                    let mut peer = test_packet(state);
                    peer.poll = true;
                    peer.required_min_rx_us = 0;
                    peer.demand = true;
                    assert_eq!(
                        session.receive(&wire(&peer), now).err(),
                        Some("authentication required"),
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
                    Some("authentication required")
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
                        Some("authentication required")
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
