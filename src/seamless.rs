//! Stateless RFC 7880 reflection; transport validates addresses and UDP ports first.
use crate::{
    config::{Options, ProtocolRole, Timing, ValidatedOptions},
    error::{ConfigError, PacketError},
    packet::{AuthConfig, ControlPacket, Diagnostic, State},
    session::ReceiveError,
};

/// One local S-BFD entity, shared by any number of initiating sessions.
/// No received discriminator, timer, or authentication sequence is retained.
pub struct Reflector {
    discriminator: u32,
    min_rx_us: u32,
    admin_down: bool,
    auth: AuthConfig,
}

impl Reflector {
    /// Creates a reflector from matching, validated settings and authentication.
    ///
    /// # Errors
    /// Rejects invalid options, another protocol role, or mismatched authentication.
    pub fn new(options: Options, auth: AuthConfig) -> Result<Self, ConfigError> {
        let options = options.into_validated()?;
        if options.authentication() != &auth {
            return Err(ConfigError::AuthenticationMismatch);
        }
        Self::from_config(&options)
    }

    /// Constructs a reflector from an immutable snapshot without repeating validation.
    ///
    /// # Errors
    /// Rejects a snapshot for another protocol role.
    pub fn from_config(options: &ValidatedOptions) -> Result<Self, ConfigError> {
        let ProtocolRole::Reflector { discriminator } = options.role() else {
            return Err(ConfigError::WrongReflectorRole);
        };
        Ok(Self {
            discriminator: discriminator.get(),
            min_rx_us: options.min_rx_us,
            admin_down: options.sbfd_admin_down,
            auth: options.authentication().clone(),
        })
    }

    /// Returns the local entity state: Up when available, AdminDown in maintenance.
    pub fn state(&self) -> State {
        if self.admin_down {
            State::AdminDown
        } else {
            State::Up
        }
    }

    /// Changes the advertised receive capacity without creating peer state.
    pub fn set_timing(&mut self, timing: Timing) {
        self.min_rx_us = timing.min_rx_us;
    }

    /// Changes entity availability; requests continue receiving maintenance replies.
    pub fn set_admin_down(&mut self, admin_down: bool) {
        self.admin_down = admin_down;
    }

    /// Validates a request and encodes its response, including Poll/Final handling.
    /// The caller must first check destination/source addresses and UDP ports.
    /// Keyed authentication verifies the digest without retaining a receive window,
    /// then copies the request sequence into the freshly authenticated response.
    ///
    /// # Errors
    /// Rejects malformed packets, wrong discriminators, cleared Demand, invalid
    /// initiator states/receive intervals, or authentication failures without responding.
    pub fn respond(&self, data: &[u8]) -> Result<Vec<u8>, ReceiveError> {
        self.respond_checked(data).map(|response| response.to_vec())
    }

    pub(crate) fn respond_checked(
        &self,
        data: &[u8],
    ) -> Result<crate::packet::PacketBuffer, ReceiveError> {
        let decoded = crate::packet::DecodedPacket::decode(data).map_err(ReceiveError::Packet)?;
        let request = &decoded.control;
        if request.your_discriminator != self.discriminator {
            return Err(ReceiveError::Packet(PacketError::UnknownReflector));
        }
        if !request.demand {
            return Err(ReceiveError::Packet(PacketError::MissingDemand));
        }
        if request.state == State::Init
            || request.required_min_rx_us != 0
            || request.required_min_echo_rx_us != 0
        {
            return Err(ReceiveError::Packet(PacketError::InvalidInitiator));
        }
        let sequence = self
            .auth
            .verify_decoded(&decoded, None)
            .map_err(ReceiveError::Authentication)?;
        let response = ControlPacket {
            diagnostic: if self.admin_down {
                Diagnostic::AdminDown as u8
            } else {
                0
            },
            state: self.state(),
            poll: false,
            final_bit: request.poll,
            control_plane_independent: false,
            demand: false,
            detect_mult: request.detect_mult,
            my_discriminator: request.your_discriminator,
            your_discriminator: request.my_discriminator,
            desired_min_tx_us: request.desired_min_tx_us,
            required_min_rx_us: self.min_rx_us,
            required_min_echo_rx_us: 0,
        };
        Ok(response.encode_buffer(&self.auth, sequence.unwrap_or(0)))
    }
}
