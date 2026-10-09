//! RFC 5880 section 4 wire format and section 6.7 authentication.
use clap::ValueEnum;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

/// Size of the fixed BFD control header, excluding optional authentication.
pub const HEADER_LEN: usize = 24;
const AUTH: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// BFD session states with their two-bit wire values.
pub enum State {
    /// The session is administratively disabled rather than awaiting a peer.
    AdminDown = 0,
    /// Bidirectional communication has not been established or has failed.
    Down = 1,
    /// A peer handshake is in progress after receiving a Down control packet.
    Init = 2,
    /// Bidirectional communication has been established.
    Up = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// Local diagnostic codes emitted by this implementation.
pub enum Diagnostic {
    /// No local failure diagnostic is set.
    None = 0,
    /// No valid control packet arrived within the detection interval.
    DetectionExpired = 1,
    /// The peer signaled Down while Up, or AdminDown while Init/Up.
    NeighborDown = 3,
    /// The local session was administratively disabled.
    AdminDown = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[repr(u8)]
/// Supported RFC 5880 authentication types; None omits the authentication section.
/// Sequence-window descriptions apply to classical BFD. S-BFD reflects request
/// sequences and correlates replies with outstanding initiator probes.
pub enum AuthType {
    /// Omits authentication; the configured key must be empty.
    None = 0,
    /// Sends a cleartext password of 1–16 bytes without sequence protection.
    SimplePassword = 1,
    /// Uses an MD5 digest and a sequence window; repeated sequences are allowed.
    KeyedMd5 = 2,
    /// Uses an MD5 digest and rejects repeated sequences within the receive window.
    MeticulousMd5 = 3,
    /// Uses a SHA-1 digest and a sequence window; repeated sequences are allowed.
    KeyedSha1 = 4,
    /// Uses a SHA-1 digest and rejects repeated sequences within the receive window.
    MeticulousSha1 = 5,
}

impl AuthType {
    fn hash_len(self) -> usize {
        match self {
            Self::KeyedMd5 | Self::MeticulousMd5 => 16,
            Self::KeyedSha1 | Self::MeticulousSha1 => 20,
            _ => 0,
        }
    }
    fn meticulous(self) -> bool {
        matches!(self, Self::MeticulousMd5 | Self::MeticulousSha1)
    }
}

// Deliberately no Debug implementation: never include key material in logs.
/// Validated authentication settings. Reconstruct to change the type or key.
///
/// ```compile_fail
/// use bfd_winservice::packet::{AuthConfig, AuthType};
/// let mut auth = AuthConfig::new(AuthType::KeyedSha1, 0, vec![1; 20]).unwrap();
/// auth.kind = AuthType::KeyedMd5; // Would invalidate the validated key length.
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AuthConfig {
    kind: AuthType,
    key_id: u8,
    key: Vec<u8>,
}

impl AuthConfig {
    /// Return the validated authentication type without exposing mutation.
    pub fn kind(&self) -> AuthType {
        self.kind
    }

    /// Validate the key length for this type; None requires an empty key.
    ///
    /// # Errors
    /// Returns an error for a missing, oversized, or unexpected key.
    pub fn new(kind: AuthType, key_id: u8, key: Vec<u8>) -> Result<Self, String> {
        let max = if kind == AuthType::SimplePassword {
            16
        } else {
            kind.hash_len()
        };
        if kind == AuthType::None {
            if !key.is_empty() {
                return Err("an authentication key requires Auth".into());
            }
        } else if key.is_empty() || key.len() > max {
            return Err(format!("{kind:?} requires a key of 1..{max} bytes"));
        }
        Ok(Self { kind, key_id, key })
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self.kind {
            AuthType::KeyedMd5 | AuthType::MeticulousMd5 => md5::compute(data).0.to_vec(),
            AuthType::KeyedSha1 | AuthType::MeticulousSha1 => Sha1::digest(data).to_vec(),
            _ => unreachable!("digest only used for keyed authentication"),
        }
    }

    /// Check packet structure, configured authentication, and keyed sequence bounds.
    ///
    /// Only bytes within the declared BFD Length participate in authentication.
    /// Returns the accepted keyed sequence, or None for password/no authentication;
    /// the caller owns and commits sequence tracking. None as last_seq allows
    /// initial synchronization. This method does not update tracking itself.
    ///
    /// # Errors
    /// Rejects malformed packets, authentication mismatches, invalid digests/passwords,
    /// and sequences outside the configured authentication's receive window.
    pub fn verify(&self, data: &[u8], last_seq: Option<u32>) -> Result<Option<u32>, &'static str> {
        // Keep the authentication API safe even when called independently of Session.
        ControlPacket::decode(data)?;
        let data = &data[..usize::from(data[3])];
        if data[1] & AUTH == 0 {
            return if self.kind == AuthType::None {
                Ok(None)
            } else {
                Err("authentication required")
            };
        }
        if self.kind == AuthType::None {
            return Err("unexpected authenticated packet");
        }
        if data[24] != self.kind as u8 {
            return Err("authentication type mismatch");
        }
        let auth_len = usize::from(data[25]);
        if auth_len < 3 || HEADER_LEN + auth_len != data.len() {
            return Err("invalid authentication length");
        }
        if data[26] != self.key_id {
            return Err("authentication key ID mismatch");
        }
        if self.kind == AuthType::SimplePassword {
            if auth_len != 3 + self.key.len() || !bool::from(data[27..].ct_eq(&self.key)) {
                return Err("password mismatch");
            }
            return Ok(None);
        }
        if auth_len != 8 + self.kind.hash_len() {
            return Err("invalid keyed authentication length");
        }
        let seq = word(data, 28);
        if let Some(last) = last_seq {
            let delta = seq.wrapping_sub(last);
            if (self.kind.meticulous() && delta == 0) || delta > 3 * u32::from(data[2]) {
                return Err("authentication sequence outside receive window");
            }
        }
        let mut signed = data.to_vec();
        signed[32..].fill(0);
        signed[32..32 + self.key.len()].copy_from_slice(&self.key);
        if !bool::from(data[32..].ct_eq(&self.digest(&signed))) {
            return Err("authentication digest mismatch");
        }
        // Return the accepted sequence only after cryptographic verification succeeds.
        Ok(Some(seq))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Decoded fixed header fields, excluding authentication data.
///
/// Public fields may represent an invalid packet. Encode serializes them without
/// validation; decode and AuthConfig::verify perform the receive-side checks.
pub struct ControlPacket {
    /// The sender's five-bit diagnostic code, 0–31; encoding masks higher bits.
    pub diagnostic: u8,
    /// The sender's advertised BFD state.
    pub state: State,
    /// If true, requests a Final reply as part of a Poll sequence.
    pub poll: bool,
    /// If true, acknowledges a received Poll; false for ordinary control packets.
    pub final_bit: bool,
    /// True if the sender advertises BFD independence from its control plane.
    pub control_plane_independent: bool,
    /// True if a classical sender requests Demand mode or the sender is an S-BFD
    /// initiator; false for classical asynchronous operation and S-BFD reflectors.
    pub demand: bool,
    /// The advertised detection multiplier, 1–255; decoding rejects zero.
    pub detect_mult: u8,
    /// The sender's nonzero session identifier; decoding rejects zero.
    pub my_discriminator: u32,
    /// The learned classical peer identifier or provisioned S-BFD target;
    /// zero is allowed only in Down or AdminDown.
    pub your_discriminator: u32,
    /// The desired transmit interval in microseconds; decoding rejects zero.
    pub desired_min_tx_us: u32,
    /// The required control receive interval in microseconds; zero suppresses
    /// a classical peer's periodic control transmission. S-BFD reflectors still
    /// answer each valid request even when an initiator advertises zero.
    pub required_min_rx_us: u32,
    /// The required Echo receive interval in microseconds; this implementation
    /// advertises zero because it does not implement Echo.
    pub required_min_echo_rx_us: u32,
}

fn word(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("validated packet bounds"),
    )
}

impl ControlPacket {
    /// Decode the fixed header and check supported structural constraints.
    ///
    /// A declared BFD Length shorter than the UDP payload is allowed. This does
    /// not verify authentication, the expected discriminator, or transport metadata.
    ///
    /// # Errors
    /// Rejects truncated/invalid lengths, unsupported version/multipoint,
    /// simultaneous Poll/Final, and reserved zero multiplier, sender
    /// discriminator, or desired TX interval;
    /// Init/Up also require a nonzero receiver discriminator.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HEADER_LEN {
            return Err("truncated header");
        }
        if data[0] >> 5 != 1 {
            return Err("unsupported version");
        }
        let minimum = if data[1] & AUTH == 0 {
            HEADER_LEN
        } else {
            HEADER_LEN + 2
        };
        if usize::from(data[3]) < minimum || usize::from(data[3]) > data.len() {
            return Err("invalid packet length");
        }
        if data[2] == 0 {
            return Err("zero detection multiplier");
        }
        if data[1] & 1 != 0 {
            return Err("multipoint is unsupported");
        }
        if data[1] & 0x30 == 0x30 {
            return Err("Poll and Final cannot both be set");
        }
        if word(data, 4) == 0 {
            return Err("zero sender discriminator");
        }
        let state = match data[1] >> 6 {
            0 => State::AdminDown,
            1 => State::Down,
            2 => State::Init,
            _ => State::Up,
        };
        if word(data, 8) == 0 && !matches!(state, State::Down | State::AdminDown) {
            return Err("zero receiver discriminator in Init/Up");
        }
        if word(data, 12) == 0 {
            return Err("reserved zero desired transmit interval");
        }
        Ok(Self {
            diagnostic: data[0] & 0x1f,
            state,
            poll: data[1] & 0x20 != 0,
            final_bit: data[1] & 0x10 != 0,
            control_plane_independent: data[1] & 0x08 != 0,
            demand: data[1] & 0x02 != 0,
            detect_mult: data[2],
            my_discriminator: word(data, 4),
            your_discriminator: word(data, 8),
            desired_min_tx_us: word(data, 12),
            required_min_rx_us: word(data, 16),
            required_min_echo_rx_us: word(data, 20),
        })
    }

    /// Serialize header fields and add the configured authentication section.
    ///
    /// Does not validate header fields. The supplied sequence is used only by
    /// keyed authentication; this method does not advance sequence tracking.
    pub fn encode(&self, auth: &AuthConfig, sequence: u32) -> Vec<u8> {
        let mut data = vec![0; HEADER_LEN];
        data[0] = 0x20 | (self.diagnostic & 0x1f);
        data[1] = (self.state as u8) << 6
            | u8::from(self.poll) << 5
            | u8::from(self.final_bit) << 4
            | u8::from(self.control_plane_independent) << 3
            | u8::from(self.demand) << 1;
        data[2] = self.detect_mult;
        for (offset, value) in [
            (4, self.my_discriminator),
            (8, self.your_discriminator),
            (12, self.desired_min_tx_us),
            (16, self.required_min_rx_us),
            (20, self.required_min_echo_rx_us),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        if auth.kind != AuthType::None {
            data[1] |= AUTH;
            if auth.kind == AuthType::SimplePassword {
                data.extend_from_slice(&[1, (3 + auth.key.len()) as u8, auth.key_id]);
                data.extend_from_slice(&auth.key);
            } else {
                data.extend_from_slice(&[
                    auth.kind as u8,
                    (8 + auth.kind.hash_len()) as u8,
                    auth.key_id,
                    0,
                ]);
                data.extend_from_slice(&sequence.to_be_bytes());
                data.extend_from_slice(&auth.key);
                data.resize(32 + auth.kind.hash_len(), 0);
            }
        }
        data[3] = data.len() as u8;
        if auth.kind.hash_len() != 0 {
            let digest = auth.digest(&data);
            data[32..].copy_from_slice(&digest);
        }
        data
    }
}

#[cfg(test)]
pub(crate) fn test_packet(state: State) -> ControlPacket {
    ControlPacket {
        diagnostic: 0,
        state,
        poll: false,
        final_bit: false,
        control_plane_independent: false,
        demand: false,
        detect_mult: 3,
        my_discriminator: 0x10203040,
        your_discriminator: 7,
        desired_min_tx_us: 100_000,
        required_min_rx_us: 200_000,
        required_min_echo_rx_us: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_network_byte_order_fixture() {
        let packet = test_packet(State::Down);
        let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        let fixture = [
            0x20, 0x40, 3, 24, 0x10, 0x20, 0x30, 0x40, 0, 0, 0, 7, 0, 1, 0x86, 0xa0, 0, 3, 0x0d,
            0x40, 0, 0, 0, 0,
        ];
        assert_eq!(packet.encode(&auth, 0), fixture);
        assert_eq!(ControlPacket::decode(&fixture).unwrap(), packet);
    }

    #[test]
    fn state_diagnostic_and_flag_bits_match_rfc_5880() {
        let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        for (state, state_bits) in [
            (State::AdminDown, 0x00),
            (State::Down, 0x40),
            (State::Init, 0x80),
            (State::Up, 0xc0),
        ] {
            for diagnostic in 0..=31 {
                let mut packet = test_packet(state);
                packet.diagnostic = diagnostic;
                let data = packet.encode(&auth, 0);
                assert_eq!(data[0], 0x20 | diagnostic);
                assert_eq!(data[1], state_bits);
                assert_eq!(ControlPacket::decode(&data).unwrap(), packet);
            }
        }
        for (poll, final_bit, independent, demand, flags) in [
            (true, false, false, false, 0x20),
            (false, true, false, false, 0x10),
            (false, false, true, false, 0x08),
            (false, false, false, true, 0x02),
            (true, false, true, true, 0x2a),
            (false, true, true, true, 0x1a),
        ] {
            let mut packet = test_packet(State::Up);
            packet.poll = poll;
            packet.final_bit = final_bit;
            packet.control_plane_independent = independent;
            packet.demand = demand;
            let data = packet.encode(&auth, 0);
            assert_eq!(data[1], 0xc0 | flags);
            assert_eq!(ControlPacket::decode(&data).unwrap(), packet);
        }
    }

    #[test]
    fn authentication_presence_lengths_and_fields_match_rfc_5880() {
        for (kind, auth_len) in [
            (AuthType::None, 0),
            (AuthType::SimplePassword, 9),
            (AuthType::KeyedMd5, 24),
            (AuthType::MeticulousMd5, 24),
            (AuthType::KeyedSha1, 28),
            (AuthType::MeticulousSha1, 28),
        ] {
            let key = if kind == AuthType::None {
                vec![]
            } else {
                b"secret".to_vec()
            };
            let auth = AuthConfig::new(kind, 9, key).unwrap();
            let data = test_packet(State::Up).encode(&auth, 0x10203040);
            assert_eq!(data[1], if kind == AuthType::None { 0xc0 } else { 0xc4 });
            assert_eq!(usize::from(data[3]), HEADER_LEN + auth_len);
            assert_eq!(data.len(), HEADER_LEN + auth_len);
            if auth_len != 0 {
                assert_eq!(data[24], kind as u8);
                assert_eq!(usize::from(data[25]), auth_len);
                assert_eq!(data[26], 9);
                if kind == AuthType::SimplePassword {
                    assert_eq!(&data[27..], b"secret");
                } else {
                    assert_eq!(data[27], 0, "reserved authentication byte");
                    assert_eq!(&data[28..32], &[0x10, 0x20, 0x30, 0x40]);
                }
            }
            assert!(auth.verify(&data, None).is_ok());
        }
    }

    #[test]
    fn simultaneous_poll_and_final_are_rejected() {
        let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        let mut data = test_packet(State::Up).encode(&auth, 0);
        data[1] |= 0x30;
        assert_eq!(
            ControlPacket::decode(&data),
            Err("Poll and Final cannot both be set")
        );
    }
    #[test]
    fn rejects_malformed_packets_without_panicking() {
        let auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        let good = test_packet(State::Up).encode(&auth, 0);
        for len in 0..24 {
            assert!(ControlPacket::decode(&good[..len]).is_err());
        }
        for (offset, value) in [(0, 0x40), (3, 23), (3, 25), (2, 0), (1, 0xc1)] {
            let mut bad = good.clone();
            bad[offset] = value;
            assert!(ControlPacket::decode(&bad).is_err());
        }
        let mut bad = good.clone();
        bad[4..8].fill(0);
        assert!(ControlPacket::decode(&bad).is_err());
        let mut bad = good.clone();
        bad[8..12].fill(0);
        assert!(ControlPacket::decode(&bad).is_err());
        // RFC Length can be shorter than the enclosing UDP payload.
        let mut padded = good.clone();
        padded.extend_from_slice(&[0, 0]);
        assert!(ControlPacket::decode(&padded).is_ok());
    }
    #[test]
    fn configured_authentication_rejects_missing_or_cleared_authentication_bit() {
        let no_auth = AuthConfig::new(AuthType::None, 0, vec![]).unwrap();
        let packet = test_packet(State::Init);
        let unauthenticated = packet.encode(&no_auth, 0);
        assert_eq!(no_auth.verify(&unauthenticated, None), Ok(None));
        for kind in [
            AuthType::SimplePassword,
            AuthType::KeyedMd5,
            AuthType::MeticulousMd5,
            AuthType::KeyedSha1,
            AuthType::MeticulousSha1,
        ] {
            let auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
            assert_eq!(
                auth.verify(&unauthenticated, None),
                Err("authentication required")
            );
            let mut data = packet.encode(&auth, 100);
            assert_eq!(
                no_auth.verify(&data, None),
                Err("unexpected authenticated packet")
            );
            data[1] &= !AUTH;
            assert_eq!(auth.verify(&data, None), Err("authentication required"));
        }
    }
    #[test]
    fn all_authentication_types_reject_tampering_and_wrong_keys() {
        for kind in [
            AuthType::SimplePassword,
            AuthType::KeyedMd5,
            AuthType::MeticulousMd5,
            AuthType::KeyedSha1,
            AuthType::MeticulousSha1,
        ] {
            let auth = AuthConfig::new(kind, 9, b"secret".to_vec()).unwrap();
            let mut data = test_packet(State::Up).encode(&auth, 100);
            ControlPacket::decode(&data).unwrap();
            assert!(auth.verify(&data, None).is_ok());
            assert!(AuthConfig::new(kind, 9, b"wrong".to_vec())
                .unwrap()
                .verify(&data, None)
                .is_err());
            let end = data.len() - 1;
            data[end] ^= 1;
            assert!(auth.verify(&data, None).is_err());
            let mut truncated = data[..26].to_vec();
            truncated[3] = 26;
            assert!(auth.verify(&truncated, None).is_err());
        }
    }
    #[test]
    fn keyed_digests_match_independently_calculated_wire_fixtures() {
        // Reference hashes generated over explicit RFC-formatted bytes using .NET's
        // SHA1.HashData and MD5.HashData, independently of this codec.
        let fixtures: &[(AuthType, &[u8])] = &[
            (
                AuthType::MeticulousSha1,
                &[
                    0x75, 0xb8, 0xaf, 0xb3, 0x60, 0xcb, 0x0f, 0x50, 0x8e, 0x93, 0x91, 0xe3, 0x32,
                    0x44, 0xd0, 0x2a, 0x83, 0x42, 0xa5, 0xbf,
                ],
            ),
            (
                AuthType::MeticulousMd5,
                &[
                    0xcb, 0xdd, 0x18, 0x66, 0x23, 0x99, 0xd1, 0xa5, 0x08, 0xc6, 0x90, 0x3d, 0x17,
                    0xeb, 0xdd, 0x89,
                ],
            ),
        ];
        for (kind, digest) in fixtures {
            let auth = AuthConfig::new(*kind, 9, b"secret".to_vec()).unwrap();
            let data = test_packet(State::Up).encode(&auth, 100);
            assert_eq!(&data[32..], *digest);
        }
    }
    #[test]
    fn sequence_window_wraps_and_distinguishes_meticulous() {
        for kind in [AuthType::KeyedSha1, AuthType::MeticulousSha1] {
            let auth = AuthConfig::new(kind, 0, b"secret".to_vec()).unwrap();
            let packet = test_packet(State::Up);
            assert!(auth
                .verify(&packet.encode(&auth, 0), Some(u32::MAX))
                .is_ok());
            assert!(auth.verify(&packet.encode(&auth, 109), Some(100)).is_ok());
            assert!(auth.verify(&packet.encode(&auth, 110), Some(100)).is_err());
            assert!(auth.verify(&packet.encode(&auth, 99), Some(100)).is_err());
            assert_eq!(
                auth.verify(&packet.encode(&auth, 100), Some(100)).is_ok(),
                !kind.meticulous()
            );
        }
    }
}
