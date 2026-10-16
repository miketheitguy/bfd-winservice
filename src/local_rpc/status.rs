//! Fixed RPC integers are converted once into owned Rust domain values.
#![forbid(unsafe_code)]

use crate::{
    config::{Mode, SessionType},
    packet::{Diagnostic, State},
    runtime::StatusSnapshot,
};
use std::{
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    num::{NonZeroU128, NonZeroU32, NonZeroU64, NonZeroU8},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const VERSION: u32 = 1;
const PEER_ADDRESS: u64 = 1 << 0;
const SOURCE: u64 = 1 << 1;
const INTERFACE: u64 = 1 << 2;
const REMOTE_DISC: u64 = 1 << 3;
const PEER_REPORT: u64 = 1 << 4;
const COMMUNICATING: u64 = 1 << 5;
const RECEIVE: u64 = 1 << 6;
const SEND: u64 = 1 << 7;
const UP: u64 = 1 << 8;
const DOWN: u64 = 1 << 9;
const TX_INTERVAL: u64 = 1 << 10;
const DETECTION: u64 = 1 << 11;
const LOCAL_MULT: u64 = 1 << 12;
const KNOWN_FIELDS: u64 = (1 << 13) - 1;
// V1 supports Windows calendar years 1601..=9999, and 100 years of uptime.
const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;
const MAX_AGE_US: u64 = 100 * 366 * 24 * 60 * 60 * 1_000_000;
const MAX_TX_US: u64 = u32::MAX as u64;
const MAX_DETECTION_US: u64 = MAX_TX_US * 256;
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

/// A rejected wire value or native RPC failure. No untrusted payload is logged.
#[derive(Debug, thiserror::Error)]
pub enum SessionStatusQueryError {
    /// A stuck native worker disabled telemetry until restart.
    #[error("BFD telemetry is quarantined until broker restart")]
    Quarantined,
    /// The record cannot be represented by the V1 Rust domain types.
    #[error("invalid BFD status field: {0}")]
    InvalidData(&'static str),
    /// Windows rejected authentication, transport, availability, or the call.
    #[error("BFD status RPC failed: {0}")]
    Rpc(#[from] io::Error),
}

impl SessionStatusQueryError {
    pub(crate) fn invalid_data(&self) -> bool {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_DATA, RPC_X_BAD_STUB_DATA, RPC_X_BYTE_COUNT_TOO_SMALL,
            RPC_X_ENUM_VALUE_OUT_OF_RANGE, RPC_X_INVALID_BOUND, RPC_X_NULL_REF_POINTER,
        };
        match self {
            Self::InvalidData(_) => true,
            Self::Quarantined => false,
            Self::Rpc(error) => {
                error.kind() == io::ErrorKind::InvalidData
                    || error.raw_os_error().is_some_and(|code| {
                        [
                            ERROR_INVALID_DATA as i32,
                            RPC_X_BAD_STUB_DATA,
                            RPC_X_BYTE_COUNT_TOO_SMALL,
                            RPC_X_ENUM_VALUE_OUT_OF_RANGE,
                            RPC_X_INVALID_BOUND,
                            RPC_X_NULL_REF_POINTER,
                        ]
                        .contains(&code)
                    })
            }
        }
    }
}

type Result<T> = std::result::Result<T, SessionStatusQueryError>;

fn invalid(field: &'static str) -> SessionStatusQueryError {
    SessionStatusQueryError::InvalidData(field)
}

/// One coherent, validated status response. Peer reports can remain historical.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionStatus {
    /// Changes when the BFD engine is constructed again.
    pub engine_instance_id: NonZeroU128,
    /// Opaque publication identifier; compare for equality within an instance.
    pub publication_sequence: NonZeroU64,
    /// UTC engine capture time; use monotonic ages for freshness.
    pub captured_at_utc: SystemTime,
    /// Engine uptime measured when the RPC manager read the snapshot.
    pub engine_uptime: Duration,
    /// Monotonic snapshot age when the RPC manager read it.
    pub snapshot_age: Duration,
    /// Configured protocol role.
    pub session_type: SessionType,
    /// Configured UDP transport profile.
    pub transport_mode: Mode,
    /// Local state at publication.
    pub local_state: State,
    /// Last accepted peer state, absent before reception and for reflectors.
    pub peer_state: Option<State>,
    /// Local diagnostic at publication.
    pub local_diagnostic: Diagnostic,
    /// Last peer diagnostic, including reserved five-bit values.
    pub peer_diagnostic: Option<u8>,
    /// Communication status at publication; absent for a stateless reflector.
    pub communicating: Option<bool>,
    /// Last accepted receive time and monotonic age at the RPC read.
    pub last_valid_receive: Option<(SystemTime, Duration)>,
    /// Last successful send time and monotonic age at the RPC read.
    pub last_successful_send: Option<(SystemTime, Duration)>,
    /// UTC start of the published local state.
    pub state_since_utc: SystemTime,
    /// Last transition to Up, if any.
    pub last_up_utc: Option<SystemTime>,
    /// Last Down/AdminDown transition and diagnostic, if any.
    pub last_down: Option<(SystemTime, Diagnostic)>,
    /// Bound source address and actual UDP source port.
    pub local_address: SocketAddr,
    /// Configured peer and control destination port, absent for reflectors.
    pub peer_address: Option<SocketAddr>,
    /// Last accepted source, absent before reception.
    pub last_accepted_source: Option<SocketAddr>,
    /// Control/listen UDP port selected by the protocol role.
    pub control_port: std::num::NonZeroU16,
    /// Configured interface index, if any.
    pub interface_index: Option<NonZeroU32>,
    /// Nonzero local session/reflector discriminator.
    pub local_discriminator: NonZeroU32,
    /// Active learned or configured remote discriminator, if applicable.
    pub remote_discriminator: Option<NonZeroU32>,
    /// Effective transmit interval before jitter, absent for reflectors.
    pub effective_tx_interval: Option<Duration>,
    /// Detection duration, absent for reflectors.
    pub detection_time: Option<Duration>,
    /// Local detection multiplier, absent for reflectors.
    pub local_detect_multiplier: Option<NonZeroU8>,
    /// Last accepted peer multiplier, absent before reception/for reflectors.
    pub peer_detect_multiplier: Option<NonZeroU8>,
    /// Saturating accepted packet counter for this engine instance.
    pub packets_received_accepted: u64,
    /// Saturating successful send counter.
    pub packets_sent_successfully: u64,
    /// Saturating rejected packet counter.
    pub packets_rejected: u64,
    /// Saturating authentication rejection counter.
    pub authentication_failures: u64,
    /// Saturating socket error counter.
    pub socket_errors: u64,
    /// Saturating detection expiry counter.
    pub detection_timeouts: u64,
    /// Saturating transition-to-Up counter.
    pub up_transitions: u64,
}

// Only integer bit patterns cross FFI. This layout mirrors the frozen MIDL V1
// record; a native layout test checks its size, alignment and key offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WireAddress {
    pub family: u32,
    pub port: u32,
    pub scope: u32,
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WireStatus {
    pub version: u32,
    pub size: u32,
    pub fields: u64,
    pub instance: [u8; 16],
    pub sequence: u64,
    pub captured_utc: u64,
    pub uptime_us: u64,
    pub age_us: u64,
    pub received_utc: u64,
    pub received_age_us: u64,
    pub sent_utc: u64,
    pub sent_age_us: u64,
    pub state_since_utc: u64,
    pub up_utc: u64,
    pub down_utc: u64,
    pub tx_us: u64,
    pub detection_us: u64,
    pub received: u64,
    pub sent: u64,
    pub rejected: u64,
    pub auth_failures: u64,
    pub socket_errors: u64,
    pub detection_timeouts: u64,
    pub up_transitions: u64,
    pub role: u32,
    pub mode: u32,
    pub local_state: u32,
    pub peer_state: u32,
    pub local_diag: u32,
    pub peer_diag: u32,
    pub communicating: u32,
    pub local_disc: u32,
    pub remote_disc: u32,
    pub local_mult: u32,
    pub peer_mult: u32,
    pub down_reason: u32,
    pub interface: u32,
    pub control_port: u32,
    pub local: WireAddress,
    pub peer: WireAddress,
    pub source: WireAddress,
}

const _: () = assert!(size_of::<WireStatus>() < 1024);

fn state(value: u32) -> Result<State> {
    match value {
        0 => Ok(State::AdminDown),
        1 => Ok(State::Down),
        2 => Ok(State::Init),
        3 => Ok(State::Up),
        _ => Err(invalid("state")),
    }
}

fn diagnostic(value: u32) -> Result<Diagnostic> {
    match value {
        0 => Ok(Diagnostic::None),
        1 => Ok(Diagnostic::DetectionExpired),
        3 => Ok(Diagnostic::NeighborDown),
        7 => Ok(Diagnostic::AdminDown),
        _ => Err(invalid("local diagnostic")),
    }
}

fn boolean(value: u32) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("boolean")),
    }
}

fn multiplier(value: u32) -> Result<NonZeroU8> {
    u8::try_from(value)
        .ok()
        .and_then(NonZeroU8::new)
        .ok_or_else(|| invalid("multiplier"))
}

fn discriminator(value: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(value).ok_or_else(|| invalid("discriminator"))
}

fn duration(value: u64, max: u64) -> Result<Duration> {
    (value <= max)
        .then(|| Duration::from_micros(value))
        .ok_or_else(|| invalid("duration"))
}

fn filetime(value: u64) -> Result<SystemTime> {
    if !(1..=MAX_FILETIME).contains(&value) {
        return Err(invalid("UTC time"));
    }
    UNIX_EPOCH
        .checked_sub(Duration::from_secs(FILETIME_UNIX_OFFSET))
        .and_then(|epoch| {
            epoch.checked_add(Duration::new(
                value / 10_000_000,
                ((value % 10_000_000) * 100) as u32,
            ))
        })
        .ok_or_else(|| invalid("UTC time"))
}

fn encode_time(value: SystemTime) -> Result<u64> {
    let epoch = UNIX_EPOCH
        .checked_sub(Duration::from_secs(FILETIME_UNIX_OFFSET))
        .ok_or_else(|| invalid("UTC time"))?;
    let time = value
        .duration_since(epoch)
        .map_err(|_| invalid("UTC time"))?;
    let ticks = time
        .as_secs()
        .checked_mul(10_000_000)
        .and_then(|whole| whole.checked_add(u64::from(time.subsec_nanos() / 100)))
        .filter(|ticks| (1..=MAX_FILETIME).contains(ticks))
        .ok_or_else(|| invalid("UTC time"))?;
    Ok(ticks)
}

fn micros(value: Duration) -> Result<u64> {
    u64::try_from(value.as_micros()).map_err(|_| invalid("duration"))
}

impl TryFrom<WireAddress> for SocketAddr {
    type Error = SessionStatusQueryError;
    fn try_from(value: WireAddress) -> Result<Self> {
        let port = u16::try_from(value.port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| invalid("port"))?;
        match value.family {
            4 if value.scope == 0 && value.bytes[4..] == [0; 12] => {
                let octets: [u8; 4] = value.bytes[..4]
                    .try_into()
                    .map_err(|_| invalid("address"))?;
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
            }
            6 => Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(value.bytes),
                port,
                0,
                value.scope,
            ))),
            _ => Err(invalid("address")),
        }
    }
}

impl From<SocketAddr> for WireAddress {
    fn from(value: SocketAddr) -> Self {
        let mut result = Self {
            port: u32::from(value.port()),
            ..Self::default()
        };
        match value {
            SocketAddr::V4(address) => {
                result.family = 4;
                result.bytes[..4].copy_from_slice(&address.ip().octets());
            }
            SocketAddr::V6(address) => {
                result.family = 6;
                result.bytes = address.ip().octets();
                result.scope = address.scope_id();
            }
        }
        result
    }
}

fn optional<T: Default + PartialEq, U>(
    fields: u64,
    bit: u64,
    value: T,
    decode: impl FnOnce(T) -> Result<U>,
) -> Result<Option<U>> {
    if fields & bit != 0 {
        decode(value).map(Some)
    } else if value == T::default() {
        Ok(None)
    } else {
        Err(invalid("absent field"))
    }
}

impl TryFrom<WireStatus> for SessionStatus {
    type Error = SessionStatusQueryError;

    fn try_from(w: WireStatus) -> Result<Self> {
        if w.version != VERSION || usize::try_from(w.size).ok() != Some(size_of::<WireStatus>()) {
            return Err(invalid("schema"));
        }
        if w.fields & !KNOWN_FIELDS != 0 {
            return Err(invalid("presence bits"));
        }
        let session_type = match w.role {
            0 => SessionType::Classical,
            1 => SessionType::SbfdInitiator,
            2 => SessionType::SbfdReflector,
            _ => return Err(invalid("role")),
        };
        let transport_mode = match w.mode {
            0 => Mode::SingleHop,
            1 => Mode::Multihop,
            _ => return Err(invalid("transport mode")),
        };
        let reflector = session_type == SessionType::SbfdReflector;
        let required = PEER_ADDRESS | COMMUNICATING | TX_INTERVAL | DETECTION | LOCAL_MULT;
        if w.fields & required != if reflector { 0 } else { required }
            || reflector && w.fields & (PEER_REPORT | REMOTE_DISC) != 0
        {
            return Err(invalid("role fields"));
        }
        let peer = optional(
            w.fields,
            PEER_REPORT,
            (w.peer_state, w.peer_diag, w.peer_mult),
            |(s, d, m)| {
                let diag = u8::try_from(d)
                    .ok()
                    .filter(|code| *code <= 31)
                    .ok_or_else(|| invalid("peer diagnostic"))?;
                Ok((state(s)?, diag, multiplier(m)?))
            },
        )?;
        let age = duration(w.age_us, w.uptime_us.min(MAX_AGE_US))?;
        let event = |(utc, age_us)| -> Result<_> {
            if age_us < w.age_us {
                return Err(invalid("event age"));
            }
            Ok((filetime(utc)?, duration(age_us, w.uptime_us)?))
        };
        Ok(Self {
            engine_instance_id: NonZeroU128::new(u128::from_le_bytes(w.instance))
                .ok_or_else(|| invalid("engine instance"))?,
            publication_sequence: NonZeroU64::new(w.sequence)
                .ok_or_else(|| invalid("publication sequence"))?,
            captured_at_utc: filetime(w.captured_utc)?,
            engine_uptime: duration(w.uptime_us, MAX_AGE_US)?,
            snapshot_age: age,
            session_type,
            transport_mode,
            local_state: state(w.local_state)?,
            peer_state: peer.map(|(s, _, _)| s),
            peer_diagnostic: peer.map(|(_, d, _)| d),
            peer_detect_multiplier: peer.map(|(_, _, m)| m),
            local_diagnostic: diagnostic(w.local_diag)?,
            communicating: optional(w.fields, COMMUNICATING, w.communicating, boolean)?,
            last_valid_receive: optional(
                w.fields,
                RECEIVE,
                (w.received_utc, w.received_age_us),
                event,
            )?,
            last_successful_send: optional(w.fields, SEND, (w.sent_utc, w.sent_age_us), event)?,
            state_since_utc: filetime(w.state_since_utc)?,
            last_up_utc: optional(w.fields, UP, w.up_utc, filetime)?,
            last_down: optional(
                w.fields,
                DOWN,
                (w.down_utc, w.down_reason),
                |(utc, reason)| Ok((filetime(utc)?, diagnostic(reason)?)),
            )?,
            local_address: w.local.try_into()?,
            peer_address: optional(w.fields, PEER_ADDRESS, w.peer, SocketAddr::try_from)?,
            last_accepted_source: optional(w.fields, SOURCE, w.source, SocketAddr::try_from)?,
            control_port: u16::try_from(w.control_port)
                .ok()
                .and_then(std::num::NonZeroU16::new)
                .ok_or_else(|| invalid("control port"))?,
            interface_index: optional(w.fields, INTERFACE, w.interface, discriminator)?,
            local_discriminator: discriminator(w.local_disc)?,
            remote_discriminator: optional(w.fields, REMOTE_DISC, w.remote_disc, discriminator)?,
            effective_tx_interval: optional(w.fields, TX_INTERVAL, w.tx_us, |us| {
                duration(us, MAX_TX_US)
            })?,
            detection_time: optional(w.fields, DETECTION, w.detection_us, |us| {
                duration(us, MAX_DETECTION_US)
            })?,
            local_detect_multiplier: optional(w.fields, LOCAL_MULT, w.local_mult, multiplier)?,
            packets_received_accepted: w.received,
            packets_sent_successfully: w.sent,
            packets_rejected: w.rejected,
            authentication_failures: w.auth_failures,
            socket_errors: w.socket_errors,
            detection_timeouts: w.detection_timeouts,
            up_transitions: w.up_transitions,
        })
    }
}

impl WireStatus {
    pub(super) fn capture(s: &StatusSnapshot, now: Instant) -> Result<Self> {
        let p = &s.publication;
        let age = |instant| {
            now.checked_duration_since(instant)
                .ok_or_else(|| invalid("monotonic time"))
                .and_then(micros)
        };
        let mut w = Self {
            version: VERSION,
            size: u32::try_from(size_of::<Self>()).map_err(|_| invalid("record size"))?,
            instance: p.instance.get().to_le_bytes(),
            sequence: p.sequence,
            captured_utc: encode_time(p.utc)?,
            uptime_us: age(p.started)?,
            age_us: age(p.captured)?,
            state_since_utc: encode_time(s.state_since_utc)?,
            role: match s.session_type {
                SessionType::Classical => 0,
                SessionType::SbfdInitiator => 1,
                SessionType::SbfdReflector => 2,
            },
            mode: match s.transport_mode {
                Mode::SingleHop => 0,
                Mode::Multihop => 1,
            },
            local_state: u32::from(s.local_state as u8),
            local_diag: u32::from(s.local_diagnostic as u8),
            local_disc: s.local_discriminator,
            control_port: u32::from(s.control_port),
            local: SocketAddr::new(s.local_address, s.local_source_port).into(),
            received: s.packets_received_accepted,
            sent: s.packets_sent_successfully,
            rejected: s.packets_rejected,
            auth_failures: s.authentication_failures,
            socket_errors: s.socket_errors,
            detection_timeouts: s.detection_timeouts,
            up_transitions: s.up_transitions,
            ..Self::default()
        };
        if let Some(peer) = s.peer_address {
            w.fields |= PEER_ADDRESS;
            w.peer = SocketAddr::new(peer, s.control_port).into();
        }
        if let Some(source) = s.last_accepted_source {
            w.fields |= SOURCE;
            w.source = source.into();
        }
        if let Some(index) = s.interface_index {
            w.fields |= INTERFACE;
            w.interface = index;
        }
        if let Some(disc) = s.remote_discriminator {
            w.fields |= REMOTE_DISC;
            w.remote_disc = disc;
        }
        if let (Some(state), Some(diag), Some(mult)) = (
            s.remote_state,
            s.remote_diagnostic,
            s.remote_detect_multiplier,
        ) {
            w.fields |= PEER_REPORT;
            w.peer_state = u32::from(state as u8);
            w.peer_diag = u32::from(diag);
            w.peer_mult = u32::from(mult);
        }
        if let Some(value) = s.communicating {
            w.fields |= COMMUNICATING;
            w.communicating = u32::from(value);
        }
        if let (Some(utc), Some(at)) = (s.last_valid_receive_utc, p.received) {
            w.fields |= RECEIVE;
            w.received_utc = encode_time(utc)?;
            w.received_age_us = age(at)?;
        }
        if let (Some(utc), Some(at)) = (s.last_successful_send_utc, p.sent) {
            w.fields |= SEND;
            w.sent_utc = encode_time(utc)?;
            w.sent_age_us = age(at)?;
        }
        if let Some(utc) = s.last_up_utc {
            w.fields |= UP;
            w.up_utc = encode_time(utc)?;
        }
        if let (Some(utc), Some(reason)) = (s.last_down_utc, s.last_down_reason) {
            w.fields |= DOWN;
            w.down_utc = encode_time(utc)?;
            w.down_reason = u32::from(reason as u8);
        }
        if let Some(tx) = s.effective_tx_interval {
            w.fields |= TX_INTERVAL;
            w.tx_us = micros(tx)?;
        }
        if let Some(detection) = s.detection_time {
            w.fields |= DETECTION;
            w.detection_us = micros(detection)?;
        }
        if let Some(mult) = s.local_detect_multiplier {
            w.fields |= LOCAL_MULT;
            w.local_mult = u32::from(mult);
        }
        Ok(w)
    }
}

#[cfg(test)]
pub(crate) mod tests;
