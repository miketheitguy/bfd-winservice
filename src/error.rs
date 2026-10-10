//! Typed configuration, packet, and authentication errors; messages omit secrets.
use crate::packet::AuthType;

/// Invalid settings or an unsupported configuration combination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// MinTxUs, MinRxUs, and DetectMult must be nonzero.
    #[error("MinTxUs, MinRxUs, and DetectMult must be nonzero")]
    ZeroTiming,
    /// MaxShutdownAnnounceMs must be in the range 1..=60000.
    #[error("MaxShutdownAnnounceMs must be between 1 and 60000 milliseconds")]
    ShutdownAnnouncementLimit,
    /// AuthKey and AuthKeyHex are mutually exclusive.
    #[error("AuthKey and AuthKeyHex are mutually exclusive")]
    ConflictingKeys,
    /// BgpRoutingDomain requires BgpPeerName.
    #[error("BgpRoutingDomain requires BgpPeerName")]
    BgpDomainWithoutPeer,
    /// Local and Peer must have the same address family.
    #[error("Local and Peer must have the same address family")]
    AddressFamilyMismatch,
    /// Local and Peer must differ.
    #[error("Local and Peer must differ")]
    IdenticalEndpoints,
    /// PointToPoint applies only to single-hop sessions.
    #[error("PointToPoint applies only to single-hop sessions")]
    PointToPointRequiresSingleHop,
    /// Single-hop BFD requires the active role; Passive is multihop only.
    #[error("single-hop BFD requires the active role; Passive is multihop only")]
    SingleHopPassive,
    /// Single-hop BFD requires InterfaceIndex to bind the session to its path.
    #[error("single-hop BFD requires InterfaceIndex to bind the session to its path")]
    MissingInterface,
    /// MinTtl applies only to multihop; single-hop requires TTL 255.
    #[error("MinTtl applies only to multihop; single-hop requires TTL 255")]
    SingleHopMinTtl,
    /// Passive and Multihop apply only to classical BFD.
    #[error("Passive and Multihop apply only to classical BFD")]
    ClassicalOnlySettings,
    /// S-BFD initiators require RemoteDiscriminator.
    #[error("S-BFD initiators require RemoteDiscriminator")]
    MissingRemoteDiscriminator,
    /// S-BFD reflectors require a domain-unique Discriminator.
    #[error("S-BFD reflectors require a domain-unique Discriminator")]
    MissingReflectorDiscriminator,
    /// BgpPeerName, SourcePort, and RemoteDiscriminator do not apply to reflectors.
    #[error("BgpPeerName, SourcePort, and RemoteDiscriminator do not apply to reflectors")]
    ReflectorSettings,
    /// RemoteDiscriminator, AllowedPeers, and SbfdAdminDown require S-BFD.
    #[error("RemoteDiscriminator, AllowedPeers, and SbfdAdminDown require S-BFD")]
    SeamlessOnlySettings,
    /// SbfdAdminDown applies only to reflectors.
    #[error("SbfdAdminDown applies only to reflectors")]
    ReflectorOnlyAdminDown,
    /// AllowedPeers must contain unicast sources with Local's address family and loopback scope.
    #[error("AllowedPeers must contain unicast addresses matching Local's address family and loopback scope")]
    InvalidAllowedPeers,
    /// IPv6 link-local addresses require InterfaceIndex.
    #[error("IPv6 link-local addresses require InterfaceIndex")]
    LinkLocalRequiresInterface,
    /// AuthKeyHex must contain pairs of hexadecimal digits.
    #[error("AuthKeyHex must contain pairs of hexadecimal digits")]
    InvalidHexKey,
    /// AuthKeyHex contains an invalid byte.
    #[error("AuthKeyHex contains an invalid byte")]
    InvalidHexByte,
    /// AuthKey must be ASCII; use AuthKeyHex for binary keys.
    #[error("AuthKey must be ASCII; use AuthKeyHex for binary keys")]
    NonAsciiKey,
    /// MinTxUs and MinRxUs must be nonzero.
    #[error("MinTxUs and MinRxUs must be nonzero")]
    ZeroIntervals,
    /// StartupTxUs must be at least 1000000.
    #[error("StartupTxUs must be at least 1000000")]
    StartupInterval,
    /// DetectMult must be nonzero.
    #[error("DetectMult must be nonzero")]
    ZeroDetectMultiplier,
    /// Discriminator must be nonzero.
    #[error("Discriminator must be nonzero")]
    ZeroDiscriminator,
    /// RemoteDiscriminator must be nonzero.
    #[error("RemoteDiscriminator must be nonzero")]
    ZeroRemoteDiscriminator,
    /// SourcePort must be within 49152..65535.
    #[error("SourcePort must be within 49152..65535")]
    SourcePortRange,
    /// InterfaceIndex and MinTtl must be nonzero when specified.
    #[error("InterfaceIndex and MinTtl must be nonzero when specified")]
    ZeroInterfaceOrTtl,
    /// An authentication key requires Auth.
    #[error("an authentication key requires Auth")]
    UnexpectedKey,
    /// Session authentication does not match its configured settings.
    #[error("session authentication does not match its configured settings")]
    AuthenticationMismatch,
    /// Reflector requires matching S-BFD reflector configuration.
    #[error("reflector requires matching S-BFD reflector configuration")]
    WrongReflectorRole,
    /// Live timing updates require S-BFD.
    #[error("live timing updates require S-BFD")]
    ClassicalTimingUpdate,
    /// A transmitted Poll or its separation period still protects a timer change.
    #[error("wait for the Poll Final and a subsequent non-Final response before changing timers")]
    PollInProgress,
    /// A name is empty or contains an embedded NUL.
    #[error("{field} must be nonempty and contain no NUL characters")]
    InvalidName {
        /// Registry setting name.
        field: &'static str,
    },
    /// An endpoint is not a usable unicast address.
    #[error("{field} must be a specific unicast address")]
    InvalidAddress {
        /// Registry setting name.
        field: &'static str,
    },
    /// The peer cannot pass the local S-BFD source policy.
    #[error("{field} must have the same loopback scope as Local")]
    LoopbackScope {
        /// Registry setting name.
        field: &'static str,
    },
    /// A key exceeds the selected authentication format's bounds.
    #[error("{kind:?} requires a key of 1..{max} bytes")]
    InvalidKeyLength {
        /// Selected wire authentication format.
        kind: AuthType,
        /// Maximum key length in bytes.
        max: usize,
    },
}

/// A structural, transport, or protocol-role rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacketError {
    /// Truncated header.
    #[error("truncated header")]
    TruncatedHeader,
    /// Unsupported version.
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Invalid packet length.
    #[error("invalid packet length")]
    InvalidLength,
    /// Zero detection multiplier.
    #[error("zero detection multiplier")]
    ZeroDetectMultiplier,
    /// Multipoint is unsupported.
    #[error("multipoint is unsupported")]
    UnsupportedMultipoint,
    /// Poll and Final cannot both be set.
    #[error("Poll and Final cannot both be set")]
    PollAndFinal,
    /// Zero sender discriminator.
    #[error("zero sender discriminator")]
    ZeroSenderDiscriminator,
    /// Zero receiver discriminator in Init/Up.
    #[error("zero receiver discriminator in Init/Up")]
    ZeroReceiverDiscriminator,
    /// Reserved zero desired transmit interval.
    #[error("reserved zero desired transmit interval")]
    ZeroDesiredTx,
    /// Receiver discriminator does not identify this session.
    #[error("receiver discriminator does not identify this session")]
    WrongDiscriminator,
    /// Use Reflector::respond for stateless requests.
    #[error("use Reflector::respond for stateless requests")]
    UseReflector,
    /// S-BFD response discriminator mismatch.
    #[error("S-BFD response discriminator mismatch")]
    WrongSeamlessDiscriminator,
    /// Invalid S-BFD reflector state or Demand flag.
    #[error("invalid S-BFD reflector state or Demand flag")]
    InvalidReflectorState,
    /// Unknown S-BFD reflector discriminator.
    #[error("unknown S-BFD reflector discriminator")]
    UnknownReflector,
    /// S-BFD reflector requires the Demand bit.
    #[error("S-BFD reflector requires the Demand bit")]
    MissingDemand,
    /// Invalid S-BFD initiator state or receive intervals.
    #[error("invalid S-BFD initiator state or receive intervals")]
    InvalidInitiator,
    /// Unexpected peer address.
    #[error("unexpected peer address")]
    UnexpectedPeer,
    /// Peer source port is outside 49152..65535.
    #[error("peer source port is outside 49152..65535")]
    SourcePort,
    /// Invalid S-BFD source address.
    #[error("invalid S-BFD source address")]
    InvalidSeamlessSource,
    /// S-BFD response source port must be 7784.
    #[error("S-BFD response source port must be 7784")]
    SeamlessResponsePort,
    /// S-BFD response source is not allowed.
    #[error("S-BFD response source is not allowed")]
    DisallowedResponse,
    /// S-BFD request source port must be nonzero and different from 7784.
    #[error("S-BFD request source port must be nonzero and different from 7784")]
    SeamlessRequestPort,
    /// S-BFD request source is not allowed.
    #[error("S-BFD request source is not allowed")]
    DisallowedRequest,
    /// Destination address is not the configured local address.
    #[error("destination address is not the configured local address")]
    WrongDestination,
    /// Packet arrived on another interface.
    #[error("packet arrived on another interface")]
    WrongInterface,
    /// Missing received TTL/hop limit.
    #[error("missing received TTL/hop limit")]
    MissingTtl,
    /// Single-hop TTL/hop limit must be 255.
    #[error("single-hop TTL/hop limit must be 255")]
    SingleHopTtl,
    /// TTL/hop limit below MinTtl.
    #[error("TTL/hop limit below MinTtl")]
    MinimumTtl,
}

/// An authentication rejection without exposing key or packet bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Authentication required.
    #[error("authentication required")]
    Required,
    /// Unexpected authenticated packet.
    #[error("unexpected authenticated packet")]
    Unexpected,
    /// Authentication type mismatch.
    #[error("authentication type mismatch")]
    WrongType,
    /// Invalid authentication length.
    #[error("invalid authentication length")]
    InvalidLength,
    /// Authentication key ID mismatch.
    #[error("authentication key ID mismatch")]
    WrongKeyId,
    /// Password mismatch.
    #[error("password mismatch")]
    PasswordMismatch,
    /// Invalid keyed authentication length.
    #[error("invalid keyed authentication length")]
    InvalidKeyedLength,
    /// Authentication sequence outside receive window.
    #[error("authentication sequence outside receive window")]
    SequenceWindow,
    /// Authentication digest mismatch.
    #[error("authentication digest mismatch")]
    DigestMismatch,
    /// S-BFD response sequence was not outstanding.
    #[error("S-BFD response sequence was not outstanding")]
    SequenceNotOutstanding,
    /// Authentication was requested for a malformed control packet.
    #[error(transparent)]
    MalformedPacket(#[from] PacketError),
}
