//! Registry-backed configuration for classical BFD or an S-BFD protocol role.
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    ops::Deref,
    path::PathBuf,
    sync::Arc,
};

use crate::error::ConfigError;
use clap::{Parser, ValueEnum};

use crate::packet::{AuthConfig, AuthType};

#[cfg(windows)]
mod registry;
#[cfg(windows)]
pub use registry::load_registry;
#[cfg(windows)]
pub(crate) use registry::load_sbfd_settings;

/// Windows Service Control Manager service name.
pub const SERVICE_NAME: &str = "BfdWinService";
/// Configuration key relative to HKEY_LOCAL_MACHINE.
pub const PARAMETERS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters";
/// Default append-log path; used only when LogToFile is enabled.
pub const DEFAULT_LOG_FILE_PATH: &str = r"C:\ProgramData\BfdWinService\trace.log";
/// UDP destination port for IP-routed S-BFD requests (RFC 7881).
pub const SBFD_PORT: u16 = 7784;

/// Protocol role, independent of the classical transport profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum SessionType {
    /// Negotiates an asynchronous RFC 5880 session.
    #[default]
    Classical,
    /// Probes a preconfigured RFC 7880 reflector.
    SbfdInitiator,
    /// Answers requests for a local discriminator without peer state.
    SbfdReflector,
}

/// Required settings after the protocol role has been validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolRole {
    /// Classical BFD with one normalized transport profile.
    Classical(Mode),
    /// An initiator with a provisioned, nonzero target identifier.
    Initiator {
        /// Remote reflector identifier.
        remote_discriminator: NonZeroU32,
    },
    /// A reflector with a provisioned, nonzero local identifier.
    Reflector {
        /// Local reflector identifier.
        discriminator: NonZeroU32,
    },
}

/// Immutable, validated startup settings shared by runtime components.
/// Cloning shares the snapshot rather than copying strings or authentication keys.
///
/// ```compile_fail
/// use bfd_winservice::config::Options;
/// let mut options = Options::reflector("127.0.0.1".parse().unwrap(), 99)
///     .into_validated().unwrap();
/// options.detect_mult = 0; // Validated settings cannot be mutated.
/// ```
#[derive(Clone)]
pub struct ValidatedOptions(Arc<ValidatedSettings>);

struct ValidatedSettings {
    options: Options,
    auth: AuthConfig,
    role: ProtocolRole,
}

impl ValidatedOptions {
    /// Returns the validated role and its required identifiers.
    pub fn role(&self) -> ProtocolRole {
        self.0.role
    }
    /// Borrows the authentication settings associated with this snapshot.
    pub fn authentication(&self) -> &AuthConfig {
        &self.0.auth
    }
    /// Returns the validated startup timing without repeating its checks.
    pub fn timing(&self) -> Timing {
        Timing {
            min_tx_us: self.min_tx_us,
            min_rx_us: self.min_rx_us,
            detect_mult: self.detect_mult,
        }
    }
}

impl Deref for ValidatedOptions {
    type Target = Options;
    fn deref(&self) -> &Options {
        &self.0.options
    }
}

/// Validated live S-BFD timing settings, with intervals in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub(crate) min_tx_us: u32,
    pub(crate) min_rx_us: u32,
    pub(crate) detect_mult: u8,
}

impl Timing {
    /// Creates nonzero transmit/receive intervals and a detection multiplier.
    ///
    /// # Errors
    /// Rejects zero intervals or a zero multiplier.
    pub fn new(min_tx_us: u32, min_rx_us: u32, detect_mult: u8) -> Result<Self, ConfigError> {
        if min_tx_us == 0 || min_rx_us == 0 || detect_mult == 0 {
            return Err(ConfigError::ZeroTiming);
        }
        Ok(Self {
            min_tx_us,
            min_rx_us,
            detect_mult,
        })
    }
}

/// Execution mode is the only application command-line option.
#[derive(Parser)]
#[command(
    version,
    about = "Windows BFD service; settings are read from HKLM\\SYSTEM\\CurrentControlSet\\Services\\BfdWinService\\Parameters"
)]
pub struct CommandLine {
    /// Run in the foreground and write events to STDOUT; Ctrl+C stops the session
    #[arg(long)]
    pub console: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
/// Single-hop or multihop UDP transport profile.
pub enum Mode {
    /// Uses UDP port 3784 and requires a received TTL or hop limit of 255.
    #[default]
    SingleHop,
    /// Uses UDP port 4784 with an optional minimum received TTL or hop limit.
    Multihop,
}

impl Mode {
    /// Control destination/listen port for this profile.
    pub fn port(self) -> u16 {
        match self {
            Self::SingleHop => 3784,
            Self::Multihop => 4784,
        }
    }
}

/// Startup settings for one explicitly provisioned BFD session.
#[derive(Clone)]
pub struct Options {
    /// Run in the foreground; Ctrl+C stops the session
    pub console: bool,
    /// Local unicast IP address (binds receive and transmit sockets)
    pub local: IpAddr,
    /// Peer unicast IP address, without a port; unused by a reflector.
    pub peer: IpAddr,
    /// Classical BFD, S-BFD initiator, or S-BFD reflector; defaults to classical.
    pub session_type: SessionType,
    /// Preprovisioned target discriminator; required only by an S-BFD initiator.
    pub remote_discriminator: Option<u32>,
    /// Additional accepted S-BFD response sources, or reflector source allowlist.
    /// An empty reflector list permits any routable unicast source.
    pub allowed_peers: Vec<IpAddr>,
    /// Advertise reflector maintenance without stopping its response listener.
    pub sbfd_admin_down: bool,
    pub(crate) registry_backed: bool,
    /// Transport profile: UDP 3784 or UDP 4784
    pub mode: Mode,
    /// Select multihop during validation; loaded from the Multihop registry flag
    pub multihop: bool,
    /// Point-to-point single-hop link; accept any peer source address on its interface
    pub point_to_point: bool,
    /// Desired minimum transmit interval while Up, in microseconds
    pub min_tx_us: u32,
    /// Required minimum receive interval; S-BFD initiators use this as an RTT budget.
    pub min_rx_us: u32,
    /// Desired TX outside Up, in microseconds; at least one second, clamped to MinTxUs
    pub startup_tx_us: u32,
    /// Detection multiplier for classical BFD and S-BFD initiation;
    /// reflectors copy each request's multiplier instead.
    pub detect_mult: u8,
    /// Local discriminator; omitted means a random nonzero value for classical
    /// sessions and initiators. Reflectors require a provisioned discriminator.
    pub discriminator: Option<u32>,
    /// Stable UDP source port (49152..65535); omitted means automatically allocated
    pub source_port: Option<u16>,
    /// Wait for a validated peer control packet (multihop only)
    pub passive: bool,
    /// Windows interface index; required for classical single-hop and IPv6 link-local addresses.
    pub interface_index: Option<u32>,
    /// Minimum accepted TTL/hop limit for multihop or S-BFD; classical single-hop requires 255.
    pub min_ttl: Option<u8>,
    /// Authentication mechanism (must match the peer)
    pub auth: AuthType,
    /// Authentication key identifier
    pub auth_key_id: u8,
    /// ASCII authentication key (use AuthKeyHex for binary keys)
    pub auth_key: Option<String>,
    /// Authentication key as hexadecimal bytes
    pub auth_key_hex: Option<String>,
    /// Append-log path read from LogFilePath; use an absolute path for SCM
    pub log_file_path: PathBuf,
    /// Enable append logging; false leaves the configured path untouched
    pub log_to_file: bool,
    /// Enable native MI BGP control for this configured peer name
    pub bgp_peer_name: Option<String>,
    /// Routing domain of the BGP peer; omitted selects the default domain
    pub bgp_routing_domain: Option<String>,
    /// Log discarded packets (rate limited)
    pub verbose: bool,
}

impl Options {
    /// Consumes raw settings, normalizes the profile, and checks all role invariants.
    ///
    /// # Errors
    /// Returns a typed configuration error without exposing authentication keys.
    pub fn into_validated(mut self) -> Result<ValidatedOptions, ConfigError> {
        let auth = self.validate()?;
        let role = match self.session_type {
            SessionType::Classical => ProtocolRole::Classical(self.mode),
            SessionType::SbfdInitiator => ProtocolRole::Initiator {
                remote_discriminator: self
                    .remote_discriminator
                    .and_then(NonZeroU32::new)
                    .ok_or(ConfigError::MissingRemoteDiscriminator)?,
            },
            SessionType::SbfdReflector => ProtocolRole::Reflector {
                discriminator: self
                    .discriminator
                    .and_then(NonZeroU32::new)
                    .ok_or(ConfigError::MissingReflectorDiscriminator)?,
            },
        };
        // The immutable snapshot has one consistent transport selection.
        self.multihop = self.mode == Mode::Multihop;
        Ok(ValidatedOptions(Arc::new(ValidatedSettings {
            options: self,
            auth,
            role,
        })))
    }
    /// Construct default settings for the required local and peer addresses.
    /// Call validate after provisioning the transport/authentication settings.
    pub fn new(local: IpAddr, peer: IpAddr) -> Self {
        Self {
            console: false,
            local,
            peer,
            session_type: SessionType::Classical,
            remote_discriminator: None,
            allowed_peers: Vec::new(),
            sbfd_admin_down: false,
            registry_backed: false,
            mode: Mode::SingleHop,
            multihop: false,
            point_to_point: false,
            min_tx_us: 300_000,
            min_rx_us: 300_000,
            startup_tx_us: 1_000_000,
            detect_mult: 3,
            discriminator: None,
            source_port: None,
            passive: false,
            interface_index: None,
            min_ttl: None,
            auth: AuthType::None,
            auth_key_id: 0,
            auth_key: None,
            auth_key_hex: None,
            log_file_path: DEFAULT_LOG_FILE_PATH.into(),
            log_to_file: false,
            bgp_peer_name: None,
            bgp_routing_domain: None,
            verbose: false,
        }
    }

    /// Check ranges, addresses, transport profile, and authentication configuration.
    ///
    /// Normalizes the multihop shortcut into mode and returns validated authentication.
    /// Registry loading alone does not perform these checks. Public fields can be changed,
    /// so validate again after mutation before using the options.
    ///
    /// # Errors
    /// Returns an error for unsupported option combinations or invalid values/keys.
    /// Mode normalization can occur before a later validation error.
    pub fn validate(&mut self) -> Result<AuthConfig, ConfigError> {
        // Validate registry-loaded and programmatically constructed settings alike.
        self.validate_ranges()?;
        if self.auth_key.is_some() && self.auth_key_hex.is_some() {
            return Err(ConfigError::ConflictingKeys);
        }
        for (name, value) in [
            ("BgpPeerName", &self.bgp_peer_name),
            ("BgpRoutingDomain", &self.bgp_routing_domain),
        ] {
            if value
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
            {
                return Err(ConfigError::InvalidName { field: name });
            }
        }
        if self.bgp_routing_domain.is_some() && self.bgp_peer_name.is_none() {
            return Err(ConfigError::BgpDomainWithoutPeer);
        }
        if self.multihop {
            self.mode = Mode::Multihop;
        }
        if self.session_type != SessionType::SbfdReflector
            && self.local.is_ipv4() != self.peer.is_ipv4()
        {
            return Err(ConfigError::AddressFamilyMismatch);
        }
        for (name, ip) in [("Local", self.local), ("Peer", self.peer)] {
            if name == "Peer" && self.session_type == SessionType::SbfdReflector {
                continue;
            }
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
                || self.session_type != SessionType::Classical && !is_unicast(ip)
            {
                return Err(ConfigError::InvalidAddress { field: name });
            }
        }
        if self.local == self.peer && self.session_type == SessionType::Classical {
            return Err(ConfigError::IdenticalEndpoints);
        }
        if self.session_type == SessionType::SbfdInitiator
            && !is_seamless_source(self.local, self.peer)
        {
            return Err(ConfigError::LoopbackScope { field: "Peer" });
        }
        if self.point_to_point
            && (self.mode != Mode::SingleHop || self.session_type != SessionType::Classical)
        {
            return Err(ConfigError::PointToPointRequiresSingleHop);
        }
        if self.session_type == SessionType::Classical && self.mode == Mode::SingleHop {
            if self.passive {
                return Err(ConfigError::SingleHopPassive);
            }
            if self.interface_index.is_none() {
                return Err(ConfigError::MissingInterface);
            }
            if self.min_ttl.is_some() {
                return Err(ConfigError::SingleHopMinTtl);
            }
        }
        if self.session_type != SessionType::Classical
            && (self.passive || self.multihop || self.mode == Mode::Multihop)
        {
            return Err(ConfigError::ClassicalOnlySettings);
        }
        match self.session_type {
            SessionType::SbfdInitiator if self.remote_discriminator.is_none() => {
                return Err(ConfigError::MissingRemoteDiscriminator);
            }
            SessionType::SbfdReflector => {
                if self.discriminator.is_none() {
                    return Err(ConfigError::MissingReflectorDiscriminator);
                }
                if self.bgp_peer_name.is_some()
                    || self.source_port.is_some()
                    || self.remote_discriminator.is_some()
                {
                    return Err(ConfigError::ReflectorSettings);
                }
            }
            SessionType::Classical
                if self.remote_discriminator.is_some()
                    || !self.allowed_peers.is_empty()
                    || self.sbfd_admin_down =>
            {
                return Err(ConfigError::SeamlessOnlySettings);
            }
            _ => {}
        }
        if self.sbfd_admin_down && self.session_type != SessionType::SbfdReflector {
            return Err(ConfigError::ReflectorOnlyAdminDown);
        }
        for ip in &self.allowed_peers {
            if !is_seamless_source(self.local, *ip) {
                return Err(ConfigError::InvalidAllowedPeers);
            }
        }
        if [self.local, self.peer]
            .iter()
            .take(if self.session_type == SessionType::SbfdReflector {
                1
            } else {
                2
            })
            .chain(&self.allowed_peers)
            .any(|ip| matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
            && self.interface_index.is_none()
        {
            return Err(ConfigError::LinkLocalRequiresInterface);
        }
        let key = if let Some(hex) = &self.auth_key_hex {
            if hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err(ConfigError::InvalidHexKey);
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ConfigError::InvalidHexByte)
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if let Some(key) = &self.auth_key {
            if !key.is_ascii() {
                return Err(ConfigError::NonAsciiKey);
            }
            key.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        AuthConfig::new(self.auth, self.auth_key_id, key)
    }

    pub(crate) fn validate_ranges(&self) -> Result<(), ConfigError> {
        if self.min_tx_us == 0 || self.min_rx_us == 0 {
            return Err(ConfigError::ZeroIntervals);
        }
        if self.startup_tx_us < 1_000_000 {
            return Err(ConfigError::StartupInterval);
        }
        if self.detect_mult == 0 {
            return Err(ConfigError::ZeroDetectMultiplier);
        }
        if self.discriminator == Some(0) {
            return Err(ConfigError::ZeroDiscriminator);
        }
        if self.remote_discriminator == Some(0) {
            return Err(ConfigError::ZeroRemoteDiscriminator);
        }
        if self.source_port.is_some_and(|port| port < 49152) {
            return Err(ConfigError::SourcePortRange);
        }
        if self.interface_index == Some(0) || self.min_ttl == Some(0) {
            return Err(ConfigError::ZeroInterfaceOrTtl);
        }
        Ok(())
    }

    /// Creates a reflector configuration without provisioning an initiating peer.
    /// Call validate before using the local address and discriminator.
    pub fn reflector(local: IpAddr, discriminator: u32) -> Self {
        let unspecified = if local.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        let mut options = Self::new(local, unspecified);
        options.session_type = SessionType::SbfdReflector;
        options.discriminator = Some(discriminator);
        options
    }

    /// Returns the destination/listen port for this protocol role.
    pub fn control_port(&self) -> u16 {
        if self.session_type == SessionType::Classical {
            self.mode.port()
        } else {
            SBFD_PORT
        }
    }

    /// Returns validated settings for a live S-BFD timing update.
    ///
    /// # Errors
    /// Rejects zero intervals or a zero multiplier.
    pub fn timing(&self) -> Result<Timing, ConfigError> {
        Timing::new(self.min_tx_us, self.min_rx_us, self.detect_mult)
    }

    /// Build a socket address, adding the configured scope only for link-local IPv6.
    /// Does not validate configuration; a missing interface becomes scope zero.
    pub fn address(&self, ip: IpAddr, port: u16) -> SocketAddr {
        match ip {
            IpAddr::V4(ip) => SocketAddr::from((ip, port)),
            IpAddr::V6(ip) => std::net::SocketAddrV6::new(
                ip,
                port,
                0,
                if ip.is_unicast_link_local() {
                    self.interface_index.unwrap_or(0)
                } else {
                    0
                },
            )
            .into(),
        }
    }
}

pub(crate) fn is_unicast(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        && !matches!(ip, IpAddr::V4(ip) if ip.octets()[0] == 0 || ip.octets()[0] >= 240)
        && !matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
}

pub(crate) fn is_seamless_source(local: IpAddr, source: IpAddr) -> bool {
    is_unicast(source)
        && source.is_ipv4() == local.is_ipv4()
        && source.is_loopback() == local.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_snapshots_share_storage_and_require_role_identifiers() {
        let reflector = Options::reflector("127.0.0.1".parse().unwrap(), 99)
            .into_validated()
            .unwrap();
        assert_eq!(
            reflector.role(),
            ProtocolRole::Reflector {
                discriminator: NonZeroU32::new(99).unwrap()
            }
        );
        assert!(Arc::ptr_eq(&reflector.0, &reflector.clone().0));
        let mut initiator =
            Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        initiator.session_type = SessionType::SbfdInitiator;
        assert_eq!(
            initiator.clone().into_validated().err(),
            Some(ConfigError::MissingRemoteDiscriminator)
        );
        initiator.remote_discriminator = Some(7);
        let snapshot = initiator.clone().into_validated().unwrap();
        assert_eq!(
            snapshot.role(),
            ProtocolRole::Initiator {
                remote_discriminator: NonZeroU32::new(7).unwrap()
            }
        );
        initiator.mode = Mode::Multihop;
        assert_eq!(
            initiator.into_validated().err(),
            Some(ConfigError::ClassicalOnlySettings)
        );
        let mut classical =
            Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        classical.mode = Mode::Multihop;
        let snapshot = classical.into_validated().unwrap();
        assert_eq!(snapshot.role(), ProtocolRole::Classical(Mode::Multihop));
        assert!(snapshot.multihop);
    }

    #[test]
    fn seamless_configuration_rejects_sources_that_transport_cannot_accept() {
        for (local, peer) in [
            ("192.0.2.1", "240.0.0.1"),
            ("127.0.0.1", "192.0.2.2"),
            ("192.0.2.1", "127.0.0.1"),
            ("::1", "::ffff:192.0.2.2"),
        ] {
            let mut options = Options::new(local.parse().unwrap(), peer.parse().unwrap());
            options.session_type = SessionType::SbfdInitiator;
            options.remote_discriminator = Some(99);
            assert!(options.validate().is_err(), "accepted {local} -> {peer}");
        }
        let mut options = Options::reflector("192.0.2.2".parse().unwrap(), 99);
        options.allowed_peers = vec!["127.0.0.1".parse().unwrap()];
        assert!(options.validate().is_err());
    }

    fn options() -> Options {
        Options::new("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap())
    }
    fn multihop() -> Options {
        let mut options = options();
        options.mode = Mode::Multihop;
        options
    }

    #[test]
    fn console_is_the_only_application_command_line_option() {
        assert!(!CommandLine::try_parse_from(["bfd"]).unwrap().console);
        assert!(
            CommandLine::try_parse_from(["bfd", "--console"])
                .unwrap()
                .console
        );
        for removed in [
            "--local",
            "--peer",
            "--mode",
            "--multihop",
            "--point-to-point",
            "--interface-index",
            "--min-tx-us",
            "--min-rx-us",
            "--startup-tx-us",
            "--detect-mult",
            "--discriminator",
            "--source-port",
            "--passive",
            "--min-ttl",
            "--auth",
            "--auth-key-id",
            "--auth-key",
            "--auth-key-hex",
            "--log-file",
            "--bgp-peer-name",
            "--bgp-routing-domain",
            "--verbose",
        ] {
            assert!(
                CommandLine::try_parse_from(["bfd", removed]).is_err(),
                "{removed}"
            );
        }
    }

    #[test]
    fn validates_profiles_and_numeric_ranges() {
        let mut options = options();
        assert!(options.validate().is_err());
        options.interface_index = Some(2);
        assert!(options.validate().is_ok());
        options.passive = true;
        assert!(options.validate().is_err());
        options.multihop = true;
        assert!(options.validate().is_ok());
        assert_eq!(options.mode.port(), 4784);
    }

    #[test]
    fn validates_authentication_keys() {
        let mut options = multihop();
        options.auth = AuthType::MeticulousSha1;
        assert!(options.validate().is_err());
        options.auth = AuthType::None;
        options.auth_key = Some("secret".into());
        assert!(options.validate().is_err());
        options.auth = AuthType::KeyedSha1;
        options.auth_key = None;
        options.auth_key_hex = Some("00fe12".into());
        assert!(options.validate().is_ok());
        options.auth = AuthType::SimplePassword;
        options.auth_key_hex = Some("zz".into());
        assert!(options.validate().is_err());
    }

    #[test]
    fn programmatic_options_cannot_bypass_numeric_ranges_or_key_conflicts() {
        let valid = multihop();
        let invalid: [fn(&mut Options); 9] = [
            |o| o.min_tx_us = 0,
            |o| o.min_rx_us = 0,
            |o| o.startup_tx_us = 999_999,
            |o| o.detect_mult = 0,
            |o| o.discriminator = Some(0),
            |o| o.source_port = Some(49151),
            |o| o.interface_index = Some(0),
            |o| o.min_ttl = Some(0),
            |o| {
                o.auth = AuthType::KeyedSha1;
                o.auth_key = Some("secret".into());
                o.auth_key_hex = Some("00".into());
            },
        ];
        for mutate in invalid {
            let mut options = valid.clone();
            mutate(&mut options);
            assert!(options.validate().is_err());
        }
    }

    #[test]
    fn validates_bgp_target_and_routing_domain() {
        let mut options = multihop();
        options.bgp_routing_domain = Some("Rd001".into());
        assert!(options.validate().is_err());
        options.bgp_peer_name = Some("Site17".into());
        assert!(options.validate().is_ok());
        for name in ["", "  ", "Site\0other"] {
            options.bgp_peer_name = Some(name.into());
            assert!(options.validate().is_err());
        }
        options.bgp_peer_name = Some("Site17".into());
        options.bgp_routing_domain = Some(String::new());
        assert!(options.validate().is_err());
    }

    #[test]
    fn point_to_point_requires_single_hop_and_an_interface() {
        let mut options = options();
        options.point_to_point = true;
        assert!(options.validate().is_err());
        options.interface_index = Some(2);
        assert!(options.validate().is_ok());
        options.mode = Mode::Multihop;
        assert!(options.validate().is_err());
        options.mode = Mode::SingleHop;
        options.multihop = true;
        assert!(options.validate().is_err());
    }
}
