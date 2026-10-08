//! Registry-backed startup settings and validation for one provisioned session.
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use clap::{Parser, ValueEnum};

use crate::packet::{AuthConfig, AuthType};

#[cfg(windows)]
mod registry;
#[cfg(windows)]
pub use registry::load_registry;

/// Windows Service Control Manager service name.
pub const SERVICE_NAME: &str = "BfdWinService";
/// Configuration key relative to HKEY_LOCAL_MACHINE.
pub const PARAMETERS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters";
/// Default append-log path; used only when LogToFile is enabled.
pub const DEFAULT_LOG_FILE_PATH: &str = r"C:\ProgramData\BfdWinService\trace.log";

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
    /// Peer unicast IP address, without a port
    pub peer: IpAddr,
    /// Transport profile: UDP 3784 or UDP 4784
    pub mode: Mode,
    /// Select multihop during validation; loaded from the Multihop registry flag
    pub multihop: bool,
    /// Point-to-point single-hop link; accept any peer source address on its interface
    pub point_to_point: bool,
    /// Desired minimum transmit interval while Up, in microseconds
    pub min_tx_us: u32,
    /// Required minimum receive interval, in microseconds
    pub min_rx_us: u32,
    /// Desired TX outside Up, in microseconds; at least one second, clamped to MinTxUs
    pub startup_tx_us: u32,
    /// Detection multiplier advertised to the peer
    pub detect_mult: u8,
    /// Local discriminator; omitted means a random nonzero value
    pub discriminator: Option<u32>,
    /// Stable UDP source port (49152..65535); omitted means automatically allocated
    pub source_port: Option<u16>,
    /// Wait for a validated peer control packet (multihop only)
    pub passive: bool,
    /// Windows interface index; required for single-hop and IPv6 link-local addresses
    pub interface_index: Option<u32>,
    /// Minimum accepted TTL/hop limit in multihop (single-hop always requires 255)
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
    /// Construct default settings for the required local and peer addresses.
    /// Call validate after provisioning the transport/authentication settings.
    pub fn new(local: IpAddr, peer: IpAddr) -> Self {
        Self {
            console: false,
            local,
            peer,
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
    pub fn validate(&mut self) -> Result<AuthConfig, String> {
        // Validate registry-loaded and programmatically constructed settings alike.
        self.validate_ranges()?;
        if self.auth_key.is_some() && self.auth_key_hex.is_some() {
            return Err("AuthKey and AuthKeyHex are mutually exclusive".into());
        }
        for (name, value) in [
            ("BgpPeerName", &self.bgp_peer_name),
            ("BgpRoutingDomain", &self.bgp_routing_domain),
        ] {
            if value
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
            {
                return Err(format!(
                    "{name} must be nonempty and contain no NUL characters"
                ));
            }
        }
        if self.bgp_routing_domain.is_some() && self.bgp_peer_name.is_none() {
            return Err("BgpRoutingDomain requires BgpPeerName".into());
        }
        if self.multihop {
            self.mode = Mode::Multihop;
        }
        if self.local.is_ipv4() != self.peer.is_ipv4() {
            return Err("Local and Peer must have the same address family".into());
        }
        for (name, ip) in [("Local", self.local), ("Peer", self.peer)] {
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            {
                return Err(format!("{name} must be a specific unicast address"));
            }
        }
        if self.local == self.peer {
            return Err("Local and Peer must differ".into());
        }
        if self.point_to_point && self.mode != Mode::SingleHop {
            return Err("PointToPoint applies only to single-hop sessions".into());
        }
        if self.mode == Mode::SingleHop {
            if self.passive {
                return Err(
                    "single-hop BFD requires the active role; Passive is multihop only".into(),
                );
            }
            if self.interface_index.is_none() {
                return Err(
                    "single-hop BFD requires InterfaceIndex to bind the session to its path".into(),
                );
            }
            if self.min_ttl.is_some() {
                return Err("MinTtl applies only to multihop; single-hop requires TTL 255".into());
            }
        }
        if [self.local, self.peer]
            .iter()
            .any(|ip| matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
            && self.interface_index.is_none()
        {
            return Err("IPv6 link-local addresses require InterfaceIndex".into());
        }
        let key = if let Some(hex) = &self.auth_key_hex {
            if hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err("AuthKeyHex must contain pairs of hexadecimal digits".into());
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&hex[i..i + 2], 16)
                        .map_err(|_| "AuthKeyHex contains an invalid byte".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if let Some(key) = &self.auth_key {
            if !key.is_ascii() {
                return Err("AuthKey must be ASCII; use AuthKeyHex for binary keys".into());
            }
            key.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        AuthConfig::new(self.auth, self.auth_key_id, key)
    }

    pub(crate) fn validate_ranges(&self) -> Result<(), String> {
        if self.min_tx_us == 0 || self.min_rx_us == 0 {
            return Err("MinTxUs and MinRxUs must be nonzero".into());
        }
        if self.startup_tx_us < 1_000_000 {
            return Err("StartupTxUs must be at least 1000000".into());
        }
        if self.detect_mult == 0 {
            return Err("DetectMult must be nonzero".into());
        }
        if self.discriminator == Some(0) {
            return Err("Discriminator must be nonzero".into());
        }
        if self.source_port.is_some_and(|port| port < 49152) {
            return Err("SourcePort must be within 49152..65535".into());
        }
        if self.interface_index == Some(0) || self.min_ttl == Some(0) {
            return Err("InterfaceIndex and MinTtl must be nonzero when specified".into());
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
