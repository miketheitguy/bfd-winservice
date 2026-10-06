//! Command-line options and validation for one provisioned BFD session.
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use clap::{Parser, ValueEnum};

use crate::packet::{AuthConfig, AuthType};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
/// Single-hop or multihop UDP transport profile.
pub enum Mode {
    #[default]
    SingleHop,
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
#[derive(Clone, Parser)]
#[command(
    version,
    about = "Windows BFD service (asynchronous IPv4/IPv6, single-hop or multihop)"
)]
pub struct Options {
    /// Run in the foreground; Ctrl+C stops the session
    #[arg(long)]
    pub console: bool,
    /// Local unicast IP address (binds receive and transmit sockets)
    #[arg(long)]
    pub local: IpAddr,
    /// Peer unicast IP address, without a port
    #[arg(long)]
    pub peer: IpAddr,
    /// Transport profile: UDP 3784 or UDP 4784
    #[arg(long, value_enum, default_value_t)]
    pub mode: Mode,
    /// Shortcut for --mode multihop
    #[arg(long, conflicts_with = "mode")]
    pub multihop: bool,
    /// Point-to-point single-hop link; accept any peer source address on its interface
    #[arg(long)]
    pub point_to_point: bool,
    /// Desired minimum transmit interval while Up, in microseconds
    #[arg(long, default_value_t = 300_000, value_parser = clap::value_parser!(u32).range(1..))]
    pub min_tx_us: u32,
    /// Required minimum receive interval, in microseconds
    #[arg(long, default_value_t = 300_000, value_parser = clap::value_parser!(u32).range(1..))]
    pub min_rx_us: u32,
    /// Desired TX outside Up, in microseconds; at least one second, clamped to min-tx-us
    #[arg(long, default_value_t = 1_000_000, value_parser = clap::value_parser!(u32).range(1_000_000..))]
    pub startup_tx_us: u32,
    /// Detection multiplier advertised to the peer
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..))]
    pub detect_mult: u8,
    /// Local discriminator; omitted means a random nonzero value
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub discriminator: Option<u32>,
    /// Stable UDP source port (49152..65535); omitted means automatically allocated
    #[arg(long, value_parser = clap::value_parser!(u16).range(49152..))]
    pub source_port: Option<u16>,
    /// Wait for a validated peer control packet (multihop only)
    #[arg(long)]
    pub passive: bool,
    /// Windows interface index; required for single-hop and IPv6 link-local addresses
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub interface_index: Option<u32>,
    /// Minimum accepted TTL/hop limit in multihop (single-hop always requires 255)
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..))]
    pub min_ttl: Option<u8>,
    /// Authentication mechanism (must match the peer)
    #[arg(long, value_enum, default_value_t = AuthType::None)]
    pub auth: AuthType,
    /// Authentication key identifier
    #[arg(long, default_value_t = 0)]
    pub auth_key_id: u8,
    /// ASCII authentication key (use --auth-key-hex for binary keys)
    #[arg(long, conflicts_with = "auth_key_hex")]
    pub auth_key: Option<String>,
    /// Authentication key as hexadecimal bytes
    #[arg(long, conflicts_with = "auth_key")]
    pub auth_key_hex: Option<String>,
    /// Append timestamped state changes and errors to this file (use an absolute path for SCM)
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    /// Enable native MI BGP control for this configured peer name
    #[arg(long)]
    pub bgp_peer_name: Option<String>,
    /// Routing domain of the BGP peer; omitted selects the default domain
    #[arg(long, requires = "bgp_peer_name")]
    pub bgp_routing_domain: Option<String>,
    /// Log discarded packets (rate limited)
    #[arg(long)]
    pub verbose: bool,
}

impl Options {
    /// Check ranges, addresses, transport profile, and authentication configuration.
    ///
    /// Normalizes the multihop shortcut into mode and returns validated authentication.
    /// Parsing alone does not perform these checks. Public fields can be changed,
    /// so validate again after mutation before using the options.
    ///
    /// # Errors
    /// Returns an error for unsupported option combinations or invalid values/keys.
    /// Mode normalization can occur before a later validation error.
    pub fn validate(&mut self) -> Result<AuthConfig, String> {
        // Clap's range/conflict parsers do not run for programmatic callers.
        self.validate_ranges()?;
        if self.auth_key.is_some() && self.auth_key_hex.is_some() {
            return Err("--auth-key and --auth-key-hex are mutually exclusive".into());
        }
        for (name, value) in [
            ("bgp-peer-name", &self.bgp_peer_name),
            ("bgp-routing-domain", &self.bgp_routing_domain),
        ] {
            if value
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
            {
                return Err(format!(
                    "--{name} must be nonempty and contain no NUL characters"
                ));
            }
        }
        if self.bgp_routing_domain.is_some() && self.bgp_peer_name.is_none() {
            return Err("--bgp-routing-domain requires --bgp-peer-name".into());
        }
        if self.multihop {
            self.mode = Mode::Multihop;
        }
        if self.local.is_ipv4() != self.peer.is_ipv4() {
            return Err("--local and --peer must have the same address family".into());
        }
        for (name, ip) in [("local", self.local), ("peer", self.peer)] {
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            {
                return Err(format!("--{name} must be a specific unicast address"));
            }
        }
        if self.local == self.peer {
            return Err("--local and --peer must differ".into());
        }
        if self.point_to_point && self.mode != Mode::SingleHop {
            return Err("--point-to-point applies only to single-hop sessions".into());
        }
        if self.mode == Mode::SingleHop {
            if self.passive {
                return Err(
                    "single-hop BFD requires the active role; --passive is multihop only".into(),
                );
            }
            if self.interface_index.is_none() {
                return Err(
                    "single-hop BFD requires --interface-index to bind the session to its path"
                        .into(),
                );
            }
            if self.min_ttl.is_some() {
                return Err(
                    "--min-ttl applies only to multihop; single-hop requires TTL 255".into(),
                );
            }
        }
        if [self.local, self.peer]
            .iter()
            .any(|ip| matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
            && self.interface_index.is_none()
        {
            return Err("IPv6 link-local addresses require --interface-index".into());
        }
        let key = if let Some(hex) = &self.auth_key_hex {
            if hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err("--auth-key-hex must contain pairs of hexadecimal digits".into());
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&hex[i..i + 2], 16)
                        .map_err(|_| "--auth-key-hex contains an invalid byte".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if let Some(key) = &self.auth_key {
            if !key.is_ascii() {
                return Err("--auth-key must be ASCII; use --auth-key-hex for binary keys".into());
            }
            key.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        AuthConfig::new(self.auth, self.auth_key_id, key)
    }

    pub(crate) fn validate_ranges(&self) -> Result<(), String> {
        if self.min_tx_us == 0 || self.min_rx_us == 0 {
            return Err("--min-tx-us and --min-rx-us must be nonzero".into());
        }
        if self.startup_tx_us < 1_000_000 {
            return Err("--startup-tx-us must be at least 1000000".into());
        }
        if self.detect_mult == 0 {
            return Err("--detect-mult must be nonzero".into());
        }
        if self.discriminator == Some(0) {
            return Err("--discriminator must be nonzero".into());
        }
        if self.source_port.is_some_and(|port| port < 49152) {
            return Err("--source-port must be within 49152..65535".into());
        }
        if self.interface_index == Some(0) || self.min_ttl == Some(0) {
            return Err("--interface-index and --min-ttl must be nonzero when specified".into());
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
    fn parse(extra: &[&str]) -> Result<Options, clap::Error> {
        Options::try_parse_from(
            ["bfd", "--local", "192.0.2.1", "--peer", "192.0.2.2"]
                .into_iter()
                .chain(extra.iter().copied()),
        )
    }
    #[test]
    fn validates_profiles_and_numeric_ranges() {
        assert!(parse(&[]).unwrap().validate().is_err());
        assert!(parse(&["--interface-index", "2"])
            .unwrap()
            .validate()
            .is_ok());
        let mut options = parse(&["--multihop", "--passive"]).unwrap();
        assert!(options.validate().is_ok());
        assert_eq!(options.mode.port(), 4784);
        for args in [
            &["--detect-mult", "0"][..],
            &["--min-tx-us", "0"],
            &["--startup-tx-us", "999999"],
            &["--source-port", "3784"],
            &["--discriminator", "0"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
        assert!(parse(&["--interface-index", "2", "--passive"])
            .unwrap()
            .validate()
            .is_err());
    }
    #[test]
    fn validates_authentication_keys() {
        assert!(parse(&["--multihop", "--auth", "meticulous-sha1"])
            .unwrap()
            .validate()
            .is_err());
        assert!(parse(&["--multihop", "--auth-key", "secret"])
            .unwrap()
            .validate()
            .is_err());
        assert!(parse(&[
            "--multihop",
            "--auth",
            "keyed-sha1",
            "--auth-key-hex",
            "00fe12"
        ])
        .unwrap()
        .validate()
        .is_ok());
        assert!(parse(&[
            "--multihop",
            "--auth",
            "simple-password",
            "--auth-key-hex",
            "zz"
        ])
        .unwrap()
        .validate()
        .is_err());
    }

    #[test]
    fn programmatic_options_cannot_bypass_numeric_ranges_or_key_conflicts() {
        let valid = parse(&["--multihop"]).unwrap();
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
        assert!(parse(&["--multihop", "--bgp-peer-name", "Site17"])
            .unwrap()
            .validate()
            .is_ok());
        assert!(parse(&[
            "--multihop",
            "--bgp-peer-name",
            "Site17",
            "--bgp-routing-domain",
            "Rd001"
        ])
        .unwrap()
        .validate()
        .is_ok());
        assert!(parse(&["--multihop", "--bgp-routing-domain", "Rd001"]).is_err());
        for name in ["", "  ", "Site\0other"] {
            assert!(parse(&["--multihop", "--bgp-peer-name", name])
                .unwrap()
                .validate()
                .is_err());
        }
        assert!(parse(&[
            "--multihop",
            "--bgp-peer-name",
            "Site17",
            "--bgp-routing-domain",
            ""
        ])
        .unwrap()
        .validate()
        .is_err());
    }

    #[test]
    fn point_to_point_requires_single_hop_and_an_interface() {
        assert!(parse(&["--point-to-point", "--interface-index", "2"])
            .unwrap()
            .validate()
            .is_ok());
        assert!(parse(&["--point-to-point"]).unwrap().validate().is_err());
        for mode in [&["--multihop"][..], &["--mode", "multihop"][..]] {
            let mut args = vec!["--point-to-point", "--interface-index", "2"];
            args.extend_from_slice(mode);
            assert!(parse(&args).unwrap().validate().is_err());
        }
    }
}
