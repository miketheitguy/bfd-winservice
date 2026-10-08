//! Read service settings without creating or modifying registry keys.
use super::{Mode, Options, PARAMETERS_KEY};
use crate::packet::AuthType;
use clap::ValueEnum;
use std::{io, net::IpAddr, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS},
    System::Registry::{
        RegGetValueW, HKEY, HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    },
};

/// Read settings from the service's HKLM Parameters key. Only the execution
/// mode comes from the command line; optional values retain their defaults.
/// Call Options::validate before opening the engine.
///
/// # Errors
/// Returns errors for missing required addresses, denied registry access,
/// incorrect value types, invalid Unicode/enums, or overflowing numeric values.
/// Error messages identify value names and never include authentication keys.
pub fn load_registry(console: bool) -> io::Result<Options> {
    Registry::new(HKEY_LOCAL_MACHINE, PARAMETERS_KEY).load(console)
}

struct Registry {
    // A borrowed predefined key (or test fixture handle); never owned/closed.
    root: HKEY,
    path: Vec<u16>,
}

impl Registry {
    fn new(root: HKEY, path: &str) -> Self {
        Self {
            root,
            path: wide(path),
        }
    }

    fn load(&self, console: bool) -> io::Result<Options> {
        let mut options = Options::new(self.address("Local")?, self.address("Peer")?);
        options.console = console;
        let mode = self.string("Mode")?;
        if let Some(mode) = &mode {
            options.mode = Mode::from_str(mode, false)
                .map_err(|_| invalid("Mode", "must be single-hop or multihop"))?;
        }
        options.multihop = self.boolean("Multihop")?;
        if options.multihop && mode.is_some() {
            return Err(invalid(
                "Multihop",
                "cannot be combined with Mode; use one transport selector",
            ));
        }
        options.point_to_point = self.boolean("PointToPoint")?;
        options.min_tx_us = self.dword("MinTxUs")?.unwrap_or(options.min_tx_us);
        options.min_rx_us = self.dword("MinRxUs")?.unwrap_or(options.min_rx_us);
        options.startup_tx_us = self.dword("StartupTxUs")?.unwrap_or(options.startup_tx_us);
        options.detect_mult = self.narrow("DetectMult")?.unwrap_or(options.detect_mult);
        options.discriminator = self.dword("Discriminator")?;
        options.source_port = self.narrow("SourcePort")?;
        options.passive = self.boolean("Passive")?;
        options.interface_index = self.dword("InterfaceIndex")?;
        options.min_ttl = self.narrow("MinTtl")?;
        if let Some(auth) = self.string("Auth")? {
            options.auth = AuthType::from_str(&auth, false)
                .map_err(|_| invalid("Auth", "has an unsupported authentication type"))?;
        }
        options.auth_key_id = self.narrow("AuthKeyId")?.unwrap_or(options.auth_key_id);
        options.auth_key = self.string("AuthKey")?;
        options.auth_key_hex = self.string("AuthKeyHex")?;
        options.log_file = self.string("LogFile")?.map(Into::into);
        options.bgp_peer_name = self.string("BgpPeerName")?;
        options.bgp_routing_domain = self.string("BgpRoutingDomain")?;
        options.verbose = self.boolean("Verbose")?;
        Ok(options)
    }

    fn address(&self, name: &str) -> io::Result<IpAddr> {
        self.string(name)?
            .ok_or_else(|| invalid(name, "is required"))?
            .parse()
            .map_err(|_| invalid(name, "must be an IPv4 or IPv6 literal"))
    }

    fn boolean(&self, name: &str) -> io::Result<bool> {
        match self.dword(name)?.unwrap_or(0) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid(name, "must be DWORD 0 or 1")),
        }
    }

    fn narrow<T: TryFrom<u32>>(&self, name: &str) -> io::Result<Option<T>> {
        self.dword(name)?
            .map(|value| {
                T::try_from(value)
                    .map_err(|_| invalid(name, "is outside its supported numeric range"))
            })
            .transpose()
    }

    fn dword(&self, name: &str) -> io::Result<Option<u32>> {
        let name_wide = wide(name);
        let mut value = 0u32;
        let mut size = 4;
        // SAFETY: root is a valid borrowed key. Both names are NUL-terminated,
        // and value/size are writable for the full synchronous call. The strict
        // type flag rejects binary/string values instead of coercing them.
        let status = unsafe {
            RegGetValueW(
                self.root,
                self.path.as_ptr(),
                name_wide.as_ptr(),
                RRF_RT_REG_DWORD,
                ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        check(status, name, "REG_DWORD")?;
        if size != 4 {
            return Err(invalid(name, "must contain exactly four DWORD bytes"));
        }
        Ok(Some(value))
    }

    fn string(&self, name: &str) -> io::Result<Option<String>> {
        let name_wide = wide(name);
        let mut buffer = vec![0u16; 256];
        // Bounded retries handle a value changing size during startup. Values
        // exceeding 64 KiB or continually growing fail instead of looping.
        for _ in 0..4 {
            let mut bytes =
                u32::try_from(buffer.len() * 2).map_err(|_| invalid(name, "is too large"))?;
            // SAFETY: names and the borrowed root are valid. The initialized
            // u16 buffer is writable for exactly bytes bytes, and remains alive
            // throughout the call. RegGetValueW ensures string termination.
            let status = unsafe {
                RegGetValueW(
                    self.root,
                    self.path.as_ptr(),
                    name_wide.as_ptr(),
                    // Preserve the stored type so REG_EXPAND_SZ is rejected,
                    // rather than expanded and treated as REG_SZ by Windows.
                    RRF_RT_REG_SZ | RRF_NOEXPAND,
                    ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    &mut bytes,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status == ERROR_MORE_DATA {
                if bytes > 65536 || !bytes.is_multiple_of(2) {
                    return Err(invalid(name, "has an invalid or oversized string length"));
                }
                buffer.resize(
                    usize::try_from(bytes / 2).map_err(|_| invalid(name, "is too large"))?,
                    0,
                );
                continue;
            }
            check(status, name, "REG_SZ")?;
            return decode_string(name, &buffer, bytes).map(Some);
        }
        Err(invalid(name, "changed size repeatedly while reading"))
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn invalid(name: &str, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("registry value {name} {reason}"),
    )
}

fn check(status: u32, name: &str, expected: &str) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        return Ok(());
    }
    let error = io::Error::from_raw_os_error(i32::from_ne_bytes(status.to_ne_bytes()));
    Err(io::Error::new(
        error.kind(),
        format!("cannot read registry value {name} as {expected}: {error}"),
    ))
}

fn decode_string(name: &str, buffer: &[u16], bytes: u32) -> io::Result<String> {
    let units = usize::try_from(bytes / 2).map_err(|_| invalid(name, "is too large"))?;
    if !bytes.is_multiple_of(2) || units == 0 || units > buffer.len() || buffer[units - 1] != 0 {
        return Err(invalid(name, "is not a terminated UTF-16 string"));
    }
    let text = &buffer[..units - 1];
    if text.contains(&0) {
        return Err(invalid(name, "contains an embedded NUL"));
    }
    String::from_utf16(text).map_err(|_| invalid(name, "contains invalid UTF-16"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_strings_require_valid_terminated_utf16_without_embedded_nuls() {
        let text = wide("Péér 🦀");
        assert_eq!(
            decode_string("BgpPeerName", &text, u32::try_from(text.len() * 2).unwrap()).unwrap(),
            "Péér 🦀"
        );
        for (data, bytes) in [
            (&[65, 0][..], 3),
            (&[65][..], 2),
            (&[65, 0][..], 6),
            (&[65, 0, 66, 0][..], 8),
            (&[0xd800, 0][..], 4),
            (&[][..], 0),
        ] {
            assert!(decode_string("AuthKey", data, bytes).is_err());
        }
    }

    #[cfg(not(miri))]
    mod native {
        use super::*;
        use crate::packet::AuthConfig;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyW, RegDeleteKeyW, RegDeleteValueW, RegSetValueExW,
            HKEY_CURRENT_USER, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
        };

        // Every fixture owns a unique HKCU key. No installed service/HKLM
        // settings are changed, and Drop closes the handle before removing it.
        struct Fixture {
            path: Vec<u16>,
            key: HKEY,
        }

        impl Fixture {
            fn new() -> Self {
                let path = wide(&format!(
                    "Software\\bfd-winservice-test-{}-{}",
                    std::process::id(),
                    rand::random::<u64>()
                ));
                let mut key = ptr::null_mut();
                // SAFETY: the predefined root/name and writable output are valid.
                check(
                    unsafe { RegCreateKeyW(HKEY_CURRENT_USER, path.as_ptr(), &mut key) },
                    "test key",
                    "key",
                )
                .unwrap();
                Self { path, key }
            }
            fn set(&self, name: &str, kind: u32, data: &[u8]) {
                let name_wide = wide(name);
                let size = u32::try_from(data.len()).unwrap();
                // SAFETY: fixture owns a live key; names/data remain valid for
                // the call and size is exactly the initialized data length.
                check(
                    unsafe {
                        RegSetValueExW(self.key, name_wide.as_ptr(), 0, kind, data.as_ptr(), size)
                    },
                    name,
                    "test value",
                )
                .unwrap();
            }
            fn string(&self, name: &str, value: &str) {
                let data: Vec<_> = wide(value).into_iter().flat_map(u16::to_le_bytes).collect();
                self.set(name, REG_SZ, &data);
            }
            fn dword(&self, name: &str, value: u32) {
                self.set(name, REG_DWORD, &value.to_le_bytes());
            }
            fn remove(&self, name: &str) {
                let name = wide(name);
                // SAFETY: key and terminated value name are valid for the call.
                check(
                    unsafe { RegDeleteValueW(self.key, name.as_ptr()) },
                    "test value",
                    "value",
                )
                .unwrap();
            }
            fn addresses(&self) {
                self.string("Local", "192.0.2.1");
                self.string("Peer", "192.0.2.2");
            }
            fn load(&self, console: bool) -> io::Result<Options> {
                Registry::new(self.key, "").load(console)
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                // SAFETY: fixture is the sole handle owner and no read borrows
                // remain; close exactly once before deleting its unique HKCU key.
                let closed = unsafe { RegCloseKey(self.key) };
                // SAFETY: this terminated path names only the fixture's unique
                // test key, which has no subkeys and is no longer used.
                let deleted = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, self.path.as_ptr()) };
                if closed != ERROR_SUCCESS || deleted != ERROR_SUCCESS {
                    eprintln!("registry fixture cleanup failed: close={closed}, delete={deleted}");
                }
            }
        }

        #[test]
        fn native_registry_required_values_and_defaults_are_read_without_writes() {
            let fixture = Fixture::new();
            assert!(fixture
                .load(false)
                .err()
                .unwrap()
                .to_string()
                .contains("Local"));
            fixture.string("Local", "192.0.2.1");
            assert!(fixture
                .load(false)
                .err()
                .unwrap()
                .to_string()
                .contains("Peer"));
            fixture.string("Peer", "192.0.2.2");
            fixture.dword("InterfaceIndex", 12);
            let mut options = fixture.load(true).unwrap();
            assert!(options.console);
            assert_eq!(options.mode, Mode::SingleHop);
            assert_eq!(
                (options.min_tx_us, options.min_rx_us, options.startup_tx_us),
                (300000, 300000, 1000000)
            );
            assert_eq!((options.detect_mult, options.auth_key_id), (3, 0));
            assert_eq!(options.interface_index, Some(12));
            assert!(options.discriminator.is_none() && options.source_port.is_none());
            assert!(options.log_file.is_none() && options.bgp_peer_name.is_none());
            assert!(options.validate().is_ok());
        }

        #[test]
        fn native_registry_loads_all_types_including_unicode_and_dword_limits() {
            let fixture = Fixture::new();
            for (name, value) in [
                ("Local", "2001:db8::1"),
                ("Peer", "2001:db8::2"),
                ("Mode", "multihop"),
                ("Auth", "meticulous-sha1"),
                ("AuthKeyHex", "00fe12"),
                ("BgpPeerName", "Péér 🦀"),
                ("BgpRoutingDomain", "Domaine 🦀"),
                ("LogFile", r"C:\BFD\résultats.log"),
            ] {
                fixture.string(name, value);
            }
            for (name, value) in [
                ("Multihop", 0),
                ("PointToPoint", 0),
                ("MinTxUs", u32::MAX),
                ("MinRxUs", 1),
                ("StartupTxUs", 2000000),
                ("DetectMult", 255),
                ("Discriminator", u32::MAX),
                ("SourcePort", 65535),
                ("Passive", 1),
                ("InterfaceIndex", 42),
                ("MinTtl", 255),
                ("AuthKeyId", 255),
                ("Verbose", 1),
            ] {
                fixture.dword(name, value);
            }
            let mut options = fixture.load(false).unwrap();
            assert!(!options.console && options.passive && options.verbose);
            assert_eq!(
                (options.min_tx_us, options.min_rx_us, options.startup_tx_us),
                (u32::MAX, 1, 2000000)
            );
            assert_eq!((options.detect_mult, options.auth_key_id), (255, 255));
            assert_eq!(
                (options.discriminator, options.source_port, options.min_ttl),
                (Some(u32::MAX), Some(65535), Some(255))
            );
            assert_eq!(options.bgp_peer_name.as_deref(), Some("Péér 🦀"));
            assert_eq!(options.bgp_routing_domain.as_deref(), Some("Domaine 🦀"));
            assert_eq!(
                options.log_file.unwrap().to_str(),
                Some(r"C:\BFD\résultats.log")
            );
            options.log_file = None;
            assert!(
                options.validate().unwrap()
                    == AuthConfig::new(AuthType::MeticulousSha1, 255, vec![0, 254, 18]).unwrap()
            );
            fixture.remove("AuthKeyHex");
            fixture.string("AuthKey", "hidden-key");
            assert!(fixture.load(false).unwrap().validate().is_ok());
        }

        #[test]
        fn native_registry_rejects_wrong_types_instead_of_using_defaults() {
            let fixture = Fixture::new();
            fixture.addresses();
            for name in ["InterfaceIndex", "DetectMult", "Passive"] {
                fixture.string(name, "12");
                let error = fixture.load(false).err().unwrap().to_string();
                assert!(
                    error.contains(name) && error.contains("REG_DWORD"),
                    "{error}"
                );
                fixture.remove(name);
            }
            for name in ["Auth", "BgpPeerName", "LogFile", "AuthKey"] {
                fixture.dword(name, 1);
                let error = fixture.load(false).err().unwrap().to_string();
                assert!(error.contains(name) && error.contains("REG_SZ"), "{error}");
                fixture.remove(name);
            }
            fixture.set("LogFile", REG_EXPAND_SZ, &[0, 0]);
            assert!(fixture.load(false).is_err());
        }

        #[test]
        fn native_registry_handles_long_strings_and_rejects_malformed_or_oversized_data() {
            let fixture = Fixture::new();
            fixture.addresses();
            let long_name = "Péér 🦀".repeat(200);
            fixture.string("BgpPeerName", &long_name);
            assert_eq!(
                fixture.load(false).unwrap().bgp_peer_name.as_deref(),
                Some(long_name.as_str())
            );
            for data in [
                vec![0x00, 0xd8, 0x00, 0x00],   // unpaired surrogate
                vec![65, 0, 0, 0, 66, 0, 0, 0], // embedded NUL
            ] {
                fixture.set("BgpPeerName", REG_SZ, &data);
                assert!(fixture.load(false).is_err());
            }
            fixture.string("BgpPeerName", &"Z".repeat(33000));
            let error = fixture.load(false).err().unwrap().to_string();
            assert!(error.contains("BgpPeerName") && error.contains("oversized"));
        }

        #[test]
        fn native_registry_rejects_overflow_invalid_booleans_and_conflicting_selectors() {
            let fixture = Fixture::new();
            fixture.addresses();
            for (name, value) in [
                ("DetectMult", 256),
                ("AuthKeyId", 256),
                ("SourcePort", 65536),
                ("MinTtl", 256),
                ("Verbose", 2),
                ("Passive", 2),
                ("PointToPoint", 2),
                ("Multihop", 2),
            ] {
                fixture.dword(name, value);
                assert!(fixture
                    .load(false)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains(name));
                fixture.remove(name);
            }
            fixture.string("Mode", "invalid");
            assert!(fixture.load(false).is_err());
            fixture.string("Mode", "single-hop");
            fixture.dword("Multihop", 1);
            assert!(fixture.load(false).is_err());
            fixture.remove("Mode");
            let mut options = fixture.load(false).unwrap();
            assert!(options.validate().is_ok());
            assert_eq!(options.mode, Mode::Multihop);
            fixture.string("Auth", "invalid-auth-hidden-key");
            let error = fixture.load(false).err().unwrap().to_string();
            assert!(error.contains("Auth") && !error.contains("hidden-key"));
        }
    }
}
