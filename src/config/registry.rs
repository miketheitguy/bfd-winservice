//! Read service settings without creating or modifying registry keys.
// Registry calls and handle ownership require the Windows FFI boundary.
#![allow(unsafe_code)]
use super::{Mode, Options, SessionType, Timing, ValidatedOptions, PARAMETERS_KEY};
use crate::packet::AuthType;
use clap::ValueEnum;
use std::{
    io,
    net::IpAddr,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        Registry::{
            RegCloseKey, RegGetValueW, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY,
            HKEY_LOCAL_MACHINE, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_THREAD_AGNOSTIC,
            RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
        },
        Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
    },
};

/// Read settings from the service's HKLM Parameters key. Only the execution
/// mode comes from the command line; optional values retain their defaults.
/// Multihop selects the transport: absent/0 is single-hop, 1 is multihop.
/// SessionType selects classical BFD or an S-BFD role; reflectors omit Peer.
/// Returns an immutable, validated snapshot ready for Engine::from_config.
///
/// # Errors
/// Returns errors for missing required addresses, denied registry access,
/// incorrect value types, invalid Unicode/enums, or overflowing numeric values.
/// Error messages identify value names and never include authentication keys.
pub fn load_registry(console: bool) -> io::Result<ValidatedOptions> {
    Registry::new(HKEY_LOCAL_MACHINE, PARAMETERS_KEY)
        .load(console)?
        .into_validated()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

pub(crate) fn load_sbfd_settings(options: &Options) -> io::Result<(Timing, bool)> {
    Registry::new(HKEY_LOCAL_MACHINE, PARAMETERS_KEY).sbfd_settings(options)
}

/// Signals an event when a value in the Parameters key changes, so live S-BFD
/// settings reload on demand instead of through periodic registry reads.
pub(crate) struct SettingsWatch {
    // Field order closes the key, which cancels its notification, before the event.
    key: OwnedKey,
    event: OwnedHandle,
}

struct OwnedKey(HKEY);

// SAFETY: an opened registry key is a process-wide kernel handle, usable and
// closable from any thread. Its notification is registered thread-agnostic, and
// the key is owned exclusively, so moving it with the engine is sound.
unsafe impl Send for OwnedKey {}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: this owner closes its successfully opened key exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl SettingsWatch {
    pub(crate) fn open() -> io::Result<Self> {
        Self::open_at(HKEY_LOCAL_MACHINE, PARAMETERS_KEY)
    }

    fn open_at(root: HKEY, path: &str) -> io::Result<Self> {
        let path = wide(path);
        let mut key = ptr::null_mut();
        // SAFETY: root is a valid borrowed key, path is terminated, and the
        // output is writable. KEY_NOTIFY grants only change notification.
        let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_NOTIFY, &mut key) };
        check(status, "Parameters", "a change-notification key")?;
        let key = OwnedKey(key);
        // SAFETY: unnamed manual-reset event, no borrowed security/name storage.
        let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateEventW returned a new valid handle owned by this function.
        let event = unsafe { OwnedHandle::from_raw_handle(raw) };
        let watch = Self { key, event };
        watch.arm()?;
        Ok(watch)
    }

    fn arm(&self) -> io::Result<()> {
        // SAFETY: the key and event stay alive until Drop closes the key first.
        // Thread-agnostic registration survives the creating thread.
        check(
            unsafe {
                RegNotifyChangeKeyValue(
                    self.key.0,
                    0,
                    REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                    self.event.as_raw_handle(),
                    1,
                )
            },
            "Parameters",
            "a change notification",
        )
    }

    /// The manual-reset event that becomes signalled after a value changes.
    pub(crate) fn event(&self) -> BorrowedHandle<'_> {
        self.event.as_handle()
    }

    /// Consumes a pending change and rearms before the caller reads the settings,
    /// so a later write signals again rather than being lost.
    ///
    /// # Errors
    /// Returns wait or registration errors, including deletion of the watched key.
    pub(crate) fn take_change(&self) -> io::Result<bool> {
        // SAFETY: the owned event is alive; a zero timeout only samples its state.
        match unsafe { WaitForSingleObject(self.event.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(false),
            WAIT_OBJECT_0 => {
                // SAFETY: the owned manual-reset event is alive.
                if unsafe { ResetEvent(self.event.as_raw_handle()) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                self.arm()?;
                Ok(true)
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// The privileged broker reads its target from protected HKLM configuration,
/// never from an IPC message. It does not need BFD addresses or authentication keys.
pub(crate) fn load_bgp_target() -> io::Result<Option<(String, Option<String>)>> {
    bgp_target(&Registry::new(HKEY_LOCAL_MACHINE, PARAMETERS_KEY))
}

fn bgp_target(registry: &Registry) -> io::Result<Option<(String, Option<String>)>> {
    let peer = registry.string("BgpPeerName")?;
    let domain = registry.string("BgpRoutingDomain")?;
    for (name, value) in [("BgpPeerName", &peer), ("BgpRoutingDomain", &domain)] {
        if value
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
        {
            return Err(invalid(name, "must be a nonempty name"));
        }
    }
    if domain.is_some() && peer.is_none() {
        return Err(invalid("BgpRoutingDomain", "requires BgpPeerName"));
    }
    Ok(peer.map(|peer| (peer, domain)))
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
        let session_type = self
            .string("SessionType")?
            .map(|value| {
                SessionType::from_str(&value, false)
                    .map_err(|_| invalid("SessionType", "has an unsupported protocol role"))
            })
            .transpose()?
            .unwrap_or_default();
        let local = self.address("Local")?;
        let mut options = if session_type == SessionType::SbfdReflector {
            let discriminator = self
                .dword("Discriminator")?
                .ok_or_else(|| invalid("Discriminator", "is required for a reflector"))?;
            Options::reflector(local, discriminator)
        } else {
            Options::new(local, self.address("Peer")?)
        };
        options.session_type = session_type;
        options.registry_backed = true;
        options.remote_discriminator = self.dword("RemoteDiscriminator")?;
        options.sbfd_admin_down = self.boolean("SbfdAdminDown")?;
        if let Some(peers) = self.string("AllowedPeers")? {
            options.allowed_peers = peers
                .split(',')
                .map(|peer| {
                    peer.trim().parse().map_err(|_| {
                        invalid("AllowedPeers", "must contain comma-separated IP literals")
                    })
                })
                .collect::<io::Result<_>>()?;
        }
        options.console = console;
        options.multihop = self.boolean("Multihop")?;
        options.mode = if options.multihop {
            Mode::Multihop
        } else {
            Mode::SingleHop
        };
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
        if let Some(path) = self.string("LogFilePath")? {
            options.log_file_path = path.into();
        }
        options.log_to_file = self.boolean("LogToFile")?;
        options.max_shutdown_announce_ms = self
            .dword("MaxShutdownAnnounceMs")?
            .unwrap_or(options.max_shutdown_announce_ms);
        options.bgp_peer_name = self.string("BgpPeerName")?;
        options.bgp_routing_domain = self.string("BgpRoutingDomain")?;
        options.verbose = self.boolean("Verbose")?;
        Ok(options)
    }

    fn sbfd_settings(&self, options: &Options) -> io::Result<(Timing, bool)> {
        let defaults = Options::new(options.local, options.peer);
        let timing = Timing::new(
            self.dword("MinTxUs")?.unwrap_or(defaults.min_tx_us),
            self.dword("MinRxUs")?.unwrap_or(defaults.min_rx_us),
            self.narrow("DetectMult")?.unwrap_or(defaults.detect_mult),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let admin_down = self.boolean("SbfdAdminDown")?;
        if admin_down && options.session_type != SessionType::SbfdReflector {
            return Err(invalid("SbfdAdminDown", "applies only to reflectors"));
        }
        Ok((timing, admin_down))
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
            // Values can hold authentication keys; clear every native buffer we release.
            if status == ERROR_MORE_DATA {
                super::wipe(&mut buffer);
                if bytes > 65536 || !bytes.is_multiple_of(2) {
                    return Err(invalid(name, "has an invalid or oversized string length"));
                }
                buffer.resize(
                    usize::try_from(bytes / 2).map_err(|_| invalid(name, "is too large"))?,
                    0,
                );
                continue;
            }
            let result = check(status, name, "REG_SZ")
                .and_then(|()| decode_string(name, &buffer, bytes).map(Some));
            super::wipe(&mut buffer);
            return result;
        }
        super::wipe(&mut buffer);
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
        use crate::{config::DEFAULT_LOG_FILE_PATH, packet::AuthConfig};
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
        fn broker_target_does_not_read_bfd_addresses_or_authentication() {
            let fixture = Fixture::new();
            let registry = Registry::new(fixture.key, "");
            assert_eq!(bgp_target(&registry).unwrap(), None);
            fixture.string("AuthKey", "\u{0}");
            fixture.dword("Local", 1);
            fixture.string("BgpPeerName", "Site 🦀");
            assert_eq!(
                bgp_target(&registry).unwrap(),
                Some(("Site 🦀".into(), None))
            );
            fixture.string("BgpRoutingDomain", "Tenant");
            assert_eq!(
                bgp_target(&registry).unwrap(),
                Some(("Site 🦀".into(), Some("Tenant".into())))
            );
            fixture.remove("BgpPeerName");
            assert!(bgp_target(&registry).is_err());
            fixture.string("BgpPeerName", " ");
            assert!(bgp_target(&registry).is_err());
            fixture.dword("BgpPeerName", 1);
            assert!(bgp_target(&registry).is_err());
        }

        #[test]
        fn native_registry_loads_both_seamless_roles_and_source_filters() {
            let fixture = Fixture::new();
            fixture.string("Local", "192.0.2.2");
            fixture.string("SessionType", "sbfd-reflector");
            fixture.dword("Discriminator", 99);
            fixture.string("AllowedPeers", "192.0.2.1, 192.0.2.3");
            let mut options = fixture.load(true).unwrap();
            assert_eq!(options.session_type, SessionType::SbfdReflector);
            assert_eq!(options.control_port(), 7784);
            assert_eq!(options.allowed_peers.len(), 2);
            assert!(options.peer.is_unspecified());
            options.validate().unwrap();
            fixture.string("SessionType", "sbfd-initiator");
            fixture.string("Peer", "192.0.2.1");
            fixture.dword("RemoteDiscriminator", 7);
            let mut options = fixture.load(true).unwrap();
            assert_eq!(options.remote_discriminator, Some(7));
            options.validate().unwrap();
        }

        #[test]
        fn native_registry_rejects_invalid_seamless_values_and_types() {
            let fixture = Fixture::new();
            fixture.addresses();
            fixture.string("SessionType", "unknown");
            assert!(fixture.load(true).is_err());
            fixture.dword("SessionType", 1);
            assert!(fixture.load(true).is_err());
            fixture.string("SessionType", "sbfd-initiator");
            fixture.string("RemoteDiscriminator", "99");
            assert!(fixture.load(true).is_err());
            fixture.dword("RemoteDiscriminator", 0);
            assert!(fixture.load(true).unwrap().validate().is_err());
            fixture.dword("RemoteDiscriminator", 99);
            fixture.string("AllowedPeers", "192.0.2.3,invalid");
            assert!(fixture.load(true).is_err());
            fixture.dword("AllowedPeers", 1);
            assert!(fixture.load(true).is_err());
            fixture.remove("AllowedPeers");
            fixture.dword("SbfdAdminDown", 2);
            assert!(fixture.load(true).is_err());
            fixture.string("SessionType", "sbfd-reflector");
            fixture.remove("RemoteDiscriminator");
            fixture.remove("SbfdAdminDown");
            assert!(fixture.load(true).is_err());
        }

        #[test]
        fn native_registry_live_settings_are_validated_without_reloading_identity() {
            let fixture = Fixture::new();
            fixture.string("Local", "192.0.2.2");
            fixture.string("SessionType", "sbfd-reflector");
            fixture.dword("Discriminator", 99);
            let options = fixture.load(true).unwrap();
            let registry = Registry::new(fixture.key, "");
            fixture.dword("MinTxUs", 250_000);
            fixture.dword("MinRxUs", 500_000);
            fixture.dword("DetectMult", 5);
            fixture.dword("SbfdAdminDown", 1);
            fixture.string("Local", "not-a-live-setting");
            assert_eq!(
                registry.sbfd_settings(&options).unwrap(),
                (Timing::new(250_000, 500_000, 5).unwrap(), true)
            );
            fixture.dword("DetectMult", 256);
            assert!(registry.sbfd_settings(&options).is_err());
            fixture.dword("DetectMult", 5);
            fixture.dword("MinRxUs", 0);
            assert!(registry.sbfd_settings(&options).is_err());
        }

        #[test]
        fn settings_watch_signals_each_value_change_once_and_rearms() {
            let fixture = Fixture::new();
            let watch = SettingsWatch::open_at(fixture.key, "").unwrap();
            assert!(!watch.take_change().unwrap());
            let signalled = |watch: &SettingsWatch| {
                // SAFETY: the borrowed event stays alive for this bounded wait.
                let result = unsafe { WaitForSingleObject(watch.event().as_raw_handle(), 2000) };
                result == WAIT_OBJECT_0
            };
            for value in [250_000, 500_000] {
                fixture.dword("MinTxUs", value);
                assert!(signalled(&watch), "value change was not signalled");
                assert!(watch.take_change().unwrap());
                assert!(!watch.take_change().unwrap(), "a change was reported twice");
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
            assert_eq!(options.log_file_path.to_str(), Some(DEFAULT_LOG_FILE_PATH));
            assert!(!options.log_to_file && options.bgp_peer_name.is_none());
            assert!(Registry::new(fixture.key, "")
                .string("LogFilePath")
                .unwrap()
                .is_none());
            assert!(Registry::new(fixture.key, "")
                .dword("LogToFile")
                .unwrap()
                .is_none());
            assert!(options.validate().is_ok());
        }

        #[test]
        fn native_registry_reads_log_path_independently_of_file_logging_flag() {
            let fixture = Fixture::new();
            fixture.addresses();
            fixture.string("LogFilePath", r"C:\BFD\custom.log");
            for enabled in [0, 1] {
                fixture.dword("LogToFile", enabled);
                let options = fixture.load(false).unwrap();
                assert_eq!(options.log_to_file, enabled == 1);
                assert_eq!(options.log_file_path.to_str(), Some(r"C:\BFD\custom.log"));
            }
            fixture.remove("LogFilePath");
            let options = fixture.load(false).unwrap();
            assert!(options.log_to_file);
            assert_eq!(options.log_file_path.to_str(), Some(DEFAULT_LOG_FILE_PATH));
        }

        #[test]
        fn native_registry_reads_and_validates_shutdown_announcement_limit() {
            let fixture = Fixture::new();
            fixture.addresses();
            fixture.dword("Multihop", 1);
            assert_eq!(
                fixture.load(false).unwrap().max_shutdown_announce_ms,
                30_000
            );
            for value in [1, 60_000] {
                fixture.dword("MaxShutdownAnnounceMs", value);
                let mut options = fixture.load(false).unwrap();
                assert_eq!(options.max_shutdown_announce_ms, value);
                options.validate().unwrap();
            }
            for value in [0, 60_001, u32::MAX] {
                fixture.dword("MaxShutdownAnnounceMs", value);
                assert_eq!(
                    fixture.load(false).unwrap().validate().err().unwrap(),
                    crate::error::ConfigError::ShutdownAnnouncementLimit
                );
            }
        }

        #[test]
        fn native_registry_multihop_flag_selects_transport_and_ignores_legacy_mode() {
            let fixture = Fixture::new();
            fixture.addresses();
            fixture.dword("InterfaceIndex", 12);

            // An absent flag selects single-hop, even if an obsolete selector
            // from an earlier installation is still present.
            fixture.string("Mode", "multihop");
            let options = fixture.load(false).unwrap();
            assert!(!options.multihop);
            assert_eq!(options.mode, Mode::SingleHop);
            assert_eq!(options.mode.port(), 3784);

            for legacy_mode in ["single-hop", "multihop", "invalid"] {
                fixture.string("Mode", legacy_mode);
                for (value, expected) in [(0, Mode::SingleHop), (1, Mode::Multihop)] {
                    fixture.dword("Multihop", value);
                    let mut options = fixture.load(false).unwrap();
                    assert_eq!(options.multihop, value == 1);
                    assert_eq!(options.mode, expected);
                    options.validate().unwrap();
                    assert_eq!(options.mode, expected);
                    assert_eq!(options.mode.port(), if value == 0 { 3784 } else { 4784 });
                }
            }

            // Removed values are not read or type-checked.
            fixture.dword("Mode", 1);
            fixture.dword("Multihop", 0);
            assert_eq!(fixture.load(false).unwrap().mode, Mode::SingleHop);
        }

        #[test]
        fn native_registry_loads_all_types_including_unicode_and_dword_limits() {
            let fixture = Fixture::new();
            for (name, value) in [
                ("Local", "2001:db8::1"),
                ("Peer", "2001:db8::2"),
                ("Auth", "meticulous-sha1"),
                ("AuthKeyHex", "00fe12"),
                ("BgpPeerName", "Péér 🦀"),
                ("BgpRoutingDomain", "Domaine 🦀"),
                ("LogFilePath", r"C:\BFD\résultats.log"),
            ] {
                fixture.string(name, value);
            }
            for (name, value) in [
                ("Multihop", 1),
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
                ("LogToFile", 1),
            ] {
                fixture.dword(name, value);
            }
            let mut options = fixture.load(false).unwrap();
            assert!(!options.console && options.passive && options.verbose && options.log_to_file);
            assert!(options.multihop);
            assert_eq!(options.mode, Mode::Multihop);
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
                options.log_file_path.to_str(),
                Some(r"C:\BFD\résultats.log")
            );
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
            for name in [
                "InterfaceIndex",
                "DetectMult",
                "Passive",
                "Multihop",
                "LogToFile",
            ] {
                fixture.string(name, "12");
                let error = fixture.load(false).err().unwrap().to_string();
                assert!(
                    error.contains(name) && error.contains("REG_DWORD"),
                    "{error}"
                );
                fixture.remove(name);
            }
            for name in ["Auth", "BgpPeerName", "LogFilePath", "AuthKey"] {
                fixture.dword(name, 1);
                let error = fixture.load(false).err().unwrap().to_string();
                assert!(error.contains(name) && error.contains("REG_SZ"), "{error}");
                fixture.remove(name);
            }
            fixture.set("LogFilePath", REG_EXPAND_SZ, &[0, 0]);
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
        fn native_registry_rejects_overflow_invalid_booleans_and_auth_types() {
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
                ("LogToFile", 2),
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
            fixture.dword("Multihop", 1);
            let mut options = fixture.load(false).unwrap();
            assert!(options.validate().is_ok());
            assert_eq!(options.mode, Mode::Multihop);
            fixture.string("Auth", "invalid-auth-hidden-key");
            let error = fixture.load(false).err().unwrap().to_string();
            assert!(error.contains("Auth") && !error.contains("hidden-key"));
        }
    }
}
