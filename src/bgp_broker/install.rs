//! Fixed-target deferred MSI provisioning, with a protected rollback snapshot.
#![allow(unsafe_code)]
use crate::bgp::ipc::BROKER_NAME;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    ptr,
    time::Duration,
};
use windows_service::{
    service::{Service, ServiceAccess, ServiceSidType},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, QueryServiceConfig2W, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_NO_CHANGE,
    SERVICE_PRESHUTDOWN_INFO,
};

const NAMES: [&str; 2] = ["BfdWinService", BROKER_NAME];
const SNAPSHOT_MAGIC: &[u8; 4] = b"BSI4";
/// Account, SID type, delayed start, recovery flag, and little-endian preshutdown timeout.
const RECORD_LEN: usize = 8;
const DEPENDENCIES_OFFSET: usize = SNAPSHOT_MAGIC.len() + RECORD_LEN * NAMES.len();
const MAX_DEPENDENCY_UNITS: usize = 4096;
const MAX_SNAPSHOT_BYTES: usize = DEPENDENCIES_OFFSET
    + 4
    + MAX_DEPENDENCY_UNITS * 2
    + 4
    + NAMES.len() * (4 + privileges::MAX_UNITS * 2);
/// Covers the maximum 60-second announcement, 60-second cleanup, and final logging.
const BFD_PRESHUTDOWN_MS: u32 = 125_000;

mod privileges;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Account {
    System,
    LocalService,
    NetworkService,
}
impl Account {
    fn name(self) -> &'static str {
        match self {
            Self::System => "LocalSystem",
            Self::LocalService => "NT AUTHORITY\\LocalService",
            Self::NetworkService => "NT AUTHORITY\\NetworkService",
        }
    }
    fn parse(value: &str) -> io::Result<Self> {
        if value.eq_ignore_ascii_case("LocalSystem")
            || value.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM")
        {
            Ok(Self::System)
        } else if value.eq_ignore_ascii_case("NT AUTHORITY\\LocalService") {
            Ok(Self::LocalService)
        } else if value.eq_ignore_ascii_case("NT AUTHORITY\\NetworkService") {
            Ok(Self::NetworkService)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "service migration supports only built-in service accounts",
            ))
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::System => 0,
            Self::LocalService => 1,
            Self::NetworkService => 2,
        }
    }
}

/// The service settings this installer changes and restores on rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Policy {
    account: Account,
    sid: ServiceSidType,
    /// Start automatic services after other automatic services, plus a delay.
    delayed: bool,
    /// Run failure actions when the service stops with a nonzero exit code.
    non_crash_recovery: bool,
    preshutdown_ms: u32,
}

impl Policy {
    fn encode(self) -> [u8; RECORD_LEN] {
        let mut record = [
            self.account.byte(),
            match self.sid {
                ServiceSidType::None => 0,
                ServiceSidType::Unrestricted => 1,
                ServiceSidType::Restricted => 3,
            },
            u8::from(self.delayed),
            u8::from(self.non_crash_recovery),
            0,
            0,
            0,
            0,
        ];
        record[4..].copy_from_slice(&self.preshutdown_ms.to_le_bytes());
        record
    }
}

fn snapshot_path() -> io::Result<PathBuf> {
    // This location is fixed relative to the MSI-installed, administrator-protected
    // binary. No installer command accepts a caller-provided path or service name.
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| io::Error::other("missing broker directory"))?;
    Ok(parent.join("service-policy.rollback"))
}

fn manager() -> io::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)
}
fn open(manager: &ServiceManager, name: &str) -> io::Result<Service> {
    manager
        .open_service(
            name,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG,
        )
        .map_err(io::Error::other)
}

fn delayed_auto_start(service: &Service) -> io::Result<bool> {
    let mut info = SERVICE_DELAYED_AUTO_START_INFO {
        fDelayedAutostart: 0,
    };
    let mut needed = 0;
    // SAFETY: live service handle with QUERY_CONFIG; the output is a correctly
    // sized, aligned, writable SERVICE_DELAYED_AUTO_START_INFO.
    if unsafe {
        QueryServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            (&mut info as *mut SERVICE_DELAYED_AUTO_START_INFO).cast(),
            u32::try_from(size_of::<SERVICE_DELAYED_AUTO_START_INFO>())
                .map_err(io::Error::other)?,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.fDelayedAutostart != 0)
}

fn preshutdown_timeout(service: &Service) -> io::Result<u32> {
    let mut info = SERVICE_PRESHUTDOWN_INFO {
        dwPreshutdownTimeout: 0,
    };
    let mut needed = 0;
    // SAFETY: QUERY_CONFIG handle and aligned, correctly sized output storage.
    if unsafe {
        QueryServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_PRESHUTDOWN_INFO,
            (&mut info as *mut SERVICE_PRESHUTDOWN_INFO).cast(),
            size_of::<SERVICE_PRESHUTDOWN_INFO>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.dwPreshutdownTimeout)
}

fn query(service: &Service) -> io::Result<Policy> {
    let config = service.query_config().map_err(io::Error::other)?;
    let account = config
        .account_name
        .ok_or_else(|| io::Error::other("missing service account"))?;
    let account = account
        .to_str()
        .ok_or_else(|| io::Error::other("invalid service account"))?;
    Ok(Policy {
        account: Account::parse(account)?,
        sid: service
            .get_config_service_sid_info()
            .map_err(io::Error::other)?,
        preshutdown_ms: preshutdown_timeout(service)?,
        delayed: delayed_auto_start(service)?,
        non_crash_recovery: service
            .get_failure_actions_on_non_crash_failures()
            .map_err(io::Error::other)?,
    })
}

fn set(service: &Service, policy: Policy, dependencies: Option<&[u16]>) -> io::Result<()> {
    if let Some(dependencies) = dependencies {
        validate_dependencies(dependencies)?;
    }
    let account: Vec<u16> = policy
        .account
        .name()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: live service handle has CHANGE_CONFIG; terminated account name;
    // optional dependencies are validated MULTI_SZ storage alive through the call.
    // Other configuration fields remain unchanged; built-in accounts have no password.
    if unsafe {
        ChangeServiceConfigW(
            service.raw_handle(),
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            dependencies.map_or(ptr::null(), <[u16]>::as_ptr),
            account.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    service
        .set_config_service_sid_info(policy.sid)
        .map_err(io::Error::other)?;
    service
        .set_delayed_auto_start(policy.delayed)
        .map_err(io::Error::other)?;
    service
        .set_failure_actions_on_non_crash_failures(policy.non_crash_recovery)
        .map_err(io::Error::other)?;
    service
        .set_preshutdown_timeout(Duration::from_millis(u64::from(policy.preshutdown_ms)))
        .map_err(io::Error::other)
}

fn validate_dependencies(units: &[u16]) -> io::Result<()> {
    if !(2..=MAX_DEPENDENCY_UNITS).contains(&units.len()) || !units.ends_with(&[0, 0]) {
        return Err(io::Error::other("invalid rollback dependency list"));
    }
    if units == [0, 0] {
        return Ok(());
    }
    let mut start = 0;
    for (index, unit) in units[..units.len() - 1].iter().enumerate() {
        if *unit == 0 {
            if index == start {
                return Err(io::Error::other("empty rollback dependency name"));
            }
            start = index + 1;
        }
    }
    Ok(())
}

fn dependencies(service: &Service) -> io::Result<Vec<u16>> {
    let config = service.query_config().map_err(io::Error::other)?;
    let mut units = Vec::new();
    for dependency in config.dependencies {
        for unit in dependency.to_system_identifier().encode_wide().chain([0]) {
            if units.len() >= MAX_DEPENDENCY_UNITS - 1 {
                return Err(io::Error::other("service dependency list is too large"));
            }
            units.push(unit);
        }
    }
    if units.is_empty() {
        units.push(0);
    }
    units.push(0);
    validate_dependencies(&units)?;
    Ok(units)
}

fn append_dependencies(bytes: &mut Vec<u8>, units: &[u16]) -> io::Result<()> {
    validate_dependencies(units)?;
    let count = u32::try_from(units.len()).map_err(io::Error::other)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    policies: [Option<Policy>; 2],
    bfd_dependencies: Vec<u16>,
    // Older snapshots have no privilege footer and can still undo deferred
    // account/SID changes. Commit requires the new exact-policy snapshot.
    privileges: Option<[privileges::Policy; 2]>,
}

fn read_snapshot() -> io::Result<Snapshot> {
    let mut bytes = Vec::new();
    fs::File::open(snapshot_path()?)?
        .take(u64::try_from(MAX_SNAPSHOT_BYTES + 1).map_err(io::Error::other)?)
        .read_to_end(&mut bytes)?;
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> io::Result<Snapshot> {
    if !(DEPENDENCIES_OFFSET + 4..=MAX_SNAPSHOT_BYTES).contains(&bytes.len())
        || &bytes[..SNAPSHOT_MAGIC.len()] != SNAPSHOT_MAGIC
    {
        return Err(io::Error::other("invalid service rollback snapshot"));
    }
    let mut values = [None, None];
    let (records, _) = bytes[SNAPSHOT_MAGIC.len()..DEPENDENCIES_OFFSET].as_chunks::<RECORD_LEN>();
    for (value, record) in values.iter_mut().zip(records) {
        let account = match record[0] {
            0 => Account::System,
            1 => Account::LocalService,
            2 => Account::NetworkService,
            255 if record[1..] == [0; RECORD_LEN - 1] => continue,
            _ => return Err(io::Error::other("invalid rollback account")),
        };
        let sid = match record[1] {
            0 => ServiceSidType::None,
            1 => ServiceSidType::Unrestricted,
            3 => ServiceSidType::Restricted,
            _ => return Err(io::Error::other("invalid rollback SID type")),
        };
        let flag = |byte: u8| match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(io::Error::other("invalid rollback service flag")),
        };
        *value = Some(Policy {
            account,
            sid,
            delayed: flag(record[2])?,
            non_crash_recovery: flag(record[3])?,
            preshutdown_ms: u32::from_le_bytes(record[4..].try_into().map_err(io::Error::other)?),
        });
    }
    let count = u32::from_le_bytes(
        bytes[DEPENDENCIES_OFFSET..DEPENDENCIES_OFFSET + 4]
            .try_into()
            .map_err(io::Error::other)?,
    );
    let count = usize::try_from(count).map_err(io::Error::other)?;
    if count > MAX_DEPENDENCY_UNITS || count * 2 > bytes.len() - DEPENDENCIES_OFFSET - 4 {
        return Err(io::Error::other("invalid rollback dependency length"));
    }
    let end = DEPENDENCIES_OFFSET + 4 + count * 2;
    let (words, _) = bytes[DEPENDENCIES_OFFSET + 4..end].as_chunks::<2>();
    let bfd_dependencies: Vec<u16> = words.iter().map(|word| u16::from_le_bytes(*word)).collect();
    validate_dependencies(&bfd_dependencies)?;
    if values[0].is_none() && bfd_dependencies != [0, 0] {
        return Err(io::Error::other(
            "absent BFD service has rollback dependencies",
        ));
    }
    Ok(Snapshot {
        policies: values,
        bfd_dependencies,
        privileges: decode_privileges(&bytes[end..])?,
    })
}

fn decode_privileges(mut bytes: &[u8]) -> io::Result<Option<[privileges::Policy; 2]>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if !bytes.starts_with(b"PRV1") {
        return Err(io::Error::other("invalid rollback privilege footer"));
    }
    bytes = &bytes[4..];
    let mut policies = [None, None];
    for policy in &mut policies {
        let (length, rest) = bytes
            .split_at_checked(4)
            .ok_or_else(|| io::Error::other("truncated rollback privileges"))?;
        bytes = rest;
        let count = u32::from_le_bytes(length.try_into().map_err(io::Error::other)?);
        if count == u32::MAX {
            continue;
        }
        let count = usize::try_from(count).map_err(io::Error::other)?;
        if count > privileges::MAX_UNITS {
            return Err(io::Error::other("oversized rollback privileges"));
        }
        let (data, rest) = bytes
            .split_at_checked(count * 2)
            .ok_or_else(|| io::Error::other("truncated rollback privileges"))?;
        bytes = rest;
        let (words, _) = data.as_chunks::<2>();
        let units: Vec<u16> = words.iter().map(|word| u16::from_le_bytes(*word)).collect();
        privileges::validate(&units)?;
        *policy = Some(units);
    }
    if !bytes.is_empty() {
        return Err(io::Error::other("trailing rollback privilege data"));
    }
    Ok(Some(policies))
}

fn append_privileges(bytes: &mut Vec<u8>, policies: &[privileges::Policy; 2]) -> io::Result<()> {
    bytes.extend_from_slice(b"PRV1");
    for policy in policies {
        match policy {
            None => bytes.extend_from_slice(&u32::MAX.to_le_bytes()),
            Some(units) => {
                privileges::validate(units)?;
                bytes.extend_from_slice(
                    &u32::try_from(units.len())
                        .map_err(io::Error::other)?
                        .to_le_bytes(),
                );
                for unit in units {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
            }
        }
    }
    Ok(())
}

pub(super) fn prepare() -> io::Result<()> {
    let manager = manager()?;
    let mut bytes = Vec::with_capacity(SNAPSHOT_MAGIC.len() + RECORD_LEN * NAMES.len());
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    let mut bfd_dependencies = vec![0, 0];
    let mut privilege_policies = [None, None];
    for (index, name) in NAMES.iter().copied().enumerate() {
        let service = match manager.open_service(name, ServiceAccess::QUERY_CONFIG) {
            Ok(service) => service,
            Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
                let mut absent = [0; RECORD_LEN];
                absent[0] = 255;
                bytes.extend_from_slice(&absent);
                continue;
            }
            Err(error) => return Err(io::Error::other(error)),
        };
        bytes.extend_from_slice(&query(&service)?.encode());
        privilege_policies[index] = privileges::query(name)?;
        if name == NAMES[0] {
            bfd_dependencies = dependencies(&service)?;
        }
    }
    append_dependencies(&mut bytes, &bfd_dependencies)?;
    append_privileges(&mut bytes, &privilege_policies)?;
    let path = snapshot_path()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    if result.is_err() {
        drop(file);
        // Remove only the snapshot this call created; a partial snapshot must not
        // obstruct rollback or the next attempt before any service was changed.
        let _ = fs::remove_file(path);
    }
    result
}

fn bfd_policy() -> Policy {
    Policy {
        account: Account::LocalService,
        sid: ServiceSidType::Restricted,
        delayed: true,
        non_crash_recovery: true,
        preshutdown_ms: BFD_PRESHUTDOWN_MS,
    }
}

fn broker_policy(preshutdown_ms: u32) -> Policy {
    Policy {
        account: Account::System,
        sid: ServiceSidType::Unrestricted,
        delayed: true,
        non_crash_recovery: false,
        preshutdown_ms,
    }
}

pub(super) fn configure() -> io::Result<()> {
    // A valid snapshot is required before changing either installed service.
    read_snapshot()?;
    let manager = manager()?;
    // RequiredPrivileges remains untouched until commit. That preserves absent,
    // explicit-empty, and explicit-list policies on every ordinary rollback.
    // Both start after the boot-critical automatic services, when interface
    // addresses are more likely to exist. BFD recovery also covers nonzero exits.
    // Explicit empty MULTI_SZ also clears the old broker dependency on repair.
    set(&open(&manager, NAMES[0])?, bfd_policy(), Some(&[0, 0]))?;
    let broker = open(&manager, NAMES[1])?;
    set(&broker, broker_policy(preshutdown_timeout(&broker)?), None)
}

pub(super) fn rollback() -> io::Result<()> {
    let path = snapshot_path()?;
    let snapshot = match read_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let manager = manager()?;
    // Restore every previously existing service, even if restoring the first fails.
    let mut failure = None;
    for (index, (name, old)) in NAMES.iter().zip(snapshot.policies).enumerate() {
        if let Some(policy) = old {
            let dependencies = if *name == NAMES[0] {
                Some(snapshot.bfd_dependencies.as_slice())
            } else {
                None
            };
            if let Err(error) =
                open(&manager, name).and_then(|service| set(&service, policy, dependencies))
            {
                failure = Some(error);
            }
            if let Some(policies) = &snapshot.privileges {
                if let Err(error) = open(&manager, name)
                    .and_then(|service| privileges::restore(&service, name, &policies[index]))
                {
                    failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    fs::remove_file(path)
}

pub(super) fn commit() -> io::Result<()> {
    let path = snapshot_path()?;
    if read_snapshot()?.privileges.is_none() {
        return Err(io::Error::other(
            "commit requires an exact service privilege snapshot",
        ));
    }
    let manager = manager()?;
    // Open both handles before changing either policy.
    let bfd = open(&manager, NAMES[0])?;
    let broker = open(&manager, NAMES[1])?;
    // MSI stops both services and never starts them. Commit is the final policy
    // mutation before the next SCM launch. A failure after either mutation
    // retains the exact prior lists for MSI rollback, including absent policies.
    privileges::commit_with(
        || {
            privileges::set_minimum(&bfd)?;
            privileges::set_minimum(&broker)
        },
        || fs::remove_file(&path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn privilege_snapshot_preserves_absent_empty_and_ordered_lists() {
        let explicit = "SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0\0"
            .encode_utf16()
            .collect();
        for policies in [
            [None, Some(explicit)],
            [Some(vec![]), Some(vec![0, 0])],
            [None, None],
        ] {
            let mut bytes = Vec::new();
            append_privileges(&mut bytes, &policies).unwrap();
            assert_eq!(decode_privileges(&bytes).unwrap(), Some(policies));
        }
        assert_eq!(decode_privileges(&[]).unwrap(), None);
    }

    #[test]
    fn privilege_snapshot_rejects_truncation_oversize_and_trailing_data() {
        let mut bytes = Vec::new();
        append_privileges(&mut bytes, &[None, Some(vec![0, 0])]).unwrap();
        for length in 1..bytes.len() {
            assert!(decode_privileges(&bytes[..length]).is_err());
        }
        bytes.push(0);
        assert!(decode_privileges(&bytes).is_err());
        let mut oversized = b"PRV1".to_vec();
        oversized.extend_from_slice(&(privileges::MAX_UNITS as u32 + 1).to_le_bytes());
        assert!(decode_privileges(&oversized).is_err());
        let mut invalid = Vec::new();
        append_privileges(&mut invalid, &[Some(vec![0, 0]), None]).unwrap();
        invalid[8..12].copy_from_slice(&[1, 0, 1, 0]);
        assert!(decode_privileges(&invalid).is_err());
    }

    #[test]
    fn target_policies_restrict_only_bfd_and_keep_broker_system_authority() {
        let bfd = bfd_policy();
        assert_eq!(bfd.account, Account::LocalService);
        assert_eq!(bfd.sid, ServiceSidType::Restricted);
        assert!(bfd.delayed);
        assert!(bfd.non_crash_recovery);
        assert_eq!(bfd.preshutdown_ms, BFD_PRESHUTDOWN_MS);
        let broker = broker_policy(12_345);
        assert_eq!(broker.account, Account::System);
        assert_eq!(broker.sid, ServiceSidType::Unrestricted);
        assert!(broker.delayed);
        assert!(!broker.non_crash_recovery);
        assert_eq!(broker.preshutdown_ms, 12_345);
    }

    #[test]
    fn rollback_snapshot_restores_previously_restricted_service_sid_types() {
        let bfd = Policy {
            sid: ServiceSidType::Restricted,
            ..bfd_policy()
        };
        let broker = Policy {
            sid: ServiceSidType::Restricted,
            ..broker_policy(12_345)
        };
        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(&bfd.encode());
        bytes.extend_from_slice(&broker.encode());
        append_dependencies(&mut bytes, &[0, 0]).unwrap();
        assert_eq!(bytes[SNAPSHOT_MAGIC.len() + 1], 3);
        assert_eq!(bytes[SNAPSHOT_MAGIC.len() + RECORD_LEN + 1], 3);
        assert_eq!(decode(&bytes).unwrap().policies, [Some(bfd), Some(broker)]);
    }

    #[test]
    fn rollback_snapshot_rejects_unknown_accounts_sid_types_flags_and_extra_data() {
        let system = Policy {
            account: Account::System,
            sid: ServiceSidType::None,
            delayed: false,
            non_crash_recovery: false,
            preshutdown_ms: 10_000,
        };
        let local = Policy {
            account: Account::LocalService,
            sid: ServiceSidType::Unrestricted,
            delayed: true,
            non_crash_recovery: true,
            preshutdown_ms: BFD_PRESHUTDOWN_MS,
        };
        let mut encoded = SNAPSHOT_MAGIC.to_vec();
        encoded.extend_from_slice(&system.encode());
        encoded.extend_from_slice(&local.encode());
        append_dependencies(&mut encoded, &[0, 0]).unwrap();
        assert_eq!(
            decode(&encoded).unwrap().policies,
            [Some(system), Some(local)]
        );
        let mut absent = SNAPSHOT_MAGIC.to_vec();
        for _ in NAMES {
            absent.extend_from_slice(&[255, 0, 0, 0, 0, 0, 0, 0]);
        }
        append_dependencies(&mut absent, &[0, 0]).unwrap();
        assert_eq!(decode(&absent).unwrap().policies, [None, None]);
        for (index, value) in [(0, 3), (1, 2), (2, 2), (3, 2)] {
            let mut invalid = encoded.clone();
            invalid[SNAPSHOT_MAGIC.len() + index] = value;
            assert!(decode(&invalid).is_err());
        }
        for index in 1..RECORD_LEN {
            let mut invalid = absent.clone();
            invalid[SNAPSHOT_MAGIC.len() + index] = 1;
            assert!(decode(&invalid).is_err());
        }
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length]).is_err());
        }
        for bytes in [
            &b"BSI2\0\0\0\0\x01\x01\x01\x01"[..],
            &b"BSI1\0\0\0\0\0\0\0\0"[..],
            &b"BSI1\0\0\x01\x01"[..],
        ] {
            assert!(decode(bytes).is_err(), "{bytes:?}");
        }
        assert!(Account::parse("DOMAIN\\custom-service-user").is_err());
    }

    #[test]
    fn rollback_preserves_dependency_names_groups_order_and_utf16() {
        let dependencies: Vec<u16> = "RpcSs\0+Group\u{1f40e}\0BfdBgpBroker\0"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(&bfd_policy().encode());
        bytes.extend_from_slice(&broker_policy(10_000).encode());
        append_dependencies(&mut bytes, &dependencies).unwrap();
        assert_eq!(decode(&bytes).unwrap().bfd_dependencies, dependencies);
    }

    #[test]
    fn rollback_rejects_malformed_or_oversized_dependency_storage() {
        for invalid in [
            vec![],
            vec![0],
            vec![1, 0],
            vec![0, 0, 0],
            vec![1, 0, 0, 2, 0, 0],
        ] {
            assert!(validate_dependencies(&invalid).is_err(), "{invalid:?}");
        }
        let mut boundary = vec![1; MAX_DEPENDENCY_UNITS];
        boundary[MAX_DEPENDENCY_UNITS - 2..].fill(0);
        validate_dependencies(&boundary).unwrap();
        boundary.push(0);
        assert!(validate_dependencies(&boundary).is_err());

        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.extend_from_slice(&bfd_policy().encode());
        bytes.extend_from_slice(&broker_policy(10_000).encode());
        append_dependencies(&mut bytes, &[0, 0]).unwrap();
        for count in [0_u32, 1, 3, u32::MAX] {
            let mut invalid = bytes.clone();
            invalid[DEPENDENCIES_OFFSET..DEPENDENCIES_OFFSET + 4]
                .copy_from_slice(&count.to_le_bytes());
            assert!(decode(&invalid).is_err());
        }
        let mut odd = bytes.clone();
        odd.push(0);
        assert!(decode(&odd).is_err());
        let mut unterminated = bytes.clone();
        *unterminated.last_mut().unwrap() = 1;
        assert!(decode(&unterminated).is_err());
        let mut oversized = bytes;
        oversized.resize(MAX_SNAPSHOT_BYTES + 1, 0);
        assert!(decode(&oversized).is_err());
    }
}
