//! Fixed-target deferred MSI provisioning, with a protected rollback snapshot.
#![allow(unsafe_code)]
use crate::bgp::ipc::BROKER_NAME;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    mem::size_of,
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
const SNAPSHOT_MAGIC: &[u8; 4] = b"BSI3";
/// Account, SID type, delayed start, recovery flag, and little-endian preshutdown timeout.
const RECORD_LEN: usize = 8;
/// Covers the maximum 60-second announcement, 60-second cleanup, and final logging.
const BFD_PRESHUTDOWN_MS: u32 = 125_000;

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

fn set(service: &Service, policy: Policy) -> io::Result<()> {
    let account: Vec<u16> = policy
        .account
        .name()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: live service handle has CHANGE_CONFIG; terminated account name;
    // all other configuration fields remain unchanged. Built-in accounts have no password.
    if unsafe {
        ChangeServiceConfigW(
            service.raw_handle(),
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
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

fn decode(bytes: &[u8]) -> io::Result<[Option<Policy>; 2]> {
    if bytes.len() != SNAPSHOT_MAGIC.len() + RECORD_LEN * NAMES.len()
        || &bytes[..SNAPSHOT_MAGIC.len()] != SNAPSHOT_MAGIC
    {
        return Err(io::Error::other("invalid service rollback snapshot"));
    }
    let mut values = [None, None];
    let (records, _) = bytes[SNAPSHOT_MAGIC.len()..].as_chunks::<RECORD_LEN>();
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
    Ok(values)
}

pub(super) fn prepare() -> io::Result<()> {
    let manager = manager()?;
    let mut bytes = Vec::with_capacity(SNAPSHOT_MAGIC.len() + RECORD_LEN * NAMES.len());
    bytes.extend_from_slice(SNAPSHOT_MAGIC);
    for name in NAMES {
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
    }
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

pub(super) fn configure() -> io::Result<()> {
    // A valid snapshot is required before changing either installed service.
    decode(&fs::read(snapshot_path()?)?)?;
    let manager = manager()?;
    // Both start after the boot-critical automatic services, when interface
    // addresses are more likely to exist. BFD recovery also covers nonzero exits.
    set(
        &open(&manager, NAMES[0])?,
        Policy {
            account: Account::LocalService,
            sid: ServiceSidType::Unrestricted,
            delayed: true,
            non_crash_recovery: true,
            preshutdown_ms: BFD_PRESHUTDOWN_MS,
        },
    )?;
    let broker = open(&manager, NAMES[1])?;
    set(
        &broker,
        Policy {
            account: Account::System,
            sid: ServiceSidType::Unrestricted,
            delayed: true,
            non_crash_recovery: false,
            preshutdown_ms: preshutdown_timeout(&broker)?,
        },
    )
}

pub(super) fn rollback() -> io::Result<()> {
    let path = snapshot_path()?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let manager = manager()?;
    // Restore every previously existing service, even if restoring the first fails.
    let mut failure = None;
    for (name, old) in NAMES.iter().zip(decode(&bytes)?) {
        if let Some(policy) = old {
            if let Err(error) = open(&manager, name).and_then(|service| set(&service, policy)) {
                failure = Some(error);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    fs::remove_file(path)
}

pub(super) fn commit() -> io::Result<()> {
    fs::remove_file(snapshot_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(decode(&encoded).unwrap(), [Some(system), Some(local)]);
        let mut absent = SNAPSHOT_MAGIC.to_vec();
        for _ in NAMES {
            absent.extend_from_slice(&[255, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(decode(&absent).unwrap(), [None, None]);
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
}
