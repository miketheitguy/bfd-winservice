//! Fixed-target deferred MSI provisioning, with a protected rollback snapshot.
#![allow(unsafe_code)]
use crate::bgp::ipc::BROKER_NAME;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    ptr,
};
use windows_service::{
    service::{Service, ServiceAccess, ServiceSidType},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::System::Services::{ChangeServiceConfigW, SERVICE_NO_CHANGE};

const NAMES: [&str; 2] = ["BfdWinService", BROKER_NAME];

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

fn set(service: &Service, account: Account, sid: ServiceSidType) -> io::Result<()> {
    let account: Vec<u16> = account.name().encode_utf16().chain(Some(0)).collect();
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
        .set_config_service_sid_info(sid)
        .map_err(io::Error::other)
}

fn decode(bytes: &[u8]) -> io::Result<[Option<(Account, ServiceSidType)>; 2]> {
    if bytes.len() != 8 || &bytes[..4] != b"BSI1" {
        return Err(io::Error::other("invalid service rollback snapshot"));
    }
    let mut values = [None, None];
    for index in 0..2 {
        let account = match bytes[4 + index * 2] {
            0 => Account::System,
            1 => Account::LocalService,
            2 => Account::NetworkService,
            255 if bytes[5 + index * 2] == 0 => continue,
            _ => return Err(io::Error::other("invalid rollback account")),
        };
        let sid = match bytes[5 + index * 2] {
            0 => ServiceSidType::None,
            1 => ServiceSidType::Unrestricted,
            3 => ServiceSidType::Restricted,
            _ => return Err(io::Error::other("invalid rollback SID type")),
        };
        values[index] = Some((account, sid));
    }
    Ok(values)
}

pub(super) fn prepare() -> io::Result<()> {
    let manager = manager()?;
    let mut bytes = *b"BSI1\xff\0\xff\0";
    for (index, name) in NAMES.iter().enumerate() {
        let service = match manager.open_service(name, ServiceAccess::QUERY_CONFIG) {
            Ok(service) => service,
            Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
                continue
            }
            Err(error) => return Err(io::Error::other(error)),
        };
        let config = service.query_config().map_err(io::Error::other)?;
        let account = config
            .account_name
            .ok_or_else(|| io::Error::other("missing service account"))?;
        let account = account
            .to_str()
            .ok_or_else(|| io::Error::other("invalid service account"))?;
        bytes[4 + index * 2] = Account::parse(account)?.byte();
        bytes[5 + index * 2] = match service
            .get_config_service_sid_info()
            .map_err(io::Error::other)?
        {
            ServiceSidType::None => 0,
            ServiceSidType::Unrestricted => 1,
            ServiceSidType::Restricted => 3,
        };
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
    set(
        &open(&manager, NAMES[0])?,
        Account::LocalService,
        ServiceSidType::Unrestricted,
    )?;
    set(
        &open(&manager, NAMES[1])?,
        Account::System,
        ServiceSidType::Unrestricted,
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
        if let Some((account, sid)) = old {
            if let Err(error) = open(&manager, name).and_then(|service| set(&service, account, sid))
            {
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
    fn rollback_snapshot_rejects_unknown_accounts_sid_types_and_extra_data() {
        assert_eq!(
            decode(b"BSI1\0\0\x01\x01").unwrap(),
            [
                Some((Account::System, ServiceSidType::None)),
                Some((Account::LocalService, ServiceSidType::Unrestricted))
            ]
        );
        assert_eq!(decode(b"BSI1\xff\0\xff\0").unwrap(), [None, None]);
        for bytes in [
            &b"BSI1\x03\0\0\0"[..],
            &b"BSI1\0\x02\0\0"[..],
            &b"BSI1\xff\x01\0\0"[..],
            &b"BSI1\0\0\0\0\0"[..],
        ] {
            assert!(decode(bytes).is_err());
        }
        assert!(Account::parse("DOMAIN\\custom-service-user").is_err());
    }
}
