//! Verifies SCM-issued privileges before either service accepts work.
// Read-only token queries require the Windows FFI boundary.
#![allow(unsafe_code)]

use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, LUID},
    Security::{
        GetTokenInformation, LookupPrivilegeNameW, TokenPrivileges, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
    },
};

/// SCM's explicit minimum for both service processes.
pub(crate) const REQUIRED_PRIVILEGE: &str = "SeChangeNotifyPrivilege";

#[cfg(test)]
mod fixture;
#[cfg(test)]
pub(crate) use fixture::drop_rpc_privileges;

/// Verifies that SCM issued exactly the expected enabled privilege.
/// Does not modify the token. Run before configured resource or network access.
///
/// # Errors
/// Returns token query errors or PermissionDenied for a missing, disabled, or
/// unexpected privilege, including an unexpected disabled privilege.
pub fn verify_service_privileges() -> io::Result<()> {
    require_service_privileges(&crate::service_identity::process_token()?)
}

fn require_service_privileges(token: &OwnedHandle) -> io::Result<()> {
    validate_privileges(&privileges(token)?)
}

fn validate_privileges(entries: &[LUID_AND_ATTRIBUTES]) -> io::Result<()> {
    if let [entry] = entries {
        if privilege_name(&entry.Luid)? == REQUIRED_PRIVILEGE
            && entry.Attributes & SE_PRIVILEGE_ENABLED != 0
        {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "service token must contain only enabled SeChangeNotifyPrivilege; repair the SCM RequiredPrivileges policy and restart the service",
    ))
}

fn privileges(token: &OwnedHandle) -> io::Result<Vec<LUID_AND_ATTRIBUTES>> {
    let mut needed = 0;
    // SAFETY: a null buffer with zero length only queries the required size.
    let sized = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if sized == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(i32::from_ne_bytes(ERROR_INSUFFICIENT_BUFFER.to_ne_bytes()))
        {
            return Err(error);
        }
    }
    let length = usize::try_from(needed).map_err(io::Error::other)?;
    let offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    if !(offset..=65_536).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid token privilege buffer size",
        ));
    }
    let mut storage = vec![0u32; length.div_ceil(size_of::<u32>())];
    // SAFETY: storage is writable for at least `needed` bytes and suitably aligned.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let returned = usize::try_from(needed).map_err(io::Error::other)?;
    if returned < offset || returned > length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid token privilege result size",
        ));
    }
    let header = storage.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: Windows initialized a TOKEN_PRIVILEGES header in this storage.
    let count = usize::try_from(unsafe { (*header).PrivilegeCount }).map_err(io::Error::other)?;
    if count > (returned - offset) / size_of::<LUID_AND_ATTRIBUTES>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token privilege count exceeds its buffer",
        ));
    }
    // SAFETY: the bounds check above keeps every initialized entry in storage.
    let entries = unsafe {
        std::slice::from_raw_parts(
            storage
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    Ok(entries.to_vec())
}

fn privilege_name(luid: &LUID) -> io::Result<String> {
    let mut name = [0u16; 64];
    let mut length = u32::try_from(name.len()).map_err(io::Error::other)?;
    // SAFETY: the LUID is valid and the output holds `length` UTF-16 units.
    if unsafe { LookupPrivilegeNameW(ptr::null(), luid, name.as_mut_ptr(), &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    let value = name.get(..length).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid privilege name length")
    })?;
    String::from_utf16(value).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Security::TOKEN_QUERY,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    #[test]
    #[ignore = "requires the installed broker on a disposable MSI test runner"]
    fn installed_broker_token_retains_only_change_notify() {
        let token = installed_service_token(crate::bgp::ipc::BROKER_NAME);
        crate::service_identity::require_identity(
            token.as_raw_handle(),
            crate::bgp::ipc::BROKER_SID,
            "S-1-5-18",
        )
        .unwrap();
        require_service_privileges(&token).unwrap();
    }

    #[test]
    #[ignore = "requires the installed BFD service on a disposable MSI test runner"]
    fn installed_bfd_token_is_restricted_and_retains_only_change_notify() {
        let token = installed_service_token(crate::config::SERVICE_NAME);
        crate::service_identity::require_restricted_bfd_token(token.as_raw_handle()).unwrap();
        require_service_privileges(&token).unwrap();
    }

    fn installed_service_token(name: &str) -> OwnedHandle {
        use windows_service::{
            service::{ServiceAccess, ServiceState},
            service_manager::{ServiceManager, ServiceManagerAccess},
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let hosted_runner = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted");
        let disposable_vm = std::env::var("BFD_TEST_DISPOSABLE_VM").as_deref() == Ok("1")
            && std::env::var("COMPUTERNAME").as_deref() == Ok("BFD-WS2025");
        assert!(
            hosted_runner || disposable_vm,
            "installed token tests require a hosted runner or the explicit disposable BFD-WS2025 VM"
        );
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let service = manager
            .open_service(name, ServiceAccess::QUERY_STATUS)
            .unwrap();
        let status = service.query_status().unwrap();
        assert_eq!(status.current_state, ServiceState::Running);
        let service_pid = status.process_id.unwrap();
        // SAFETY: the SCM-reported process ID is used only to open a read-only handle.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, service_pid) };
        assert!(!raw.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: OpenProcess returned a uniquely owned live process handle.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut raw_token = ptr::null_mut();
        // SAFETY: the process remains live and the token output is writable.
        let opened =
            unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw_token) };
        assert_ne!(opened, 0);
        // SAFETY: the successful open transfers a uniquely owned token handle.
        unsafe { OwnedHandle::from_raw_handle(raw_token) }
    }

    #[test]
    fn validation_rejects_missing_disabled_and_extra_privileges_without_mutation() {
        use windows_sys::{w, Win32::Security::LookupPrivilegeValueW};
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        // SAFETY: fixed terminated name and writable LUID output.
        let found =
            unsafe { LookupPrivilegeValueW(ptr::null(), w!("SeChangeNotifyPrivilege"), &mut luid) };
        assert_ne!(found, 0);
        let enabled = LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        let disabled = LUID_AND_ATTRIBUTES {
            Attributes: 0,
            ..enabled
        };
        let mut other_luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        // SAFETY: fixed terminated name and writable LUID output.
        let found = unsafe {
            LookupPrivilegeValueW(ptr::null(), w!("SeCreateGlobalPrivilege"), &mut other_luid)
        };
        assert_ne!(found, 0);
        let other = LUID_AND_ATTRIBUTES {
            Luid: other_luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        assert!(validate_privileges(&[enabled]).is_ok());
        for entries in [
            vec![],
            vec![disabled],
            vec![other],
            vec![enabled, enabled],
            vec![enabled, disabled],
            vec![enabled, other],
            vec![
                enabled,
                LUID_AND_ATTRIBUTES {
                    Attributes: 0,
                    ..other
                },
            ],
        ] {
            assert_eq!(
                validate_privileges(&entries).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let token = crate::service_identity::process_token().unwrap();
        let before = privileges(&token).unwrap();
        let _ = require_service_privileges(&token);
        let after = privileges(&token).unwrap();
        let values = |entries: &[LUID_AND_ATTRIBUTES]| {
            entries
                .iter()
                .map(|e| (e.Luid.LowPart, e.Luid.HighPart, e.Attributes))
                .collect::<Vec<_>>()
        };
        assert_eq!(values(&before), values(&after));
    }

    #[cfg(not(miri))]
    #[test]
    fn broker_retains_only_change_notify_and_can_read_provider_schema() {
        const CHILD: &str = "BFD_TEST_BROKER_PRIVILEGES_CHILD";
        if std::env::var_os(CHILD).is_some() {
            drop_rpc_privileges().unwrap();
            let mut raw = ptr::null_mut();
            // SAFETY: valid process pseudo-handle and writable output.
            let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
            assert_ne!(opened, 0);
            // SAFETY: the successful open transfers a uniquely owned handle.
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let names: Vec<_> = privileges(&token)
                .unwrap()
                .iter()
                .map(|entry| privilege_name(&entry.Luid).unwrap())
                .collect();
            assert_eq!(names, ["SeChangeNotifyPrivilege"]);
            verify_service_privileges().unwrap();
            crate::bgp_broker::test_rpc_with_provider(|schema| schema())
                .unwrap()
                .unwrap();
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "runtime::privileges::tests::broker_retains_only_change_notify_and_can_read_provider_schema", "--nocapture"])
            .env(CHILD, "1").status().unwrap();
        assert!(status.success(), "{status}");
    }

    #[cfg(not(miri))]
    #[test]
    fn unused_privileges_are_removed_permanently_in_an_isolated_process() {
        use std::process::Command;
        const CHILD: &str = "BFD_TEST_DROP_PRIVILEGES_CHILD";
        if std::env::var_os(CHILD).is_some() {
            drop_rpc_privileges().unwrap();
            let token = {
                let mut raw = ptr::null_mut();
                // SAFETY: valid pseudo-handle and writable output.
                let opened =
                    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
                assert_ne!(opened, 0);
                // SAFETY: successful open transfers ownership.
                unsafe { OwnedHandle::from_raw_handle(raw) }
            };
            require_service_privileges(&token).unwrap();
            verify_service_privileges().unwrap();
            // Sockets and their events still work without the removed privileges.
            let mut options = crate::config::Options::new(
                "127.0.0.244".parse().unwrap(),
                "127.0.0.245".parse().unwrap(),
            );
            options.multihop = true;
            crate::transport::Transport::open(&options).unwrap();
            return;
        }
        // Privilege removal cannot be undone, so it runs in a child test process.
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::privileges::tests::unused_privileges_are_removed_permanently_in_an_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "{status}");
    }
}
