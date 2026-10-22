//! Permanently reduces each service's process privileges before accepting work.
// Token queries and privilege removal require the Windows FFI boundary.
#![allow(unsafe_code)]

use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, LUID},
    Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeNameW, TokenPrivileges,
        LUID_AND_ATTRIBUTES, SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        TOKEN_QUERY,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Directory traversal remains available. Local RPC, file logging, and Winsock
/// operate without any other token privilege.
const RETAINED: [&str; 1] = ["SeChangeNotifyPrivilege"];

/// Permanently removes every other privilege from the process token, including
/// SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege, before the service
/// accepts network traffic. Removed privileges cannot be restored.
/// Returns the removed privilege names; a second call returns none.
///
/// # Errors
/// Returns token query, privilege lookup, or adjustment errors.
pub fn drop_privileges() -> io::Result<Vec<String>> {
    drop_except(&RETAINED)
}

/// The SYSTEM broker needs directory traversal only. Provider operations run
/// under its own account; no client token or impersonation privilege is needed.
pub(crate) fn drop_broker_privileges() -> io::Result<Vec<String>> {
    drop_except(&["SeChangeNotifyPrivilege"])
}

/// Native test clients remove privileges independently of their parent process.
#[cfg(test)]
pub(crate) fn drop_rpc_privileges() -> io::Result<()> {
    drop_except(&["SeChangeNotifyPrivilege"]).map(|_| ())
}

fn drop_except(retained: &[&str]) -> io::Result<Vec<String>> {
    let mut raw = ptr::null_mut();
    // SAFETY: the process pseudo-handle is valid and the output is writable.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut raw,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transfers a uniquely owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut removed = Vec::new();
    let mut names = Vec::new();
    for entry in privileges(&token)? {
        let name = privilege_name(&entry.Luid)?;
        if !retained.contains(&name.as_str()) {
            removed.push(LUID_AND_ATTRIBUTES {
                Luid: entry.Luid,
                Attributes: SE_PRIVILEGE_REMOVED,
            });
            names.push(name);
        }
    }
    if removed.is_empty() {
        return Ok(names);
    }
    // TOKEN_PRIVILEGES ends in a one-element array; build the variable-length form
    // in u32 storage, which has the structure's four-byte alignment.
    let offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let bytes = offset + removed.len() * size_of::<LUID_AND_ATTRIBUTES>();
    let mut storage = vec![0u32; bytes.div_ceil(size_of::<u32>())];
    let header = storage.as_mut_ptr().cast::<TOKEN_PRIVILEGES>();
    let count = u32::try_from(removed.len()).map_err(io::Error::other)?;
    // SAFETY: storage is aligned for TOKEN_PRIVILEGES and holds the header plus
    // every entry; each write stays within the allocation.
    unsafe {
        (*header).PrivilegeCount = count;
        let entries = storage
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<LUID_AND_ATTRIBUTES>();
        for (index, entry) in removed.iter().enumerate() {
            entries.add(index).write(*entry);
        }
    }
    let length = u32::try_from(bytes).map_err(io::Error::other)?;
    // SAFETY: the token has ADJUST_PRIVILEGES access and the buffer holds count
    // initialized entries. No previous state is requested.
    if unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            header,
            length,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Success can still report ERROR_NOT_ALL_ASSIGNED for an incomplete change.
    // SAFETY: GetLastError has no memory requirements.
    let status = unsafe { GetLastError() };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(
            status.to_ne_bytes(),
        )));
    }
    Ok(names)
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
    let header = storage.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: Windows initialized a TOKEN_PRIVILEGES header in this storage.
    let count = usize::try_from(unsafe { (*header).PrivilegeCount }).map_err(io::Error::other)?;
    let offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    if offset + count * size_of::<LUID_AND_ATTRIBUTES>() > storage.len() * size_of::<u32>() {
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
    String::from_utf16(&name[..length.min(name.len())]).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_only_change_notify(&token);
    }

    #[test]
    #[ignore = "requires the installed BFD service on a disposable MSI test runner"]
    fn installed_bfd_token_is_restricted_and_retains_only_change_notify() {
        let token = installed_service_token(crate::config::SERVICE_NAME);
        crate::service_identity::require_restricted_bfd_token(token.as_raw_handle()).unwrap();
        assert_only_change_notify(&token);
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

    fn assert_only_change_notify(token: &OwnedHandle) {
        use windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED;

        let entries = privileges(token).unwrap();
        let names: Vec<_> = entries
            .iter()
            .map(|entry| privilege_name(&entry.Luid).unwrap())
            .collect();
        assert_eq!(names, ["SeChangeNotifyPrivilege"]);
        assert_ne!(entries[0].Attributes & SE_PRIVILEGE_ENABLED, 0);
    }

    #[cfg(not(miri))]
    #[test]
    fn broker_retains_only_change_notify_and_can_read_provider_schema() {
        const CHILD: &str = "BFD_TEST_BROKER_PRIVILEGES_CHILD";
        if std::env::var_os(CHILD).is_some() {
            drop_broker_privileges().unwrap();
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
            assert!(drop_broker_privileges().unwrap().is_empty());
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
            drop_privileges().unwrap();
            let token = {
                let mut raw = ptr::null_mut();
                // SAFETY: valid pseudo-handle and writable output.
                let opened =
                    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) };
                assert_ne!(opened, 0);
                // SAFETY: successful open transfers ownership.
                unsafe { OwnedHandle::from_raw_handle(raw) }
            };
            assert_only_change_notify(&token);
            assert!(drop_privileges().unwrap().is_empty());
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
