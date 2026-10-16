//! Removes process privileges that the BFD service never uses.
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

/// Directory traversal and global object creation remain available to RPC,
/// file logging, and Winsock. No BFD operation needs any other privilege.
const RETAINED: [&str; 2] = ["SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege"];

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
            for entry in privileges(&token).unwrap() {
                let name = privilege_name(&entry.Luid).unwrap();
                assert!(RETAINED.contains(&name.as_str()), "{name} remained");
            }
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
