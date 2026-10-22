//! Token mutation for disposable child test processes only.
use super::*;
use std::os::windows::io::FromRawHandle;
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_SUCCESS},
    Security::{AdjustTokenPrivileges, SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub(crate) fn drop_rpc_privileges() -> io::Result<()> {
    drop_except(&[REQUIRED_PRIVILEGE]).map(|_| ())
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
