//! Native account and service-SID checks, independent of restricting account SIDs.
#![allow(unsafe_code)]

use std::{
    io,
    mem::{align_of, offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{
        Authorization::ConvertStringSidToSidW, EqualSid, GetTokenInformation, TokenGroups,
        TokenRestrictedSids, TokenUser, SID, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
        TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

// Token group attribute flags from winnt.h, absent from windows-sys exports.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

struct SidAllocation(*mut std::ffi::c_void);
impl Drop for SidAllocation {
    fn drop(&mut self) {
        // SAFETY: owns one allocation returned by a Windows SID conversion.
        unsafe { LocalFree(self.0) };
    }
}
fn sid(value: &str) -> io::Result<SidAllocation> {
    let text: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let mut output = ptr::null_mut();
    // SAFETY: terminated input and writable output; success transfers ownership.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut output) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SidAllocation(output))
}

pub(crate) fn process_token() -> io::Result<OwnedHandle> {
    let mut output = ptr::null_mut();
    // SAFETY: valid process pseudo-handle and writable real-token handle output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut output) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transfers one uniquely owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(output) })
}

pub(crate) fn require_identity(token: HANDLE, group_sid: &str, user_sid: &str) -> io::Result<()> {
    let group = sid(group_sid)?;
    let user = sid(user_sid)?;
    let groups = TokenInfo::query(token, TokenGroups)?;
    let restrictions = TokenInfo::query(token, TokenRestrictedSids)?;
    let (restricting_count, restricting_member) = restrictions.groups(&group, false)?;
    let account = TokenInfo::query(token, TokenUser)?;
    if !groups.groups(&group, true)?.1
        || (restricting_count != 0 && !restricting_member)
        || !account.matches(account.user_pointer()?, &user)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service identity is not authorized",
        ));
    }
    Ok(())
}

struct TokenInfo {
    words: Vec<usize>,
    length: usize,
}
impl TokenInfo {
    fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Self> {
        let mut needed = 0;
        // SAFETY: size-only query on a live token with a writable size output.
        if unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(error);
            }
        }
        let length = usize::try_from(needed).map_err(io::Error::other)?;
        if length == 0 || length > 1024 * 1024 {
            return Err(invalid_token());
        }
        let mut info = Self {
            words: vec![0; length.div_ceil(size_of::<usize>())],
            length,
        };
        let capacity = needed;
        // SAFETY: usize storage aligns pointer-bearing token headers and has
        // capacity for every requested byte. Windows initializes the result.
        if unsafe {
            GetTokenInformation(
                token,
                class,
                info.words.as_mut_ptr().cast(),
                capacity,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        info.length = usize::try_from(needed).map_err(io::Error::other)?;
        if info.length > length {
            return Err(invalid_token());
        }
        Ok(info)
    }

    fn matches(&self, actual: *mut std::ffi::c_void, expected: &SidAllocation) -> io::Result<bool> {
        let base = self.words.as_ptr() as usize;
        let address = actual as usize;
        let offset = address.checked_sub(base).ok_or_else(invalid_token)?;
        let header = offset_of!(SID, SubAuthority);
        if !address.is_multiple_of(align_of::<SID>())
            || offset > self.length
            || self.length - offset < header
        {
            return Err(invalid_token());
        }
        // SAFETY: the initialized token buffer contains the checked SID header;
        // all allocated words were initialized before the native query.
        let bytes =
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) };
        let count = usize::from(bytes[offset + 1]);
        if bytes[offset] != 1
            || count > 15
            || self.length - offset < header + count * size_of::<u32>()
        {
            return Err(invalid_token());
        }
        // SAFETY: both SID bodies are validated and remain live for this call.
        Ok(unsafe { EqualSid(actual, expected.0) } != 0)
    }

    fn user_pointer(&self) -> io::Result<*mut std::ffi::c_void> {
        if self.length < size_of::<TOKEN_USER>() {
            return Err(invalid_token());
        }
        // SAFETY: aligned storage contains a complete native TOKEN_USER header.
        Ok(unsafe { (*self.words.as_ptr().cast::<TOKEN_USER>()).User.Sid })
    }

    fn groups(&self, expected: &SidAllocation, enabled: bool) -> io::Result<(usize, bool)> {
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        if self.length < offset {
            return Err(invalid_token());
        }
        // SAFETY: the initialized, aligned group header fits the returned buffer.
        let count =
            usize::try_from(unsafe { (*self.words.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount })
                .map_err(io::Error::other)?;
        let end = count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|length| offset.checked_add(length))
            .ok_or_else(invalid_token)?;
        if end > self.length {
            return Err(invalid_token());
        }
        for index in 0..count {
            // SAFETY: the count check covers every aligned native array entry.
            let entry = unsafe {
                self.words
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<SID_AND_ATTRIBUTES>()
                    .add(index)
                    .read()
            };
            if self.matches(entry.Sid, expected)?
                && (!enabled
                    || (entry.Attributes & SE_GROUP_ENABLED != 0
                        && entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0))
            {
                return Ok((count, true));
            }
        }
        Ok((count, false))
    }
}

fn invalid_token() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native service token information",
    )
}

pub(crate) fn require_restricted_bfd_token(token: HANDLE) -> io::Result<()> {
    require_identity(token, crate::bgp::ipc::SERVICE_SID, "S-1-5-19")?;
    let restrictions = TokenInfo::query(token, TokenRestrictedSids)?;
    for expected in [crate::bgp::ipc::SERVICE_SID, "S-1-5-33"] {
        if !restrictions.groups(&sid(expected)?, false)?.1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "BFD requires its restricted service SID and write-restricted SID",
            ));
        }
    }
    Ok(())
}

/// Verifies the installed service's LocalService account and restricted service SID.
///
/// # Errors
/// Returns an error if token inspection fails or SCM supplied an unexpected identity.
pub fn verify_bfd_service_identity() -> io::Result<()> {
    require_restricted_bfd_token(process_token()?.as_raw_handle())
}

#[cfg(test)]
pub(crate) fn current_user_sid() -> io::Result<String> {
    let token = process_token()?;
    let info = TokenInfo::query(token.as_raw_handle(), TokenUser)?;
    let actual = info.user_pointer()?;
    // Validate the pointer/body before asking Windows to convert the SID.
    let _ = info.matches(actual, &sid("S-1-1-0")?)?;
    let mut text = ptr::null_mut();
    // SAFETY: validated live SID and writable conversion output.
    if unsafe { ConvertSidToStringSidW(actual, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text = SidAllocation(text.cast());
    let mut length = 0;
    // SAFETY: Windows returns an allocated, terminated UTF-16 string.
    while unsafe { *text.0.cast::<u16>().add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the measured initialized UTF-16 string remains owned here.
    let units = unsafe { std::slice::from_raw_parts(text.0.cast::<u16>(), length) };
    String::from_utf16(units).map_err(io::Error::other)
}

#[cfg(test)]
mod tests;
