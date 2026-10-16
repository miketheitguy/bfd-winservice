//! Restrict only our own account; never grant a service SID or a privilege.
use super::*;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Security::{
        Authorization::ConvertStringSidToSidW, CreateRestrictedToken, ImpersonateLoggedOnUser,
        RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY, WRITE_RESTRICTED,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn restricted_token(sid: &str, disable: bool) -> OwnedHandle {
    let text: Vec<u16> = sid.encode_utf16().chain([0]).collect();
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: terminated trusted SID and writable allocation output.
        unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) },
        0
    );
    let sid = local_rpc::LocalAllocation(raw);
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: own process pseudo-handle and writable token output, no foreign access.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) },
        0
    );
    // SAFETY: successful open transfers one owned token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let entry = SID_AND_ATTRIBUTES {
        Sid: sid.0,
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: all inputs live through the call; output narrows only our own token.
        unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                if disable { 0 } else { WRITE_RESTRICTED },
                u32::from(disable),
                if disable { &entry } else { ptr::null() },
                0,
                ptr::null(),
                u32::from(!disable),
                if disable { ptr::null() } else { &entry },
                &mut raw,
            )
        },
        0,
        "CreateRestrictedToken: {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful restriction transfers one new owned token.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

struct OwnIdentity;
impl OwnIdentity {
    fn enter(token: &OwnedHandle) -> Self {
        // SAFETY: attaches only our own reduced identity to this test thread.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        Self
    }
}
impl Drop for OwnIdentity {
    fn drop(&mut self) {
        // SAFETY: restore the same test thread before any other test can use it.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

#[test]
fn native_write_restricted_caller_requires_its_group_in_both_lists() {
    for group in [WORLD, "S-1-5-11"] {
        let fixture = Fixture::start(&user(), group, 0, true);
        let token = restricted_token(WORLD, false);
        {
            let _identity = OwnIdentity::enter(&token);
            let result = call_with_policy(&fixture.endpoint, &user(), WORLD, 2, 2_000, None);
            if group == WORLD {
                assert_eq!(result.unwrap().status, 0);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            }
        }
        assert_eq!(fixture.calls(), if group == WORLD { "Start\n" } else { "" });
        fixture.stop();
    }
}

#[test]
fn native_deny_only_caller_group_is_rejected_before_dispatch() {
    let fixture = Fixture::start(&user(), WORLD, 0, true);
    let token = restricted_token(WORLD, true);
    {
        let _identity = OwnIdentity::enter(&token);
        assert!(fixture.call(2).is_err());
    }
    assert!(fixture.calls().is_empty());
    fixture.stop();
}
