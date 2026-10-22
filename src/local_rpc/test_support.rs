//! Reduced identities for native fixtures; never grants a service SID or privilege.
use super::LocalAllocation;
use std::{
    io,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
};
use windows_sys::Win32::{
    Security::{
        CreateRestrictedToken, ImpersonateLoggedOnUser, RevertToSelf, SID_AND_ATTRIBUTES,
        TOKEN_DUPLICATE, TOKEN_QUERY, WRITE_RESTRICTED,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub(crate) fn restricted_token(sid: &str, disable: bool) -> OwnedHandle {
    let sid = LocalAllocation::sid(sid).unwrap();
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

pub(crate) struct OwnIdentity {
    // RevertToSelf must run on the thread that attached the reduced identity.
    _thread_bound: PhantomData<Rc<()>>,
}
impl OwnIdentity {
    pub(crate) fn enter(token: &OwnedHandle) -> Self {
        // SAFETY: attaches only our own reduced identity to this test thread.
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
        Self {
            _thread_bound: PhantomData,
        }
    }
}
impl Drop for OwnIdentity {
    fn drop(&mut self) {
        // SAFETY: this non-Send guard restores the same test thread before reuse.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}
