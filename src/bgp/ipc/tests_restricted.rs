//! Native pipe fixtures use an actual reduced token of the current account.
//! Service SIDs are never added as enabled normal groups or granted privileges.
#![allow(clippy::unwrap_used)]

use super::*;
use std::thread;
use windows_sys::Win32::{
    Security::{
        Authorization::ConvertStringSidToSidW, CreateRestrictedToken, ImpersonateLoggedOnUser,
        SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, WRITE_RESTRICTED,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const WORLD: &str = "S-1-1-0";
const AUTHENTICATED_USERS: &str = "S-1-5-11";

fn write_restricted_token(restricting_sid: &str) -> OwnedHandle {
    let text = wide(restricting_sid);
    let mut raw_sid = ptr::null_mut();
    assert_ne!(
        // SAFETY: terminated trusted SID text and writable allocation output.
        unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw_sid) },
        0,
        "ConvertStringSidToSid: {}",
        io::Error::last_os_error()
    );
    let sid = LocalAllocation(raw_sid);
    let mut raw_token = ptr::null_mut();
    assert_ne!(
        // SAFETY: own process pseudo-handle, query/duplicate-only access and
        // writable output. No service or foreign token is accessed.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut raw_token,
            )
        },
        0,
        "OpenProcessToken: {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful open transfers unique ownership of a real token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let entry = SID_AND_ATTRIBUTES {
        Sid: sid.0,
        Attributes: 0,
    };
    let mut restricted = ptr::null_mut();
    assert_ne!(
        // SAFETY: live token and SID allocation, one correctly sized restriction
        // entry and writable output. CRT narrows only the current account's rights.
        unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                WRITE_RESTRICTED,
                0,
                ptr::null(),
                0,
                ptr::null(),
                1,
                &entry,
                &mut restricted,
            )
        },
        0,
        "CreateRestrictedToken(WRITE_RESTRICTED): {}",
        io::Error::last_os_error()
    );
    // SAFETY: CRT transfers unique ownership of its new token handle.
    unsafe { OwnedHandle::from_raw_handle(restricted) }
}

struct OwnRestrictedIdentity;
impl OwnRestrictedIdentity {
    fn enter(token: &OwnedHandle) -> Self {
        assert_ne!(
            // SAFETY: live own-account restricted token. Client-side impersonation
            // only attaches it to this thread; each fixture keeps the guard local
            // until Drop restores this same test thread.
            unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) },
            0,
            "ImpersonateLoggedOnUser(own restricted token): {}",
            io::Error::last_os_error()
        );
        Self
    }
}
impl Drop for OwnRestrictedIdentity {
    fn drop(&mut self) {
        // SAFETY: restores this test thread after successful own impersonation.
        // Abort rather than let another test inherit a leaked restricted token.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn assert_server_has_no_client_token() {
    let mut raw = ptr::null_mut();
    // SAFETY: current thread pseudo-handle and writable query-only token output.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    if result != 0 {
        // SAFETY: unexpected successful open still transfers handle ownership.
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
    }
    assert_eq!(result, 0, "caller token leaked beyond pipe authorization");
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1008));
}

#[test]
fn actual_write_restricted_client_round_trips_using_static_identification() {
    let token = write_restricted_token(WORLD);
    let (listener, name) = fixtures::listener(WORLD);
    let stop = StopSignal::new().unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            listener.accept(&stop).unwrap();
            for previous in 0..2 {
                let frame = listener.request(previous, &stop).unwrap();
                assert_server_has_no_client_token();
                listener
                    .respond(Frame { value: 1, ..frame }, &stop)
                    .unwrap();
            }
        });
        let _cleanup = fixtures::StopOnDrop(stop.clone());
        let _restricted_identity = OwnRestrictedIdentity::enter(&token);
        let client = fixtures::connect_pipe(&name);
        for sequence in 1..=2 {
            assert_eq!(
                fixtures::request(&client, Method::Start, sequence)
                    .unwrap()
                    .value,
                1
            );
        }
        server.join().unwrap();
    });
    println!("EXERCISED: native WRITE_RESTRICTED pipe open; static Identify SQOS; two authorized requests; server reverts before work");
}

#[test]
fn native_open_can_succeed_while_missing_restricting_service_group_is_denied() {
    let token = write_restricted_token(AUTHENTICATED_USERS);
    let user = crate::service_identity::current_user_sid().unwrap();
    let name = format!(r"\\.\pipe\BfdRestrictedPolicyTest.{}", std::process::id());
    // Test-only descriptor grants native pipe access via AU in both token lists;
    // application policy independently requires the enabled World analogue in
    // both lists. Production descriptor and exact service policy are unchanged.
    let mut listener = Listener::with_policy(&name, AUTHENTICATED_USERS, &user).unwrap();
    listener.client_sid = WORLD.into();
    let stop = StopSignal::new().unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            listener.accept(&stop).unwrap();
            let error = listener.request(0, &stop).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_server_has_no_client_token();
            listener.disconnect();
        });
        let _cleanup = fixtures::StopOnDrop(stop.clone());
        let _restricted_identity = OwnRestrictedIdentity::enter(&token);
        let client = fixtures::connect_pipe(&name);
        assert!(fixtures::request(&client, Method::Start, 1).is_err());
        server.join().unwrap();
    });
    println!("EXERCISED: native AU pipe open succeeded; enabled normal World did not bypass missing restricting World; rejected before work");
}
