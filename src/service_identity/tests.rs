//! Native token tests use our actual account and existing groups as analogues.
//! They never grant a service SID, impersonate another account, or alter services.
#![allow(clippy::unwrap_used)]

use super::*;
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, LUID},
    Security::{
        AccessCheck, CheckTokenMembership, CreateRestrictedToken, DuplicateToken,
        SecurityIdentification, GENERIC_MAPPING, LUID_AND_ATTRIBUTES, PRIVILEGE_SET,
        SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, WRITE_RESTRICTED,
    },
};

const WORLD: &str = "S-1-1-0";
const AUTHENTICATED_USERS: &str = "S-1-5-11";

fn own_query_duplicate_token() -> OwnedHandle {
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: valid process pseudo-handle and writable real-token output. The
        // handle is queried/duplicated only, never applied to a process or thread.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) },
        0,
        "OpenProcessToken: {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful OpenProcessToken transfers unique handle ownership.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

fn restricted_token(restricting: &[&str], disabled: &[&str]) -> OwnedHandle {
    restricted_token_with_flags(restricting, disabled, WRITE_RESTRICTED)
}

fn restricted_token_with_flags(restricting: &[&str], disabled: &[&str], flags: u32) -> OwnedHandle {
    let original = own_query_duplicate_token();
    let restricting_sids: Vec<_> = restricting
        .iter()
        .map(|value| sid(value).unwrap())
        .collect();
    let disabled_sids: Vec<_> = disabled.iter().map(|value| sid(value).unwrap()).collect();
    let restricting_entries: Vec<_> = restricting_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: 0,
        })
        .collect();
    let disabled_entries: Vec<_> = disabled_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.0,
            Attributes: 0,
        })
        .collect();
    let mut raw = ptr::null_mut();
    // SAFETY: live query/duplicate token, correctly sized SID arrays whose SID
    // allocations remain live through this synchronous call, and writable
    // output. CRT only narrows permissions; it cannot add normal group grants.
    let success = unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            flags,
            u32::try_from(disabled_entries.len()).unwrap(),
            if disabled_entries.is_empty() {
                ptr::null()
            } else {
                disabled_entries.as_ptr()
            },
            0,
            ptr::null(),
            u32::try_from(restricting_entries.len()).unwrap(),
            restricting_entries.as_ptr(),
            &mut raw,
        )
    };
    assert_ne!(
        success,
        0,
        "CreateRestrictedToken(flags={flags:#x}): {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful CRT transfers a uniquely owned token handle.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

fn identify_token(token: &OwnedHandle) -> OwnedHandle {
    let mut raw = ptr::null_mut();
    assert_ne!(
        // SAFETY: live duplicate-capable token and writable identification-token
        // output. The resulting token is never attached to a thread.
        unsafe { DuplicateToken(token.as_raw_handle(), SecurityIdentification, &mut raw) },
        0,
        "DuplicateToken(Identify): {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful duplication transfers unique handle ownership.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

fn legacy_membership(token: &OwnedHandle, expected: &str) -> bool {
    let identification = identify_token(token);
    let expected = sid(expected).unwrap();
    let mut member = 0;
    assert_ne!(
        // SAFETY: live identification token, SID allocation and writable BOOL.
        unsafe { CheckTokenMembership(identification.as_raw_handle(), expected.0, &mut member) },
        0,
        "CheckTokenMembership: {}",
        io::Error::last_os_error()
    );
    member != 0
}

fn write_access(token: &OwnedHandle, trustee: &str) -> bool {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    let text: Vec<u16> = format!("O:SYG:SYD:(A;;0x2;;;{trustee})")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut descriptor = ptr::null_mut();
    assert_ne!(
        // SAFETY: terminated trusted SDDL and writable descriptor output.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0,
        "ConvertStringSecurityDescriptor: {}",
        io::Error::last_os_error()
    );
    let descriptor = SidAllocation(descriptor);
    let identification = identify_token(token);
    // FILE_WRITE_DATA (0x2) is mapped as write access for this test resource.
    let mapping = GENERIC_MAPPING {
        GenericRead: 1,
        GenericWrite: 2,
        GenericExecute: 0,
        GenericAll: 3,
    };
    let mut privileges = PRIVILEGE_SET {
        PrivilegeCount: 0,
        Control: 0,
        Privilege: [LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: 0,
        }],
    };
    let mut length = u32::try_from(size_of::<PRIVILEGE_SET>()).unwrap();
    let mut granted = 0;
    let mut allowed = 0;
    assert_ne!(
        // SAFETY: valid descriptor, Identify token, mapping and initialized native
        // output buffers. No privilege-granting access is requested. Evaluation
        // success and permission success are deliberately tested independently.
        unsafe {
            AccessCheck(
                descriptor.0,
                identification.as_raw_handle(),
                2,
                &mapping,
                &mut privileges,
                &mut length,
                &mut granted,
                &mut allowed,
            )
        },
        0,
        "AccessCheck: {}",
        io::Error::last_os_error()
    );
    assert_eq!(granted, if allowed != 0 { 2 } else { 0 });
    allowed != 0
}

#[test]
fn native_membership_distinguishes_fully_and_write_restricted_tokens() {
    let user = current_user_sid().unwrap();
    assert_ne!(user, WORLD);
    for flags in [0, WRITE_RESTRICTED] {
        let token = restricted_token_with_flags(&[WORLD], &[], flags);
        let restrictions = TokenInfo::query(token.as_raw_handle(), TokenRestrictedSids).unwrap();
        assert!(restrictions.groups(&sid(WORLD).unwrap(), false).unwrap().1);
        assert!(
            !restrictions.groups(&sid(&user).unwrap(), false).unwrap().1,
            "fixture must exclude the actual account from its restricting list"
        );
        let groups = TokenInfo::query(token.as_raw_handle(), TokenGroups).unwrap();
        assert!(groups.groups(&sid(WORLD).unwrap(), true).unwrap().1);
        let member = legacy_membership(&token, &user);
        assert_eq!(member, flags == WRITE_RESTRICTED);
        println!(
            "EXERCISED native token: CRT flags={flags:#x}; actual account absent from restricting SIDs; CheckTokenMembership(account)={}",
            member
        );
        require_identity(token.as_raw_handle(), WORLD, &user).unwrap();
    }
}

#[test]
fn exact_identity_accepts_actual_write_restricted_token_with_query_only_handle() {
    let user = current_user_sid().unwrap();
    let restricted = restricted_token(&[WORLD], &[]);
    let mut query_only = ptr::null_mut();
    assert_ne!(
        // SAFETY: live source token and process pseudo-handles, writable output;
        // narrowing the duplicate handle to TOKEN_QUERY grants no token mutation.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                restricted.as_raw_handle(),
                GetCurrentProcess(),
                &mut query_only,
                TOKEN_QUERY,
                0,
                0,
            )
        },
        0,
        "DuplicateHandle(TOKEN_QUERY): {}",
        io::Error::last_os_error()
    );
    // SAFETY: successful duplication transfers unique handle ownership.
    let query_only = unsafe { OwnedHandle::from_raw_handle(query_only) };
    let actual = TokenInfo::query(query_only.as_raw_handle(), TokenUser).unwrap();
    assert!(actual
        .matches(actual.user_pointer().unwrap(), &sid(&user).unwrap())
        .unwrap());
    let normal = TokenInfo::query(query_only.as_raw_handle(), TokenGroups).unwrap();
    assert!(normal.groups(&sid(WORLD).unwrap(), true).unwrap().1);
    let restrictions = TokenInfo::query(query_only.as_raw_handle(), TokenRestrictedSids).unwrap();
    assert!(restrictions.groups(&sid(WORLD).unwrap(), false).unwrap().1);
    require_identity(query_only.as_raw_handle(), WORLD, &user).unwrap();
    println!("EXERCISED: native WRITE_RESTRICTED identity checks require TOKEN_QUERY only");
}

#[test]
fn exact_identity_does_not_bypass_native_restricting_sid_write_access() {
    let user = current_user_sid().unwrap();
    let token = restricted_token(&[WORLD], &[]);
    assert!(
        !write_access(&token, &user),
        "account-only ACL must fail the restricting SID write check"
    );
    assert!(
        write_access(&token, WORLD),
        "normal/restricting group ACL must permit the write"
    );
    require_identity(token.as_raw_handle(), WORLD, &user).unwrap();
}

#[test]
fn service_group_must_be_enabled_in_normal_and_restricting_lists() {
    let user = current_user_sid().unwrap();
    let world_only = restricted_token(&[WORLD], &[]);
    let normal = TokenInfo::query(world_only.as_raw_handle(), TokenGroups).unwrap();
    assert!(
        normal
            .groups(&sid(AUTHENTICATED_USERS).unwrap(), true)
            .unwrap()
            .1
    );
    let restricted = TokenInfo::query(world_only.as_raw_handle(), TokenRestrictedSids).unwrap();
    assert!(
        !restricted
            .groups(&sid(AUTHENTICATED_USERS).unwrap(), false)
            .unwrap()
            .1
    );
    assert!(
        legacy_membership(&world_only, AUTHENTICATED_USERS),
        "write-restricted membership alone does not enforce the restricting group"
    );
    assert_eq!(
        require_identity(world_only.as_raw_handle(), AUTHENTICATED_USERS, &user)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    // CRT may add a restricting SID, but it cannot grant that SID as a normal
    // group. A restricting service SID alone must never authorize a caller.
    let restricting_only = restricted_token(&[crate::bgp::ipc::SERVICE_SID], &[]);
    let normal = TokenInfo::query(restricting_only.as_raw_handle(), TokenGroups).unwrap();
    assert!(
        !normal
            .groups(&sid(crate::bgp::ipc::SERVICE_SID).unwrap(), true)
            .unwrap()
            .1
    );
    let restricted =
        TokenInfo::query(restricting_only.as_raw_handle(), TokenRestrictedSids).unwrap();
    assert!(
        restricted
            .groups(&sid(crate::bgp::ipc::SERVICE_SID).unwrap(), false)
            .unwrap()
            .1
    );
    assert_eq!(
        require_identity(
            restricting_only.as_raw_handle(),
            crate::bgp::ipc::SERVICE_SID,
            &user
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::PermissionDenied
    );

    let deny_only = restricted_token(&[WORLD], &[WORLD]);
    let normal = TokenInfo::query(deny_only.as_raw_handle(), TokenGroups).unwrap();
    assert!(!normal.groups(&sid(WORLD).unwrap(), true).unwrap().1);
    assert_eq!(
        require_identity(deny_only.as_raw_handle(), WORLD, &user)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn enabled_account_group_does_not_substitute_for_exact_token_user() {
    let user = current_user_sid().unwrap();
    assert_ne!(user, WORLD);
    let token = own_query_duplicate_token();
    assert!(
        legacy_membership(&token, WORLD),
        "fixture uses a real existing enabled group"
    );
    assert_eq!(
        require_identity(token.as_raw_handle(), WORLD, WORLD)
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn restricted_bfd_startup_guard_denies_unrelated_actual_tokens() {
    let token = restricted_token(&[WORLD, "S-1-5-33"], &[]);
    assert_eq!(
        require_restricted_bfd_token(token.as_raw_handle())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

fn initialized_info(length: usize) -> TokenInfo {
    TokenInfo {
        words: vec![0; length.div_ceil(size_of::<usize>())],
        length,
    }
}

fn fixture_bytes(info: &mut TokenInfo) -> &mut [u8] {
    // SAFETY: every allocated word is initialized; length never exceeds this
    // test fixture's allocation, and the exclusive borrow prevents aliasing.
    unsafe { std::slice::from_raw_parts_mut(info.words.as_mut_ptr().cast(), info.length) }
}

fn assert_invalid<T>(result: io::Result<T>) {
    match result {
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
        Ok(_) => panic!("malformed token information was accepted"),
    }
}

#[test]
fn token_user_parser_rejects_short_native_headers() {
    for length in 0..size_of::<TOKEN_USER>() {
        assert_invalid(initialized_info(length).user_pointer());
    }
}

#[test]
fn sid_parser_rejects_null_misaligned_and_out_of_buffer_pointers() {
    let expected = sid(WORLD).unwrap();
    let info = initialized_info(32);
    let base = info.words.as_ptr().cast::<u8>();
    for actual in [
        ptr::null_mut(),
        base.wrapping_sub(align_of::<SID>()).cast_mut().cast(),
        base.wrapping_add(1).cast_mut().cast(),
        base.wrapping_add(info.length).cast_mut().cast(),
        base.wrapping_add(info.length + align_of::<SID>())
            .cast_mut()
            .cast(),
    ] {
        // No invalid pointer reaches EqualSid: production bounds checks must
        // return InvalidData before any native SID dereference.
        assert_invalid(info.matches(actual, &expected));
    }
}

#[test]
fn sid_parser_rejects_invalid_revision_count_and_truncated_body() {
    let expected = sid(WORLD).unwrap();
    let header = offset_of!(SID, SubAuthority);
    for (revision, count, length) in [(0, 1, 12), (2, 1, 12), (1, 16, 80), (1, 1, 8)] {
        let mut info = initialized_info(length);
        let bytes = fixture_bytes(&mut info);
        bytes[0] = revision;
        bytes[1] = count;
        bytes[7] = 1;
        assert!(length >= header);
        assert_invalid(info.matches(info.words.as_ptr().cast_mut().cast(), &expected));
    }
    let mut info = initialized_info(12);
    let bytes = fixture_bytes(&mut info);
    bytes[0] = 1;
    bytes[1] = 1;
    bytes[7] = 1;
    assert!(info
        .matches(info.words.as_ptr().cast_mut().cast(), &expected)
        .unwrap());
}

#[test]
fn group_parser_rejects_short_headers_and_uninitialized_entry_ranges() {
    let expected = sid(WORLD).unwrap();
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    for length in 0..offset {
        assert_invalid(initialized_info(length).groups(&expected, true));
    }
    for count in [1, 2, u32::MAX] {
        let mut info = initialized_info(offset);
        fixture_bytes(&mut info)[..size_of::<u32>()].copy_from_slice(&count.to_ne_bytes());
        assert_invalid(info.groups(&expected, true));
    }
    let empty = initialized_info(offset);
    assert_eq!(empty.groups(&expected, true).unwrap(), (0, false));
}

#[test]
fn group_parser_rejects_malformed_entry_sid_before_native_access() {
    let expected = sid(WORLD).unwrap();
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    let length = offset + size_of::<SID_AND_ATTRIBUTES>();
    let mut info = initialized_info(length);
    fixture_bytes(&mut info)[..size_of::<u32>()].copy_from_slice(&1_u32.to_ne_bytes());
    let entry = SID_AND_ATTRIBUTES {
        Sid: info
            .words
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(length)
            .cast_mut()
            .cast(),
        Attributes: SE_GROUP_ENABLED,
    };
    // SAFETY: initialized usize storage aligns the one native entry and its
    // full size fits the allocation. The invalid embedded pointer is stored,
    // never dereferenced; production validation must reject it first.
    unsafe {
        info.words
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
            .write(entry);
    }
    assert_invalid(info.groups(&expected, true));
}
