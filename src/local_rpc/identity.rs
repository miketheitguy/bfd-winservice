//! Per-call RPC identity checks without attaching a caller token to a thread.
#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    io,
    mem::{align_of, offset_of, size_of},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, LUID},
    Security::{
        Authorization::{
            AuthzContextInfoGroupsSids, AuthzContextInfoRestrictedSids, AuthzContextInfoUserSid,
            AuthzGetInformationFromContext, ConvertStringSidToSidW,
            AUTHZ_CONTEXT_INFORMATION_CLASS,
        },
        EqualSid, SID, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_USER,
    },
    System::Rpc::{
        rcclLocal, RpcFreeAuthorizationContext, RpcGetAuthorizationContextForClient,
        RpcServerInqCallAttributesW, RPC_CALL_ATTRIBUTES_V2_W, RPC_C_AUTHN_WINNT, RPC_PROTSEQ_LRPC,
        RPC_QUERY_IS_CLIENT_LOCAL, RPC_S_OK,
    },
};

// RPC_C_AUTHN_LEVEL_PKT_PRIVACY from rpcdce.h; windows-sys exports it only with COM.
const AUTHENTICATION_LEVEL_PRIVACY: u32 = 6;
// Token group attributes from winnt.h, absent from windows-sys exports.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
const MAX_IDENTITY_BYTES: usize = 1024 * 1024;

/// Checks the current call's native transport, authentication, account and group.
/// The RPC interface descriptor independently applies Windows ACL semantics,
/// including the caller's restricting SIDs. This check establishes identity.
pub(crate) fn authorize_call(
    binding: *const c_void,
    expected_user: &str,
    expected_group: &str,
) -> io::Result<()> {
    authorize_identity(binding, expected_user, expected_group, false)
}

// BGP retains its additional restricted-client rule, including WRITE_RESTRICTED
// tokens. The telemetry broker caller uses the unrestricted-service policy.
pub(crate) fn authorize_restricted_call(
    binding: *const c_void,
    expected_user: &str,
    expected_group: &str,
) -> io::Result<()> {
    authorize_identity(binding, expected_user, expected_group, true)
}

fn authorize_identity(
    binding: *const c_void,
    expected_user: &str,
    expected_group: &str,
    check_restricting: bool,
) -> io::Result<()> {
    let mut attributes = RPC_CALL_ATTRIBUTES_V2_W {
        Version: 2,
        Flags: RPC_QUERY_IS_CLIENT_LOCAL,
        ..Default::default()
    };
    // SAFETY: the binding comes from the active RPC security callback. The
    // initialized, writable output has the requested native v2 layout.
    let status =
        unsafe { RpcServerInqCallAttributesW(binding, ptr::from_mut(&mut attributes).cast()) };
    if status != RPC_S_OK {
        return Err(io::Error::from_raw_os_error(status));
    }
    if !authenticated_local_call(&attributes) {
        return Err(denied());
    }

    let mut raw = ptr::null_mut();
    // SAFETY: a live authenticated call supplies the client binding; every
    // reserved argument is zero. ImpersonateOnReturn is FALSE, so no caller
    // token is attached to this thread and SeImpersonatePrivilege is unnecessary.
    let status = unsafe {
        RpcGetAuthorizationContextForClient(
            binding,
            0,
            ptr::null(),
            ptr::null(),
            LUID {
                LowPart: 0,
                HighPart: 0,
            },
            0,
            ptr::null(),
            &mut raw,
        )
    };
    if status != RPC_S_OK {
        return Err(io::Error::from_raw_os_error(status));
    }
    if raw.is_null() {
        return Err(invalid_identity());
    }
    let context = AuthorizationContext(raw);
    let user = SidAllocation::parse(expected_user)?;
    let group = SidAllocation::parse(expected_group)?;
    let user_info = IdentityInfo::query(&context, AuthzContextInfoUserSid)?;
    let group_info = IdentityInfo::query(&context, AuthzContextInfoGroupsSids)?;
    if !user_info.user_matches(&user)? || !group_info.enabled_group(&group)? {
        return Err(denied());
    }
    if check_restricting
        && !IdentityInfo::query(&context, AuthzContextInfoRestrictedSids)?
            .matches_group(&group, false, true)?
    {
        return Err(denied());
    }
    Ok(())
}

fn authenticated_local_call(attributes: &RPC_CALL_ATTRIBUTES_V2_W) -> bool {
    attributes.ProtocolSequence == RPC_PROTSEQ_LRPC
        && attributes.IsClientLocal == rcclLocal
        && attributes.NullSession == 0
        && attributes.AuthenticationService == RPC_C_AUTHN_WINNT
        && attributes.AuthenticationLevel >= AUTHENTICATION_LEVEL_PRIVACY
}

struct AuthorizationContext(*mut c_void);
impl Drop for AuthorizationContext {
    fn drop(&mut self) {
        // SAFETY: owns the single reference returned by successful RPC context
        // acquisition. This API, rather than AuthzFreeContext, releases it.
        let _ = unsafe { RpcFreeAuthorizationContext(&mut self.0) };
    }
}

struct SidAllocation(*mut c_void);
impl SidAllocation {
    fn parse(value: &str) -> io::Result<Self> {
        let text: Vec<u16> = value.encode_utf16().chain([0]).collect();
        let mut raw = ptr::null_mut();
        // SAFETY: the terminated SID text and writable output remain live;
        // successful conversion transfers one LocalFree-owned allocation.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(raw))
    }
}
impl Drop for SidAllocation {
    fn drop(&mut self) {
        // SAFETY: owns one allocation returned by ConvertStringSidToSidW.
        unsafe { LocalFree(self.0) };
    }
}

/// Initialized, pointer-aligned storage for native TOKEN_USER/TOKEN_GROUPS.
struct IdentityInfo {
    words: Vec<usize>,
    length: usize,
}
impl IdentityInfo {
    fn query(
        context: &AuthorizationContext,
        class: AUTHZ_CONTEXT_INFORMATION_CLASS,
    ) -> io::Result<Self> {
        let mut needed = 0;
        // SAFETY: the live RPC context permits read-only queries; this initial
        // size query provides a writable size and no output buffer.
        if unsafe {
            AuthzGetInformationFromContext(context.0, class, 0, &mut needed, ptr::null_mut())
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(error);
            }
        }
        let length = usize::try_from(needed).map_err(io::Error::other)?;
        if length == 0 || length > MAX_IDENTITY_BYTES {
            return Err(invalid_identity());
        }
        let mut info = Self {
            words: vec![0; length.div_ceil(size_of::<usize>())],
            length,
        };
        // SAFETY: usize storage aligns both native layouts and is initialized
        // for at least the requested bytes. The context remains live throughout.
        if unsafe {
            AuthzGetInformationFromContext(
                context.0,
                class,
                needed,
                &mut needed,
                info.words.as_mut_ptr().cast(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        info.length = usize::try_from(needed).map_err(io::Error::other)?;
        if info.length > length {
            return Err(invalid_identity());
        }
        Ok(info)
    }

    fn sid_matches(&self, actual: *mut c_void, expected: &SidAllocation) -> io::Result<bool> {
        let address = actual as usize;
        let offset = address
            .checked_sub(self.words.as_ptr() as usize)
            .ok_or_else(invalid_identity)?;
        let header = offset_of!(SID, SubAuthority);
        if !address.is_multiple_of(align_of::<SID>())
            || offset > self.length
            || self.length - offset < header
        {
            return Err(invalid_identity());
        }
        // SAFETY: every allocated word is initialized, and length does not
        // exceed storage. The checked header fits this read-only byte view.
        let bytes =
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) };
        let count = usize::from(bytes[offset + 1]);
        if bytes[offset] != 1
            || count > 15
            || self.length - offset < header + count * size_of::<u32>()
        {
            return Err(invalid_identity());
        }
        // SAFETY: both SID bodies are validated and owned for this whole call.
        Ok(unsafe { EqualSid(actual, expected.0) } != 0)
    }

    fn user_matches(&self, expected: &SidAllocation) -> io::Result<bool> {
        if self.length < size_of::<TOKEN_USER>() {
            return Err(invalid_identity());
        }
        // SAFETY: aligned initialized storage contains a complete TOKEN_USER.
        let actual = unsafe { (*self.words.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        self.sid_matches(actual, expected)
    }

    fn enabled_group(&self, expected: &SidAllocation) -> io::Result<bool> {
        self.matches_group(expected, true, false)
    }

    fn matches_group(
        &self,
        expected: &SidAllocation,
        enabled: bool,
        allow_empty: bool,
    ) -> io::Result<bool> {
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        let minimum = if allow_empty {
            size_of::<u32>()
        } else {
            offset
        };
        if self.length < minimum {
            return Err(invalid_identity());
        }
        // SAFETY: initialized, aligned storage contains the complete count field.
        let count = usize::try_from(unsafe { self.words.as_ptr().cast::<u32>().read() })
            .map_err(io::Error::other)?;
        if count == 0 {
            return Ok(allow_empty);
        }
        let end = count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|length| offset.checked_add(length))
            .ok_or_else(invalid_identity)?;
        if end > self.length {
            return Err(invalid_identity());
        }
        for index in 0..count {
            // SAFETY: storage aligns native entries; the count bounds check
            // covers the full initialized entry before it is copied out.
            let entry = unsafe {
                self.words
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<SID_AND_ATTRIBUTES>()
                    .add(index)
                    .read()
            };
            if self.sid_matches(entry.Sid, expected)?
                && (!enabled
                    || (entry.Attributes & SE_GROUP_ENABLED != 0
                        && entry.Attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local RPC caller is not authorized",
    )
}

fn invalid_identity() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native RPC caller identity",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialized_info(length: usize) -> IdentityInfo {
        IdentityInfo {
            words: vec![0; length.div_ceil(size_of::<usize>())],
            length,
        }
    }

    fn bytes(info: &mut IdentityInfo) -> &mut [u8] {
        // SAFETY: test fixtures allocate initialized storage covering length;
        // the exclusive borrow prevents other accesses while this view exists.
        unsafe { std::slice::from_raw_parts_mut(info.words.as_mut_ptr().cast(), info.length) }
    }

    fn world_sid_at(info: &mut IdentityInfo, offset: usize) -> *mut c_void {
        let value = &mut bytes(info)[offset..offset + 12];
        value[0] = 1;
        value[1] = 1;
        value[7] = 1;
        // SAFETY: the full SID was initialized inside the fixture allocation.
        unsafe { info.words.as_mut_ptr().cast::<u8>().add(offset).cast() }
    }

    fn group(attributes: u32) -> IdentityInfo {
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        let sid_offset = offset + size_of::<SID_AND_ATTRIBUTES>();
        let mut info = initialized_info(sid_offset + 12);
        let sid = world_sid_at(&mut info, sid_offset);
        bytes(&mut info)[..size_of::<u32>()].copy_from_slice(&1_u32.to_ne_bytes());
        let entry = SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: attributes,
        };
        // SAFETY: one aligned, initialized native entry fits the fixture.
        unsafe {
            info.words
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>()
                .write(entry);
        }
        info
    }

    fn assert_invalid<T>(result: io::Result<T>) {
        match result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("invalid RPC identity buffer was accepted"),
        }
    }

    #[test]
    fn call_policy_requires_local_authenticated_private_lrpc() {
        let valid = RPC_CALL_ATTRIBUTES_V2_W {
            ProtocolSequence: RPC_PROTSEQ_LRPC,
            IsClientLocal: rcclLocal,
            AuthenticationService: RPC_C_AUTHN_WINNT,
            AuthenticationLevel: AUTHENTICATION_LEVEL_PRIVACY,
            ..Default::default()
        };
        assert!(authenticated_local_call(&valid));
        for invalid in [
            RPC_CALL_ATTRIBUTES_V2_W {
                ProtocolSequence: 0,
                ..valid
            },
            RPC_CALL_ATTRIBUTES_V2_W {
                IsClientLocal: 0,
                ..valid
            },
            RPC_CALL_ATTRIBUTES_V2_W {
                IsClientLocal: 2,
                ..valid
            },
            RPC_CALL_ATTRIBUTES_V2_W {
                NullSession: 1,
                ..valid
            },
            RPC_CALL_ATTRIBUTES_V2_W {
                AuthenticationService: 0,
                ..valid
            },
            RPC_CALL_ATTRIBUTES_V2_W {
                AuthenticationLevel: 5,
                ..valid
            },
        ] {
            assert!(!authenticated_local_call(&invalid));
        }
    }

    #[test]
    fn group_identity_requires_enabled_non_deny_only_expected_sid() {
        let expected = SidAllocation::parse("S-1-1-0").unwrap();
        let unrelated = SidAllocation::parse("S-1-5-11").unwrap();
        assert!(group(SE_GROUP_ENABLED).enabled_group(&expected).unwrap());
        for attributes in [
            0,
            SE_GROUP_USE_FOR_DENY_ONLY,
            SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY,
        ] {
            assert!(!group(attributes).enabled_group(&expected).unwrap());
        }
        assert!(!group(SE_GROUP_ENABLED).enabled_group(&unrelated).unwrap());
    }

    #[test]
    fn user_identity_requires_exact_token_user() {
        let sid_offset = size_of::<TOKEN_USER>();
        let mut info = initialized_info(sid_offset + 12);
        let sid = world_sid_at(&mut info, sid_offset);
        let user = TOKEN_USER {
            User: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0,
            },
        };
        // SAFETY: initialized aligned storage fits a complete TOKEN_USER header.
        unsafe { info.words.as_mut_ptr().cast::<TOKEN_USER>().write(user) };
        assert!(info
            .user_matches(&SidAllocation::parse("S-1-1-0").unwrap())
            .unwrap());
        assert!(!info
            .user_matches(&SidAllocation::parse("S-1-5-11").unwrap())
            .unwrap());
        for length in 0..size_of::<TOKEN_USER>() {
            assert_invalid(
                initialized_info(length).user_matches(&SidAllocation::parse("S-1-1-0").unwrap()),
            );
        }
    }

    #[test]
    fn sid_bounds_and_body_are_checked_before_native_comparison() {
        let expected = SidAllocation::parse("S-1-1-0").unwrap();
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
            assert_invalid(info.sid_matches(actual, &expected));
        }
        for (revision, count, length) in [(0, 1, 12), (2, 1, 12), (1, 16, 80), (1, 1, 8)] {
            let mut info = initialized_info(length);
            bytes(&mut info)[0] = revision;
            bytes(&mut info)[1] = count;
            assert_invalid(info.sid_matches(info.words.as_ptr().cast_mut().cast(), &expected));
        }
    }

    #[test]
    fn group_bounds_reject_truncated_counts_and_invalid_sid_pointers() {
        let expected = SidAllocation::parse("S-1-1-0").unwrap();
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        for length in 0..offset {
            assert_invalid(initialized_info(length).enabled_group(&expected));
        }
        for count in [1_u32, 2, u32::MAX] {
            let mut info = initialized_info(offset);
            bytes(&mut info)[..size_of::<u32>()].copy_from_slice(&count.to_ne_bytes());
            assert_invalid(info.enabled_group(&expected));
        }
        assert!(!initialized_info(offset).enabled_group(&expected).unwrap());
        let mut info = group(SE_GROUP_ENABLED);
        // SAFETY: the fixture owns this complete aligned SID_AND_ATTRIBUTES.
        unsafe {
            (*info
                .words
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>())
            .Sid = ptr::null_mut();
        }
        assert_invalid(info.enabled_group(&expected));
    }
}
