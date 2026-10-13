//! These contract tests are written before the COM implementation.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::{
    config::Options,
    runtime::{Engine, Logger},
};
use std::process::{Command, Output, Stdio};
use windows::Win32::{
    Security::{DuplicateTokenEx, SecurityIdentification, TokenImpersonation, TOKEN_DUPLICATE},
    System::{
        Com::INVOKE_PROPERTYGET,
        Threading::{GetCurrentProcess, OpenProcessToken},
        Variant::VT_EMPTY,
    },
};

fn command_output(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "COM probe exceeded 30 seconds: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn powershell_queries_real_com_or_is_denied_by_caller_identity() {
    const CHILD: &str = "BFD_TEST_STATUS_COM_POWERSHELL";
    if std::env::var_os(CHILD).is_none() {
        let output = command_output(Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "status_com::tests::powershell_queries_real_com_or_is_denied_by_caller_identity",
                "--nocapture",
            ])
            .env(CHILD, "1"));
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    run_powershell_probe(false);
}

#[test]
fn actual_rpc_calls_inspect_caller_token() {
    const CHILD: &str = "BFD_TEST_STATUS_COM_CALLER";
    if std::env::var_os(CHILD).is_none() {
        let output = command_output(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "status_com::tests::actual_rpc_calls_inspect_caller_token",
                    "--nocapture",
                ])
                .env(CHILD, "1"),
        );
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    run_powershell_probe(true);
}

fn run_powershell_probe(inspect_caller: bool) {
    use windows::Win32::System::Com::{CoTaskMemFree, CreateBindCtx, CreateObjrefMoniker};
    let (local, peer) = if inspect_caller {
        ("127.0.0.216", "127.0.0.217")
    } else {
        ("127.0.0.214", "127.0.0.215")
    };
    let mut options = Options::new(local.parse().unwrap(), peer.parse().unwrap());
    options.multihop = true;
    options.mode = crate::config::Mode::Multihop;
    options.discriminator = Some(7);
    let authentication = options.validate().unwrap();
    let mut log = Logger::open(&options).unwrap();
    let engine = Engine::open(options, authentication, &mut log).unwrap();
    // This branch runs only in a fresh child process; match the service's
    // permanent privilege removal before accepting any COM caller.
    crate::runtime::drop_privileges().unwrap();
    let host = if inspect_caller {
        StatusComServer::start_caller_fixture(engine.status_observer())
    } else {
        StatusComServer::start_fixture(engine.status_observer())
    }
    .unwrap();
    // SAFETY: test thread balances its own apartment after its COM references drop.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .unwrap();
    let factory: IClassFactory = StatusFactory {
        observer: engine.status_observer(),
    }
    .into();
    // SAFETY: the factory remains live through child calls; Windows owns moniker.
    let moniker = unsafe { CreateObjrefMoniker(&factory) }.unwrap();
    // SAFETY: no reserved arguments and all returned references stay in this MTA.
    let context = unsafe { CreateBindCtx(0) }.unwrap();
    // SAFETY: live context and moniker; no left-hand moniker is needed.
    let name = unsafe { moniker.GetDisplayName(&context, None) }.unwrap();
    // SAFETY: COM returned an allocated terminated UTF-16 name.
    let name_text = unsafe { name.to_string() }.unwrap();
    // SAFETY: name came from GetDisplayName and is freed exactly once.
    unsafe { CoTaskMemFree(Some(name.0.cast())) };
    let output = command_output(
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                include_str!("../../tests/status_com_probe.ps1"),
            ])
            .env("BFD_TEST_STATUS_MONIKER", name_text),
    );
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    if inspect_caller {
        let inspected = CALLER_TOKEN_INSPECTIONS.load(Ordering::Relaxed);
        assert!(
            inspected > 0,
            "native transport denial occurred before the production caller-token guard: {stdout}"
        );
        println!("RPC_CALLER_TOKEN_INSPECTIONS: {inspected}");
    }
    if std::env::var_os("BFD_TEST_REQUIRE_STATUS_AUTHORIZED").is_some() {
        assert!(
            stdout.contains("STATUS_COM_ALLOWED"),
            "authorized COM output required, but caller was denied: {stdout}"
        );
    }
    assert!(
        stdout.contains("STATUS_COM_ALLOWED") || stdout.contains("STATUS_COM_DENIED"),
        "{stdout}"
    );
    println!("{stdout}");
    drop(context);
    drop(moniker);
    drop(factory);
    // SAFETY: successful initialization occurred above on this same thread.
    unsafe { CoUninitialize() };
    host.shutdown().unwrap();
}

fn sample() -> Arc<StatusSnapshot> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SERIAL.lock().unwrap();
    let mut options = Options::new(
        "127.0.0.210".parse().unwrap(),
        "127.0.0.211".parse().unwrap(),
    );
    options.multihop = true;
    options.mode = crate::config::Mode::Multihop;
    options.discriminator = Some(7);
    let authentication = options.validate().unwrap();
    let mut log = Logger::open(&options).unwrap();
    let engine = Engine::open(options, authentication, &mut log).unwrap();
    engine.status_observer().snapshot().unwrap()
}

#[test]
fn automation_properties_are_typed_and_exclude_unrequested_metadata() {
    let snapshot = sample();
    let fields = property_values(&snapshot).unwrap();
    assert_eq!(fields.len(), SNAPSHOT_MEMBERS.len());
    for omitted in [
        "SnapshotAge",
        "ReceiveAgeAtCapture",
        "PublishInterval",
        "BgpControlEnabled",
        "CapturedAtUtc",
        "SchemaVersion",
        "ServiceStatus",
    ] {
        assert!(!SNAPSHOT_MEMBERS.iter().any(|member| member.name == omitted));
    }
    let get = |name: &str| {
        &fields[SNAPSHOT_MEMBERS
            .iter()
            .position(|member| member.name == name)
            .unwrap()]
    };
    assert_eq!(get("LocalAddress").vt(), VT_BSTR);
    assert_eq!(get("LocalState").vt(), VT_BSTR);
    assert_eq!(get("LocalDiscriminator").vt(), VT_UI4);
    assert_eq!(u32::try_from(get("LocalDiscriminator")).unwrap(), 7);
    assert_eq!(get("PacketsReceivedAccepted").vt(), VT_UI8);
    assert_eq!(get("Passive").vt(), VT_BOOL);
    assert_eq!(get("LastValidReceiveUtc").vt(), VT_EMPTY);
    assert_eq!(get("StateSinceUtc").vt(), VT_DATE);
    assert_eq!(get("ConfiguredMinTxIntervalMicroseconds").vt(), VT_UI8);
}

#[test]
fn allowed_peers_round_trip_as_a_native_bstr_array() {
    use windows::{
        core::BSTR,
        Win32::System::Ole::{
            SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
            SafeArrayGetVartype,
        },
    };
    let mut snapshot = (*sample()).clone();
    snapshot.allowed_peers = Arc::from([
        "192.0.2.11".parse::<std::net::IpAddr>().unwrap(),
        "2001:db8::11".parse::<std::net::IpAddr>().unwrap(),
    ]);
    let index = SNAPSHOT_MEMBERS
        .iter()
        .position(|member| member.name == "AllowedPeers")
        .unwrap();
    let value = property_value(&snapshot, index).unwrap();
    assert_eq!(value.vt(), VARENUM(VT_ARRAY.0 | VT_BSTR.0));
    // SAFETY: the matching VT_ARRAY|VT_BSTR tag establishes the active union
    // member. value owns the array and remains alive through every access.
    let array = unsafe { value.Anonymous.Anonymous.Anonymous.parray };
    assert!(!array.is_null());
    // SAFETY: the live native array owns its bounds and declared element type.
    unsafe {
        assert_eq!(SafeArrayGetDim(array), 1);
        assert_eq!(SafeArrayGetVartype(array).unwrap(), VT_BSTR);
        assert_eq!(SafeArrayGetLBound(array, 1).unwrap(), 0);
        assert_eq!(SafeArrayGetUBound(array, 1).unwrap(), 1);
    }
    for (index, expected) in snapshot.allowed_peers.iter().enumerate() {
        let index = i32::try_from(index).unwrap();
        let mut element = BSTR::default();
        // SAFETY: index is within the bounds verified above and the writable
        // BSTR output owns the element copy returned by SafeArrayGetElement.
        unsafe { SafeArrayGetElement(array, &index, ptr::from_mut(&mut element).cast()) }.unwrap();
        assert_eq!(element.to_string(), expected.to_string());
    }
}

#[test]
fn type_information_lists_read_only_snapshot_properties() {
    // SAFETY: this test thread balances its COM apartment initialization.
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .unwrap();
    let info = type_information(SNAPSHOT_MEMBERS, 0).unwrap();
    // SAFETY: type information is live and Windows owns returned descriptors.
    let attributes = unsafe { info.GetTypeAttr() }.unwrap();
    // SAFETY: GetTypeAttr returned a valid descriptor retained until release.
    let count = unsafe { (*attributes).cFuncs };
    // SAFETY: attributes remains valid until its release below.
    assert_eq!(unsafe { (*attributes).guid }, SNAPSHOT_TYPE_ID);
    assert_eq!(usize::from(count), SNAPSHOT_MEMBERS.len());
    for (index, member) in SNAPSHOT_MEMBERS.iter().enumerate() {
        // SAFETY: the index is in range and info remains alive.
        let function = unsafe { info.GetFuncDesc(u32::try_from(index).unwrap()) }
            .unwrap_or_else(|error| panic!("{}: {error}", member.name));
        // SAFETY: GetFuncDesc returned a descriptor retained until release.
        assert_eq!(unsafe { (*function).invkind }, INVOKE_PROPERTYGET);
        // SAFETY: function descriptor remains valid until release below.
        assert_eq!(unsafe { (*function).elemdescFunc.tdesc.vt }, member.kind);
        // SAFETY: function descriptor is live and contains this member's ID.
        let id = unsafe { (*function).memid };
        let mut names = [windows::core::BSTR::default()];
        let mut count = 0;
        // SAFETY: one writable BSTR slot and valid count output; native type
        // information owns copied metadata after builder buffers have dropped.
        unsafe { info.GetNames(id, &mut names, &mut count) }.unwrap();
        assert_eq!(count, 1);
        assert_eq!(names[0].to_string(), member.name);
        let mut documentation_name = windows::core::BSTR::default();
        let mut help_context = 0;
        // SAFETY: valid member ID and writable owned BSTR/context outputs.
        unsafe {
            info.GetDocumentation(
                id,
                Some(&mut documentation_name),
                None,
                &mut help_context,
                None,
            )
        }
        .unwrap();
        assert_eq!(documentation_name.to_string(), member.name);
        // SAFETY: releasing exactly the descriptor returned above.
        unsafe { info.ReleaseFuncDesc(function) };
    }
    // SAFETY: releasing the descriptor returned above.
    unsafe { info.ReleaseTypeAttr(attributes) };
    drop(info);
    // SAFETY: successful initialization occurred on this test thread.
    unsafe { CoUninitialize() };
}

#[test]
fn calls_without_authenticated_com_context_are_denied() {
    let object: IDispatch = SnapshotObject { snapshot: sample() }.into();
    // SAFETY: interface is valid; no pointers are supplied for this method.
    let error = unsafe { object.GetTypeInfoCount() }.unwrap_err();
    assert_eq!(error.code(), E_ACCESSDENIED);
}

#[test]
fn null_dispatch_name_is_rejected_before_utf16_conversion() {
    let iid = GUID::zeroed();
    let name = PCWSTR::null();
    let mut id = 0;
    let error = dispatch_ids(SNAPSHOT_MEMBERS, &iid, &name, 1, &mut id).unwrap_err();
    assert_eq!(error.code(), E_POINTER);
}

#[implement(IServerSecurity)]
struct RevertProbe {
    attempts: Arc<std::sync::atomic::AtomicU32>,
    fails: bool,
}

impl windows::Win32::System::Com::IServerSecurity_Impl for RevertProbe_Impl {
    fn QueryBlanket(
        &self,
        _: *mut u32,
        _: *mut u32,
        _: *mut *mut u16,
        _: *mut u32,
        _: *mut u32,
        _: *mut *mut c_void,
        _: *mut u32,
    ) -> Result<()> {
        Err(windows::Win32::Foundation::E_NOTIMPL.into())
    }

    fn ImpersonateClient(&self) -> Result<()> {
        Err(windows::Win32::Foundation::E_NOTIMPL.into())
    }

    fn RevertToSelf(&self) -> Result<()> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.fails {
            Err(windows::Win32::Foundation::E_FAIL.into())
        } else {
            Ok(())
        }
    }

    fn IsImpersonating(&self) -> BOOL {
        BOOL(0)
    }
}

#[test]
fn explicit_identity_revert_is_checked_and_drop_is_only_a_fallback() {
    for fails in [false, true] {
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let security: IServerSecurity = RevertProbe {
            attempts: attempts.clone(),
            fails,
        }
        .into();
        let result = CallerImpersonation(Some(security)).revert();
        if fails {
            assert_eq!(result.unwrap_err().code(), E_ACCESSDENIED);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
        } else {
            assert!(result.is_ok());
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn com_host_has_balanced_lifetime_and_security_cannot_be_reset() {
    const CHILD: &str = "BFD_TEST_STATUS_COM_HOST";
    if std::env::var_os(CHILD).is_none() {
        let output = command_output(Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "status_com::tests::com_host_has_balanced_lifetime_and_security_cannot_be_reset",
                "--nocapture",
            ])
            .env(CHILD, "1"));
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut options = Options::new(
        "127.0.0.212".parse().unwrap(),
        "127.0.0.213".parse().unwrap(),
    );
    options.multihop = true;
    options.mode = crate::config::Mode::Multihop;
    let authentication = options.validate().unwrap();
    let mut log = Logger::open(&options).unwrap();
    let engine = Engine::open(options, authentication, &mut log).unwrap();
    let observer = engine.status_observer();
    let host = StatusComServer::start_fixture(observer.clone()).unwrap();
    assert!(StatusComServer::start_fixture(observer).is_err());
    host.shutdown().unwrap();
}

#[test]
fn current_token_membership_matches_windows_identity() {
    let mut token = HANDLE::default();
    // SAFETY: querying the current process pseudo-handle with a valid output.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    }
    .unwrap();
    let token = TokenHandle(token);
    let mut impersonation = HANDLE::default();
    // SAFETY: duplicating our owned process token with identify level only.
    unsafe {
        DuplicateTokenEx(
            token.0,
            TOKEN_QUERY,
            None,
            SecurityIdentification,
            TokenImpersonation,
            &mut impersonation,
        )
    }
    .unwrap();
    let impersonation = TokenHandle(impersonation);
    let authorized = authorized_token(impersonation.0).unwrap();
    let output = command_output(Command::new("powershell.exe").args(["-NoProfile", "-Command", "$i=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=[Security.Principal.WindowsPrincipal]::new($i); [bool]($i.IsSystem -or $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"]));
    assert!(output.status.success());
    assert_eq!(
        authorized,
        String::from_utf8_lossy(&output.stdout).trim() == "True"
    );
}

#[test]
fn deny_only_administrator_sid_does_not_authorize_querying() {
    use windows::Win32::Security::{
        CreateRestrictedToken, CREATE_RESTRICTED_TOKEN_FLAGS, SID_AND_ATTRIBUTES,
    };
    let mut token = HANDLE::default();
    // SAFETY: querying the current process token into valid owned output storage.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    }
    .unwrap();
    let token = TokenHandle(token);
    let mut storage = [0usize; 9];
    let sid = PSID(storage.as_mut_ptr().cast());
    let mut length = u32::try_from(std::mem::size_of_val(&storage)).unwrap();
    // SAFETY: aligned writable storage is large enough for the built-in SID.
    unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(sid), &mut length) }
        .unwrap();
    let attributes = token_group_attributes(token.0, sid);
    // SE_GROUP_USE_FOR_DENY_ONLY from winnt.h; an actual filtered token can
    // contain the Administrator SID even when enabled-membership is false.
    const DENY_ONLY: u32 = 0x10;
    let Some(attributes) = attributes else {
        println!("NOT_EXERCISED: deny-only Administrator boundary; current token has no Administrator SID");
        assert!(std::env::var_os("BFD_TEST_REQUIRE_STATUS_DENY_ONLY").is_none(), "deny-only Administrator coverage required, but the starting token has no Administrator SID");
        return;
    };
    if attributes & DENY_ONLY != 0 {
        let is_system = assert_deny_only_administrator(token.0, sid);
        println!("EXERCISED: current filtered Administrator SID denied; SYSTEM authorization={is_system}");
        return;
    }
    let mut restricted = HANDLE::default();
    // SAFETY: owned process token and SID live through native restriction call;
    // the new token is owned by this test and never applied to the process.
    unsafe {
        CreateRestrictedToken(
            token.0,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&[SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0,
            }]),
            None,
            None,
            &mut restricted,
        )
    }
    .unwrap();
    let restricted = TokenHandle(restricted);
    assert!(token_group_attributes(restricted.0, sid)
        .is_some_and(|attributes| attributes & DENY_ONLY != 0));
    let is_system = assert_deny_only_administrator(restricted.0, sid);
    println!("EXERCISED: Administrator SID disabled by CreateRestrictedToken and denied; SYSTEM authorization={is_system}");
}

fn token_group_attributes(token: HANDLE, sid: PSID) -> Option<u32> {
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, TokenGroups, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
    };
    let mut required = 0;
    // SAFETY: zero-length query requests the required TOKEN_GROUPS buffer size.
    let error =
        unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut required) }.unwrap_err();
    assert_eq!(
        error.code(),
        windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER.0)
    );
    let mut storage = vec![
        0u64;
        usize::try_from(required)
            .unwrap()
            .div_ceil(std::mem::size_of::<u64>())
    ];
    // SAFETY: u64 storage supplies TOKEN_GROUPS alignment and required capacity.
    unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            Some(storage.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .unwrap();
    let group_pointer = storage.as_ptr().cast::<TOKEN_GROUPS>();
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    assert!(usize::try_from(required).unwrap() >= offset);
    // SAFETY: native buffer contains the initialized GroupCount header.
    let count = unsafe { ptr::addr_of!((*group_pointer).GroupCount).read() };
    let count = usize::try_from(count).unwrap();
    assert!(
        offset + count * std::mem::size_of::<SID_AND_ATTRIBUTES>()
            <= usize::try_from(required).unwrap()
    );
    // SAFETY: validated count fits within the native buffer. addr_of! avoids
    // creating a reference to the flexible-array header or its one-entry tail.
    let entries = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*group_pointer).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    entries.iter().find_map(|entry| {
        // SAFETY: native group SIDs point into live token-information storage;
        // the comparison SID belongs to the caller and remains allocated.
        unsafe { EqualSid(entry.Sid, sid) }
            .is_ok()
            .then_some(entry.Attributes)
    })
}

fn assert_deny_only_administrator(token: HANDLE, sid: PSID) -> bool {
    let mut impersonation = HANDLE::default();
    // SAFETY: create a query-only identify token for membership checking.
    unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY,
            None,
            SecurityIdentification,
            TokenImpersonation,
            &mut impersonation,
        )
    }
    .unwrap();
    let impersonation = TokenHandle(impersonation);
    let mut administrator = BOOL::default();
    // SAFETY: token and SID are valid and membership result is writable.
    unsafe { CheckTokenMembership(Some(impersonation.0), sid, &mut administrator) }.unwrap();
    assert!(!administrator.as_bool());
    // SYSTEM remains authorized independently; ordinary user/admin tokens with
    // the Administrator SID disabled must have no administrative query access.
    let mut system_storage = [0usize; 9];
    let system_sid = PSID(system_storage.as_mut_ptr().cast());
    let mut system_length = u32::try_from(std::mem::size_of_val(&system_storage)).unwrap();
    // SAFETY: aligned storage and valid native SID output length.
    unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            Some(system_sid),
            &mut system_length,
        )
    }
    .unwrap();
    let mut system = BOOL::default();
    // SAFETY: checking a valid identification token against the initialized SID.
    unsafe { CheckTokenMembership(Some(impersonation.0), system_sid, &mut system) }.unwrap();
    assert_eq!(authorized_token(impersonation.0).unwrap(), system.as_bool());
    system.as_bool()
}
