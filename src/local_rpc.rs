//! Mutually authenticated BFD session telemetry over private local RPC.
//!
//! Windows authenticates both process tokens. The broker pins both LocalService
//! and the BFD service SID through the RPC runtime's server security descriptor.
//! The server admits only the broker service SID and checks SYSTEM plus that SID
//! on every call, without impersonating the broker or enabling privileges.
#![allow(unsafe_code)]

pub(crate) mod identity;
pub(crate) mod monitor;
mod status;
pub use monitor::{cached_bfd_session_status, BrokerStatus};
pub use status::{SessionStatus, SessionStatusQueryError};

use crate::bgp::ipc::{BROKER_SID, SERVICE_SID};
use crate::runtime::StatusObserver;
use status::WireStatus;
use std::{
    ffi::c_void,
    io, ptr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        OnceLock,
    },
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_BUSY, ERROR_INVALID_DATA, ERROR_NOT_READY},
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
        SDDL_REVISION_1,
    },
    System::{
        Com::{RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY},
        Rpc::{
            RpcBindingCreateW, RpcBindingFree, RpcBindingSetOption, RpcBindingUnbind,
            RpcMgmtSetAuthorizationFn, RpcServerRegisterAuthInfoW, RpcServerRegisterIf3,
            RpcServerUnregisterIf, RpcServerUseProtseqEpW, RPC_BHO_DONTLINGER,
            RPC_BINDING_HANDLE_OPTIONS_V1, RPC_BINDING_HANDLE_SECURITY_V1_W,
            RPC_BINDING_HANDLE_TEMPLATE_V1_W, RPC_C_AUTHN_WINNT, RPC_C_BINDING_DEFAULT_TIMEOUT,
            RPC_C_OPT_UNIQUE_BINDING, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
            RPC_C_QOS_IDENTITY_STATIC, RPC_IF_ALLOW_LOCAL_ONLY, RPC_IF_ALLOW_SECURE_ONLY,
            RPC_IF_AUTOLISTEN, RPC_IF_SEC_NO_CACHE, RPC_PROTSEQ_LRPC, RPC_SECURITY_QOS_V5_W,
            RPC_S_OK,
        },
    },
};

const ENDPOINT: &str = "BfdWinService.Local.v2";
const LOCAL_SERVICE: &str = "S-1-5-19";
const SYSTEM: &str = "S-1-5-18";
const MAX_CALLS: u32 = 8;
const CALL_TIMEOUT_MS: u32 = 2_000;

extern "C" {
    fn bfd_rpc_server_interface() -> *mut c_void;
    fn bfd_rpc_bind(binding: *mut c_void, timeout_ms: u32) -> u32;
    fn bfd_rpc_call_status(binding: *mut c_void, timeout_ms: u32, output: *mut WireStatus) -> u32;
}

struct Policy {
    user: String,
    group: String,
    observer: Option<StatusObserver>,
}

// RPC registration/endpoint state is process-wide and cannot be fully reset.
// Never allow a second registration attempt with different identity policy.
static POLICY: OnceLock<Policy> = OnceLock::new();
static STATUS_CALLS: AtomicUsize = AtomicUsize::new(0);
static CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
static TEST_STATUS_DELAY_MS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(test)]
static TEST_STATUS_CORRUPT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Owns this process's private, automatically listened RPC interface.
/// Dropping it unregisters only this interface and drains its active calls.
pub struct LocalRpcServer {
    _descriptor: LocalAllocation,
}

impl LocalRpcServer {
    /// Starts the installed BFD service's broker-only local RPC interface.
    ///
    /// # Errors
    /// Fails closed on an unexpected process identity, endpoint collision,
    /// duplicate registration, or RPC security setup error.
    pub fn start(observer: StatusObserver) -> io::Result<Self> {
        crate::service_identity::verify_bfd_service_identity()?;
        Self::with_status_policy(ENDPOINT, SYSTEM, BROKER_SID, Some(observer))
    }

    fn with_status_policy(
        endpoint: &str,
        user: &str,
        group: &str,
        observer: Option<StatusObserver>,
    ) -> io::Result<Self> {
        let descriptor = LocalAllocation::descriptor(&format!("D:P(A;;GA;;;{group})"))?;
        POLICY
            .set(Policy {
                user: user.to_owned(),
                group: group.to_owned(),
                observer,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "RPC already initialized"))?;
        // SAFETY: MIDL supplies this static interface descriptor.
        let interface = unsafe { bfd_rpc_server_interface() };
        // SAFETY: policy/callback live for the process; descriptor survives unregister.
        unsafe { register_interface(endpoint, descriptor.0, interface, Some(authorize)) }?;
        Ok(Self {
            _descriptor: descriptor,
        })
    }
}

/// # Safety
/// Interface/callback must remain live until unregister; descriptor must outlive registration.
// Both private interfaces use the same runtime gates. Management is denied in
// either host; AUTOLISTEN leaves the provider's COM listen lifecycle alone.
pub(crate) unsafe fn register_interface(
    endpoint: &str,
    descriptor: *const c_void,
    interface: *const c_void,
    callback: windows_sys::Win32::System::Rpc::RPC_IF_CALLBACK_FN,
) -> io::Result<()> {
    // SAFETY: this static callback denies every runtime management request.
    // Install it before opening an endpoint: the application interface's
    // descriptor/callback does not protect the separate management interface.
    check(unsafe { RpcMgmtSetAuthorizationFn(Some(deny_management)) })?;
    let protocol = wide("ncalrpc");
    let endpoint = wide(endpoint);
    // SAFETY: valid terminated protocol/endpoint and live native descriptor.
    // Only LRPC is registered; a collision is an error, never a fallback.
    check(unsafe {
        RpcServerUseProtseqEpW(protocol.as_ptr(), MAX_CALLS, endpoint.as_ptr(), descriptor)
    })?;
    // SAFETY: WINNT is the ncalrpc authentication provider; the runtime uses
    // this process's identity. There is no custom key callback or credential.
    check(unsafe {
        RpcServerRegisterAuthInfoW(ptr::null(), RPC_C_AUTHN_WINNT, None, ptr::null())
    })?;
    // SAFETY: MIDL owns the static interface description. The descriptor is
    // retained through unregister, and the callback/policy live for the process.
    // AUTOLISTEN avoids changing the process-wide COM/RPC listen lifecycle.
    check(unsafe {
        RpcServerRegisterIf3(
            interface,
            ptr::null(),
            ptr::null(),
            RPC_IF_AUTOLISTEN
                | RPC_IF_ALLOW_LOCAL_ONLY
                | RPC_IF_ALLOW_SECURE_ONLY
                | RPC_IF_SEC_NO_CACHE,
            MAX_CALLS,
            0, // LRPC ignores MaxRpcSize. The status record is fixed-size.
            callback,
            descriptor,
        )
    })?;
    Ok(())
}

struct StatusPermit;
impl StatusPermit {
    fn acquire() -> Option<Self> {
        STATUS_CALLS
            .try_update(Ordering::Acquire, Ordering::Relaxed, |count| {
                (count < 4).then_some(count + 1)
            })
            .ok()
            .map(|_| Self)
    }
}
impl Drop for StatusPermit {
    fn drop(&mut self) {
        STATUS_CALLS.fetch_sub(1, Ordering::Release);
    }
}

/// # Safety
/// The MIDL manager supplies exclusive writable storage for a complete record.
#[no_mangle]
unsafe extern "C" fn bfd_rpc_get_session_status(
    binding: *const c_void,
    output: *mut WireStatus,
) -> u32 {
    if output.is_null() {
        return ERROR_INVALID_DATA;
    }
    // SAFETY: MIDL supplies a live, exclusive output record for this call.
    unsafe {
        output.write(WireStatus::default());
    }
    let authorized = authorize_call(binding);
    if authorized != RPC_S_OK {
        return authorized as u32;
    }
    let Some(_permit) = StatusPermit::acquire() else {
        return ERROR_BUSY;
    };
    let Some(snapshot) = POLICY
        .get()
        .and_then(|p| p.observer.as_ref())
        .and_then(StatusObserver::snapshot)
    else {
        return ERROR_NOT_READY;
    };
    #[cfg(test)]
    std::thread::sleep(std::time::Duration::from_millis(u64::from(
        TEST_STATUS_DELAY_MS.load(Ordering::Relaxed),
    )));
    let Ok(record) = WireStatus::capture(&snapshot, Instant::now()) else {
        return ERROR_INVALID_DATA;
    };
    #[cfg(test)]
    let record = match TEST_STATUS_CORRUPT.load(Ordering::Relaxed) {
        1 => WireStatus {
            communicating: 2,
            ..record
        },
        2 => WireStatus { size: 1, ..record },
        _ => record,
    };
    // SAFETY: output remains exclusively owned by this call; record contains only integers.
    unsafe {
        output.write(record);
    }
    RPC_S_OK as u32
}

impl Drop for LocalRpcServer {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns registration of this MIDL interface.
        // Wait for dispatch/callbacks to finish before releasing descriptor storage.
        if unsafe { RpcServerUnregisterIf(bfd_rpc_server_interface(), ptr::null(), 1) } != RPC_S_OK
        {
            // Continuing could retain a listener after its security storage died.
            std::process::abort();
        }
    }
}

/// # Safety
/// RPC supplies the live current-call binding while this callback runs.
unsafe extern "system" fn authorize(_: *const c_void, binding: *const c_void) -> i32 {
    authorize_call(binding)
}

/// # Safety
/// RPC supplies a writable status pointer, if non-null, for this callback only.
unsafe extern "system" fn deny_management(_: *const c_void, _: u32, status: *mut i32) -> i32 {
    if !status.is_null() {
        // SAFETY: the runtime provides this writable output for the callback.
        unsafe { status.write(ERROR_ACCESS_DENIED as i32) };
    }
    // Deny all operation numbers, including future management operations. Keep
    // this process-wide policy after unregister; endpoints last until exit.
    0
}

// Shared by the status manager and security callback. No untrusted parameters
// are dereferenced here and no panic crosses the native boundary.
fn authorize_call(binding: *const c_void) -> i32 {
    let Some(policy) = POLICY.get() else {
        return ERROR_ACCESS_DENIED as i32;
    };
    match identity::authorize_call(binding, &policy.user, &policy.group) {
        Ok(()) => RPC_S_OK,
        Err(_) => ERROR_ACCESS_DENIED as i32,
    }
}

/// Fetches one coherent session observation using the broker's fixed BFD policy.
/// Call on a worker; native deadlines/cancellation must not block provider work.
///
/// # Errors
/// Rejects unexpected broker identity, failed RPC/security, or invalid status data.
pub fn query_bfd_session_status() -> Result<SessionStatus, SessionStatusQueryError> {
    crate::bgp::ipc::require_broker_identity()?;
    if monitor::quarantined() {
        return Err(SessionStatusQueryError::Quarantined);
    }
    let _permit = QueryPermit::acquire()?;
    query_with_policy(ENDPOINT, LOCAL_SERVICE, SERVICE_SID)
}

struct QueryPermit;
impl QueryPermit {
    fn acquire() -> io::Result<Self> {
        CLIENT_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| io::Error::from_raw_os_error(ERROR_BUSY as i32))
    }
}
impl Drop for QueryPermit {
    fn drop(&mut self) {
        CLIENT_ACTIVE.store(false, Ordering::Release);
    }
}

fn query_with_policy(
    endpoint: &str,
    user: &str,
    group: &str,
) -> Result<SessionStatus, SessionStatusQueryError> {
    let mut record = WireStatus::default();
    with_binding(endpoint, user, group, |binding| {
        // SAFETY: the initialized fixed record and binding outlive native async
        // completion. C contains structured exceptions and never releases pending storage.
        check(unsafe { bfd_rpc_call_status(binding, CALL_TIMEOUT_MS, &mut record) } as i32)
    })?;
    record.try_into()
}

// The BFD-specific expected identity never changes in the broker process.
fn with_binding<T>(
    endpoint: &str,
    server_user: &str,
    server_group: &str,
    call: impl FnOnce(*mut c_void) -> io::Result<T>,
) -> io::Result<T> {
    with_rpc_binding(
        endpoint,
        server_user,
        server_group,
        bfd_rpc_bind,
        CALL_TIMEOUT_MS,
        retain_uncertain_binding,
        call,
    )
}

pub(crate) fn with_rpc_binding<T>(
    endpoint: &str,
    server_user: &str,
    server_group: &str,
    bind: unsafe extern "C" fn(*mut c_void, u32) -> u32,
    timeout_ms: u32,
    uncertain: fn() -> !,
    call: impl FnOnce(*mut c_void) -> io::Result<T>,
) -> io::Result<T> {
    // A single conditional ACE requires BOTH SIDs. Separate allow ACEs would
    // permit any LocalService process OR any token containing the service SID.
    // QOS.Sid alone checks the account and does not pin the service SID group.
    let descriptor = LocalAllocation::descriptor(&format!(
        "D:(XA;;GA;;;WD;(Member_of {{SID({server_user}), SID({server_group})}}))"
    ))?;
    let account = LocalAllocation::sid(server_user)?;
    let mut endpoint = wide(endpoint);
    let mut qos = RPC_SECURITY_QOS_V5_W {
        Version: 5,
        Capabilities: RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH,
        IdentityTracking: RPC_C_QOS_IDENTITY_STATIC,
        ImpersonationType: RPC_C_IMP_LEVEL_IDENTIFY,
        Sid: account.0,
        EffectiveOnly: 1,
        ServerSecurityDescriptor: descriptor.0,
        ..Default::default()
    };
    let template = RPC_BINDING_HANDLE_TEMPLATE_V1_W {
        Version: 1,
        ProtocolSequence: RPC_PROTSEQ_LRPC,
        StringEndpoint: endpoint.as_mut_ptr(),
        ..Default::default()
    };
    let security = RPC_BINDING_HANDLE_SECURITY_V1_W {
        Version: 1,
        AuthnLevel: RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        AuthnSvc: RPC_C_AUTHN_WINNT,
        SecurityQos: ptr::from_mut(&mut qos).cast(),
        ..Default::default()
    };
    let options = RPC_BINDING_HANDLE_OPTIONS_V1 {
        Version: 1,
        Flags: RPC_BHO_DONTLINGER,
        ComTimeout: RPC_C_BINDING_DEFAULT_TIMEOUT,
        CallTimeout: 0, // Ignored for LRPC. Native async operations enforce deadlines.
    };
    let mut raw = ptr::null_mut();
    // SAFETY: initialized native template/security/QOS and writable output. All
    // borrowed buffers outlive binding disposal. NULL AuthIdentity supplies the
    // process credentials; creating a fast binding performs no communication.
    check(unsafe { RpcBindingCreateW(&template, &security, &options, &mut raw) })?;
    let mut binding = Binding {
        raw,
        bound: false,
        uncertain,
    };
    // SAFETY: exclusively owned fast binding. Keep the private BFD connection
    // separate from the broker's provider RPC associations.
    check(unsafe { RpcBindingSetOption(binding.raw, RPC_C_OPT_UNIQUE_BINDING, 1) })?;
    // SAFETY: live fast binding; C retains async state until completion/cancel.
    check(unsafe { bind(binding.raw, timeout_ms) } as i32)?;
    binding.bound = true;
    call(binding.raw)
}

// Only the single supervised RPC worker can reach this path in production.
// Retaining its stack keeps every borrowed allocation live without terminating
// the provider process. The monitor times out and disables further fetches.
fn retain_uncertain_binding() -> ! {
    loop {
        std::thread::park();
    }
}

struct Binding {
    raw: *mut c_void,
    bound: bool,
    uncertain: fn() -> !,
}
impl Drop for Binding {
    fn drop(&mut self) {
        // SAFETY: owns the single fast binding returned by CreateW. It is
        // released before the QOS SID/descriptor allocations leave their scope.
        if self.bound {
            // SAFETY: synchronous native wrappers have completed every async
            // operation before returning, so no outstanding call uses the binding.
            if unsafe { RpcBindingUnbind(self.raw) } != RPC_S_OK {
                // The runtime's ownership is uncertain. Do not release borrowed
                // security storage in a process that might retain this binding.
                (self.uncertain)();
            }
        }
        // SAFETY: the unique binding is no longer bound or used by any call.
        if unsafe { RpcBindingFree(&mut self.raw) } != RPC_S_OK {
            (self.uncertain)();
        }
    }
}

pub(crate) struct LocalAllocation(pub(crate) *mut c_void);
impl LocalAllocation {
    pub(crate) fn descriptor(sddl: &str) -> io::Result<Self> {
        let text = wide(sddl);
        let mut raw = ptr::null_mut();
        // SAFETY: valid terminated input and writable descriptor output;
        // successful conversion transfers one LocalFree-owned allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(raw))
    }

    fn sid(value: &str) -> io::Result<Self> {
        let text = wide(value);
        let mut raw = ptr::null_mut();
        // SAFETY: valid terminated SID and writable allocation output.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(raw))
    }
}
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: owns one successful SID or security descriptor conversion.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

pub(crate) fn check(status: i32) -> io::Result<()> {
    if status == RPC_S_OK {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
fn native_status_layout(field: u32) -> u32 {
    extern "C" {
        fn bfd_rpc_status_layout(field: u32) -> u32;
    }
    // SAFETY: the native helper returns compile-time layout constants only.
    unsafe { bfd_rpc_status_layout(field) }
}
