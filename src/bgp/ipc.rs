//! Fixed-target BGP control over mutually authenticated local RPC.
//! Shares the telemetry channel's binding policy, runtime gates and Authz checks.
#![allow(unsafe_code)]

use super::Method;
use crate::{local_rpc, runtime::StopSignal};
use std::{
    ffi::c_void,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ACCESS_DENIED, ERROR_BUSY, ERROR_INVALID_DATA, ERROR_NOT_FOUND,
        ERROR_OPERATION_ABORTED, ERROR_SERVICE_NOT_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0,
    },
    System::{
        Rpc::{RpcServerTestCancel, RpcServerUnregisterIf, RPC_S_CALL_IN_PROGRESS, RPC_S_OK},
        Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE},
    },
};

pub(crate) const SERVICE_SID: &str =
    "S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512";
pub(crate) const BROKER_SID: &str = "S-1-5-80-3301813337-1731295767-1225795713-3993009034-49020719";
pub(crate) const BROKER_NAME: &str = "BfdBgpBroker";
const ENDPOINT: &str = "BfdWinService.Bgp.v2";
const CALL_TIMEOUT_MS: u32 = 30_000;
const SHUTDOWN_TIMEOUT_MS: u32 = 20_000;
const BIND_TIMEOUT_MS: u32 = 2_000;
pub(crate) const NOT_CONFIGURED: u32 = ERROR_NOT_FOUND;

extern "C" {
    fn bgp_rpc_server_interface() -> *mut c_void;
    fn bgp_rpc_bind(binding: *mut c_void, timeout_ms: u32) -> u32;
    fn bgp_rpc_call(
        binding: *mut c_void,
        timeout_ms: u32,
        cancel: *mut c_void,
        operation: u32,
        output: *mut WireResult,
    ) -> u32;
}

#[repr(C)]
#[derive(Default, Debug)]
struct WireResult {
    status: u32,
    value: u32,
}

pub(crate) fn require_broker_identity() -> io::Result<()> {
    let token = crate::service_identity::process_token()?;
    crate::service_identity::require_identity(token.as_raw_handle(), BROKER_SID, "S-1-5-18")
}

struct Policy {
    user: String,
    group: String,
    sender: RequestSender,
    stop: StopSignal,
}

// Endpoint and identity policy stay fixed for the process lifetime, as for telemetry.
static POLICY: OnceLock<Policy> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub(crate) struct Request {
    pub(crate) method: Method,
    response: SyncSender<(u32, u32)>,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl Request {
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
    pub(crate) fn respond(self, status: u32, value: u32) {
        // A timed-out/disconnected caller cannot block the provider worker.
        let _ = self.response.try_send((status, value));
    }
}

struct RequestSender {
    sender: SyncSender<Request>,
    ready: Arc<OwnedHandle>,
}

impl RequestSender {
    fn try_send(&self, request: Request) -> Result<(), u32> {
        self.sender.try_send(request).map_err(|_| ERROR_BUSY)?;
        // SAFETY: the shared event remains owned throughout notification.
        if unsafe { SetEvent(self.ready.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error()
                .raw_os_error()
                .map_or(ERROR_SERVICE_NOT_ACTIVE, |code| code as u32));
        }
        Ok(())
    }
}

struct Dispatcher {
    receiver: Receiver<Request>,
    ready: Arc<OwnedHandle>,
}

impl Dispatcher {
    fn new() -> io::Result<(RequestSender, Self)> {
        // SAFETY: creates a private, initially clear auto-reset event; no pointers retained.
        let raw = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transfers this new handle into RAII ownership.
        let ready = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw) });
        let (sender, receiver) = mpsc::sync_channel(1);
        Ok((
            RequestSender {
                sender,
                ready: Arc::clone(&ready),
            },
            Self { receiver, ready },
        ))
    }

    fn request(&self, stop: &StopSignal) -> io::Result<Option<Request>> {
        let handles = [stop.event().as_raw_handle(), self.ready.as_raw_handle()];
        if stop.is_requested() {
            return Ok(None);
        }
        // SAFETY: both handles remain owned for this synchronous wait. Stop is
        // first so it wins when both events are signaled. There is one consumer.
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        if result == WAIT_FAILED {
            return Err(io::Error::last_os_error());
        }
        if result == WAIT_OBJECT_0 || stop.is_requested() {
            return Ok(None);
        }
        if result != WAIT_OBJECT_0 + 1 {
            return Err(io::Error::other("unexpected BGP dispatcher wait result"));
        }
        // Always consume the event before removing the request. The producer
        // enqueues before signaling, so a subsequent enqueue cannot lose its
        // wakeup to this request's auto-reset event consumption.
        self.receiver
            .try_recv()
            .map(Some)
            .map_err(|_| io::Error::other("BGP RPC dispatcher closed"))
    }
}

pub(crate) struct Listener {
    dispatcher: Dispatcher,
    _descriptor: local_rpc::LocalAllocation,
}

impl Listener {
    pub(crate) fn new(stop: StopSignal) -> io::Result<Self> {
        require_broker_identity()?;
        Self::with_policy(ENDPOINT, "S-1-5-19", SERVICE_SID, stop)
    }
    fn with_policy(endpoint: &str, user: &str, group: &str, stop: StopSignal) -> io::Result<Self> {
        let descriptor = local_rpc::LocalAllocation::descriptor(&format!("D:P(A;;GA;;;{group})"))?;
        let (sender, dispatcher) = Dispatcher::new()?;
        POLICY
            .set(Policy {
                user: user.to_owned(),
                group: group.to_owned(),
                sender,
                stop,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::AlreadyExists, "BGP RPC already initialized")
            })?;
        // SAFETY: MIDL owns this static descriptor.
        let interface = unsafe { bgp_rpc_server_interface() };
        // SAFETY: policy/callback live for the process; descriptor survives unregister.
        unsafe {
            local_rpc::register_interface(endpoint, descriptor.0, interface, Some(authorize))
        }?;
        Ok(Self {
            dispatcher,
            _descriptor: descriptor,
        })
    }
    pub(crate) fn request(&self, stop: &StopSignal) -> io::Result<Option<Request>> {
        self.dispatcher.request(stop)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(policy) = POLICY.get() {
            let _ = policy.stop.signal();
        }
        // SAFETY: uniquely owns this interface; drain callbacks before releasing SD.
        if unsafe { RpcServerUnregisterIf(bgp_rpc_server_interface(), ptr::null(), 1) } != RPC_S_OK
        {
            std::process::abort();
        }
    }
}

fn authorize_call(binding: *const c_void) -> u32 {
    let Some(policy) = POLICY.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if local_rpc::identity::authorize_call(binding, &policy.user, &policy.group).is_err() {
        ERROR_ACCESS_DENIED
    } else {
        RPC_S_OK as u32
    }
}

/// # Safety
/// RPC supplies a live current-call binding for the duration of the callback.
unsafe extern "system" fn authorize(_: *const c_void, binding: *const c_void) -> i32 {
    authorize_call(binding) as i32
}

struct ActiveCall;
impl Drop for ActiveCall {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// # Safety
/// MIDL provides a live binding and exclusive output storage for this call.
#[no_mangle]
unsafe extern "C" fn bgp_rpc_control(
    binding: *const c_void,
    operation: u32,
    output: *mut WireResult,
) -> u32 {
    if output.is_null() {
        return ERROR_INVALID_DATA;
    }
    // SAFETY: MIDL supplies exclusive initialized output storage for this call.
    unsafe {
        output.write(WireResult::default());
    }
    // Authorize again before examining application parameters or queuing work.
    let authorized = authorize_call(binding);
    if authorized != RPC_S_OK as u32 {
        return authorized;
    }
    if !(1..=3).contains(&operation) {
        return ERROR_INVALID_DATA;
    }
    let Some(policy) = POLICY.get() else {
        return ERROR_ACCESS_DENIED;
    };
    if policy.stop.is_requested() {
        return ERROR_SERVICE_NOT_ACTIVE;
    }
    if ACTIVE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return ERROR_BUSY;
    }
    let _permit = ActiveCall;
    let method = match operation {
        1 => Method::Get,
        2 => Method::Start,
        3 => Method::Stop,
        _ => return ERROR_INVALID_DATA,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(Arc::clone(&cancelled));
    let (sender, receiver) = mpsc::sync_channel(1);
    let deadline = Instant::now() + Duration::from_millis(u64::from(CALL_TIMEOUT_MS));
    if let Err(status) = policy.sender.try_send(Request {
        method,
        response: sender,
        cancelled,
        deadline,
    }) {
        if status != ERROR_BUSY {
            // A failed notification must not leave a live dispatcher asleep with
            // queued work. CancelOnDrop invalidates this request before it can run.
            let _ = policy.stop.signal();
        }
        return status;
    }
    loop {
        // SAFETY: this thread is executing the current native RPC call.
        let cancellation = unsafe { RpcServerTestCancel(binding) };
        if policy.stop.is_requested()
            || Instant::now() >= deadline
            || cancellation != RPC_S_CALL_IN_PROGRESS
        {
            return ERROR_OPERATION_ABORTED;
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok((status, value)) => {
                if value > 1 {
                    return ERROR_INVALID_DATA;
                }
                // SAFETY: output is still exclusive to this call.
                unsafe {
                    output.write(WireResult { status, value });
                }
                return RPC_S_OK as u32;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return ERROR_SERVICE_NOT_ACTIVE,
        }
    }
}

#[derive(Default)]
pub(crate) struct Client {
    cancel: Option<StopSignal>,
}
impl Client {
    pub(crate) fn with_cancel(cancel: StopSignal) -> Self {
        Self {
            cancel: Some(cancel),
        }
    }
    fn exchange(&self, operation: u32) -> io::Result<WireResult> {
        crate::service_identity::verify_bfd_service_identity()?;
        let closing = self.cancel.as_ref().is_some_and(StopSignal::is_requested);
        let timeout = if closing {
            SHUTDOWN_TIMEOUT_MS
        } else {
            CALL_TIMEOUT_MS
        };
        let cancel = self.cancel.as_ref().filter(|_| !closing);
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout));
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let remaining_ms = u32::try_from(remaining.as_millis())
                .unwrap_or(timeout)
                .max(1);
            let result = call_with_policy(
                ENDPOINT,
                "S-1-5-18",
                BROKER_SID,
                operation,
                remaining_ms,
                cancel,
            );
            // These errors mean no provider request was accepted. Never replay an
            // uncertain mutation here; the controller reconciles desired state.
            if closing
                && result.as_ref().is_err_and(|error| {
                    matches!(error.raw_os_error(), Some(170 | 1722 | 1723 | 1753))
                })
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            break result;
        }
    }
    pub(crate) fn started(&self) -> io::Result<bool> {
        let response = self.exchange(1)?;
        local_rpc::check(response.status as i32)?;
        Ok(response.value != 0)
    }
    pub(crate) fn invoke(&self, method: Method) -> io::Result<()> {
        let response = self.exchange(match method {
            Method::Get => 1,
            Method::Start => 2,
            Method::Stop => 3,
        })?;
        local_rpc::check(response.status as i32)
    }
}

fn call_with_policy(
    endpoint: &str,
    user: &str,
    group: &str,
    operation: u32,
    timeout_ms: u32,
    cancel: Option<&StopSignal>,
) -> io::Result<WireResult> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    local_rpc::with_rpc_binding(
        endpoint,
        user,
        group,
        bgp_rpc_bind,
        BIND_TIMEOUT_MS.min(timeout_ms),
        || std::process::abort(),
        |binding| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "BGP RPC deadline expired",
                ));
            }
            let timeout_ms = u32::try_from(remaining.as_millis())
                .unwrap_or(timeout_ms)
                .max(1);
            let mut output = WireResult::default();
            let event = cancel.map(StopSignal::event);
            // SAFETY: binding, output and optional event outlive async completion.
            // C contains RPC exceptions; uncertain ownership aborts without freeing storage.
            let status = unsafe {
                bgp_rpc_call(
                    binding,
                    timeout_ms,
                    event
                        .as_ref()
                        .map_or(ptr::null_mut(), AsRawHandle::as_raw_handle),
                    operation,
                    &mut output,
                )
            };
            if status == ERROR_OPERATION_ABORTED {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "BGP RPC cancelled",
                ));
            }
            local_rpc::check(status as i32)?;
            if output.value > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid BGP RPC result",
                ));
            }
            Ok(output)
        },
    )
}

#[cfg(all(test, not(miri)))]
mod tests;
