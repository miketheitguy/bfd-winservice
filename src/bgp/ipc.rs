//! Fixed-size, local BGP IPC. Native I/O and identification are confined here.
#![allow(unsafe_code)]

use super::Method;
use crate::runtime::StopSignal;
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        LocalFree, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_PIPE_CONNECTED, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            SDDL_REVISION_1,
        },
        CheckTokenMembership, DuplicateToken, RevertToSelf, SecurityIdentification,
        SECURITY_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
            ImpersonateNamedPipeClient, PeekNamedPipe, PIPE_READMODE_MESSAGE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
        },
        Threading::{
            CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
            WaitForSingleObject,
        },
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
    },
};

pub(crate) const SERVICE_SID: &str =
    "S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512";
pub(crate) const BROKER_SID: &str = "S-1-5-80-3301813337-1731295767-1225795713-3993009034-49020719";
pub(crate) const BROKER_NAME: &str = "BfdBgpBroker";
const PIPE: &str = r"\\.\pipe\BfdWinService.Bgp.v1";
const FRAME_SIZE: usize = 24;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const NOT_CONFIGURED: u32 = ERROR_NOT_FOUND;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "BGP IPC identity is not authorized",
    )
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

// LocalFree allocations must stay alive while Windows borrows their SID/SD pointers.
struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: each instance owns one allocation returned by an SDDL conversion.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn sid(value: &str) -> io::Result<LocalAllocation> {
    let value = wide(value);
    let mut result = ptr::null_mut();
    // SAFETY: terminated input and writable output; success transfers LocalFree ownership.
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(result))
}

fn member(token: HANDLE, value: &str) -> io::Result<bool> {
    let sid = sid(value)?;
    let mut present = 0;
    // SAFETY: SID is live and valid; token is an impersonation token or NULL for this thread.
    if unsafe { CheckTokenMembership(token, sid.0, &mut present) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(present != 0)
}

pub(crate) fn require_broker_identity() -> io::Result<()> {
    let mut raw = ptr::null_mut();
    // SAFETY: process pseudo-handle is valid; output is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transfers a uniquely owned real handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut raw = ptr::null_mut();
    // SAFETY: duplicate at identification level; CheckTokenMembership requires an impersonation token.
    if unsafe { DuplicateToken(token.as_raw_handle(), SecurityIdentification, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful duplication transfers a uniquely owned real handle.
    let duplicate = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !member(duplicate.as_raw_handle(), "S-1-5-18")?
        || !member(duplicate.as_raw_handle(), BROKER_SID)?
    {
        return Err(denied());
    }
    Ok(())
}

struct Identification;
impl Drop for Identification {
    fn drop(&mut self) {
        // SAFETY: this guard never leaves the thread that successfully impersonated.
        // Continuing after failed reversion could run later code under the wrong identity.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn identify_client(pipe: &OwnedHandle, client_sid: &str, account_sid: &str) -> io::Result<()> {
    // SAFETY: pipe has just delivered a request. The client permits identification only.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Identification;
    let mut raw = ptr::null_mut();
    // SAFETY: identification cannot perform access checks as the client. OpenAsSelf
    // checks TOKEN_QUERY against the server identity, without escalating the token.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open transfers a uniquely owned real token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    if !member(token.as_raw_handle(), client_sid)? || !member(token.as_raw_handle(), account_sid)? {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub method: Method,
    pub sequence: u64,
    pub status: u32,
    pub value: u32,
}
impl Frame {
    pub(crate) fn encode(self) -> [u8; FRAME_SIZE] {
        let mut bytes = [0; FRAME_SIZE];
        bytes[..4].copy_from_slice(b"BGP1");
        bytes[4] = 1;
        bytes[5] = match self.method {
            Method::Get => 1,
            Method::Start => 2,
            Method::Stop => 3,
        };
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.status.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.value.to_le_bytes());
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != FRAME_SIZE
            || &bytes[..4] != b"BGP1"
            || bytes[4] != 1
            || bytes[6..8] != [0, 0]
        {
            return Err(invalid("invalid BGP protocol frame"));
        }
        let method = match bytes[5] {
            1 => Method::Get,
            2 => Method::Start,
            3 => Method::Stop,
            _ => return Err(invalid("unsupported BGP operation")),
        };
        // Length was checked before these fixed-width conversions.
        let sequence = u64::from_le_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| invalid("invalid sequence"))?,
        );
        let status = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| invalid("invalid status"))?,
        );
        let value = u32::from_le_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| invalid("invalid value"))?,
        );
        if sequence == 0 {
            return Err(invalid("zero BGP sequence"));
        }
        Ok(Self {
            method,
            sequence,
            status,
            value,
        })
    }
    pub(crate) fn validate_request(self, previous: u64) -> io::Result<Self> {
        if previous.checked_add(1) != Some(self.sequence) || self.status != 0 || self.value != 0 {
            return Err(invalid("out-of-order or invalid BGP request"));
        }
        Ok(self)
    }
}

// Every operation holds its buffer/OVERLAPPED in place until completion or drained
// cancellation. It is never dropped while the kernel can still write to it.
fn complete(
    handle: &OwnedHandle,
    overlap: &mut OVERLAPPED,
    event: &OwnedHandle,
    initiated: io::Result<()>,
    deadline: Option<Instant>,
    stop: Option<&StopSignal>,
) -> io::Result<u32> {
    if let Err(error) = initiated {
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }
        loop {
            if stop.is_some_and(StopSignal::is_requested)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                // SAFETY: exact live operation; its memory is retained through the blocking drain.
                unsafe {
                    CancelIoEx(handle.as_raw_handle(), overlap);
                }
                let mut transferred = 0;
                // SAFETY: wait drains a cancelled/racing-complete operation before returning its memory.
                unsafe {
                    GetOverlappedResult(handle.as_raw_handle(), overlap, &mut transferred, 1);
                }
                return Err(io::Error::new(
                    if stop.is_some_and(StopSignal::is_requested) {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::TimedOut
                    },
                    "BGP pipe I/O cancelled",
                ));
            }
            // SAFETY: event is live; bounded wait also observes service shutdown.
            match unsafe { WaitForSingleObject(event.as_raw_handle(), 100) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT => {}
                _ => {
                    let error = io::Error::last_os_error();
                    // SAFETY: drain before releasing overlapped storage even when the wait failed.
                    unsafe {
                        CancelIoEx(handle.as_raw_handle(), overlap);
                    }
                    let mut transferred = 0;
                    // SAFETY: both handle and operation storage stay live until completion.
                    unsafe {
                        GetOverlappedResult(handle.as_raw_handle(), overlap, &mut transferred, 1);
                    }
                    return Err(error);
                }
            }
        }
    }
    let mut transferred = 0;
    // SAFETY: synchronous success or signalled completion; output and OVERLAPPED are live.
    if unsafe { GetOverlappedResult(handle.as_raw_handle(), overlap, &mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

fn initiation(immediate: bool) -> io::Result<()> {
    if immediate {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn operation() -> io::Result<(OwnedHandle, OVERLAPPED)> {
    // SAFETY: unnamed, manual-reset event with no inherited handle or borrowed name.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: event creation transferred unique handle ownership.
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let overlap = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    Ok((event, overlap))
}

fn read(
    pipe: &OwnedHandle,
    deadline: Option<Instant>,
    stop: Option<&StopSignal>,
) -> io::Result<Frame> {
    let (event, mut overlap) = operation()?;
    let mut bytes = [0; FRAME_SIZE];
    // SAFETY: fixed-size live buffer/OVERLAPPED retained until complete drains native I/O.
    let immediate = unsafe {
        ReadFile(
            pipe.as_raw_handle(),
            bytes.as_mut_ptr(),
            FRAME_SIZE as u32,
            ptr::null_mut(),
            &mut overlap,
        )
    } != 0;
    let initiated = initiation(immediate);
    let count = complete(pipe, &mut overlap, &event, initiated, deadline, stop)?;
    if count as usize != FRAME_SIZE {
        return Err(invalid("truncated BGP frame"));
    }
    Frame::decode(&bytes)
}

fn write(pipe: &OwnedHandle, frame: Frame, stop: Option<&StopSignal>) -> io::Result<()> {
    write_bytes(pipe, &frame.encode(), stop)
}

fn write_bytes(pipe: &OwnedHandle, bytes: &[u8], stop: Option<&StopSignal>) -> io::Result<()> {
    let (event, mut overlap) = operation()?;
    let length = u32::try_from(bytes.len()).map_err(|_| invalid("BGP frame is too large"))?;
    // SAFETY: live buffer/OVERLAPPED retained until complete drains native I/O.
    let immediate = unsafe {
        WriteFile(
            pipe.as_raw_handle(),
            bytes.as_ptr(),
            length,
            ptr::null_mut(),
            &mut overlap,
        )
    } != 0;
    // Capture GetLastError before consulting the clock or doing any other work.
    let initiated = initiation(immediate);
    let count = complete(
        pipe,
        &mut overlap,
        &event,
        initiated,
        Some(Instant::now() + IO_TIMEOUT),
        stop,
    )?;
    if count as usize != bytes.len() {
        return Err(invalid("partial BGP write"));
    }
    Ok(())
}

#[cfg(all(test, not(miri)))]
pub(crate) mod fixtures {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn listener(account_sid: &str) -> (Listener, String) {
        let name = format!(
            r"\\.\pipe\BfdBrokerTest.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        (
            Listener::with_policy(&name, "S-1-1-0", account_sid).unwrap(),
            name,
        )
    }
    pub(crate) fn connect_pipe(name: &str) -> OwnedHandle {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match connect(name) {
                Ok(pipe) => return pipe,
                Err(error) if error.raw_os_error() == Some(231) && Instant::now() < deadline => {
                    thread_sleep()
                }
                Err(error) => panic!("fixture pipe connection failed: {error}"),
            }
        }
    }
    fn thread_sleep() {
        std::thread::sleep(Duration::from_millis(10));
    }
    pub(crate) struct StopOnDrop(pub StopSignal);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            let _ = self.0.signal();
        }
    }
    pub(crate) fn request(pipe: &OwnedHandle, method: Method, sequence: u64) -> io::Result<Frame> {
        write(
            pipe,
            Frame {
                method,
                sequence,
                status: 0,
                value: 0,
            },
            None,
        )?;
        read(pipe, Some(Instant::now() + Duration::from_secs(3)), None)
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn request_frame(sequence: u64) -> Frame {
        Frame {
            method: Method::Start,
            sequence,
            status: 0,
            value: 0,
        }
    }

    #[test]
    fn protocol_rejects_extra_data_unknown_operations_replays_and_caller_results() {
        let frame = request_frame(1);
        assert_eq!(
            Frame::decode(&frame.encode())
                .unwrap()
                .validate_request(0)
                .unwrap(),
            frame
        );
        for length in 0..FRAME_SIZE {
            assert!(Frame::decode(&frame.encode()[..length]).is_err());
        }
        let mut oversized = frame.encode().to_vec();
        oversized.extend_from_slice(b"C:\\Windows\\system.ini");
        assert!(Frame::decode(&oversized).is_err());
        for index in [0, 4, 5, 6, 7] {
            let mut bytes = frame.encode();
            bytes[index] = 255;
            assert!(Frame::decode(&bytes).is_err());
        }
        assert!(frame.validate_request(1).is_err());
        assert!(request_frame(3).validate_request(1).is_err());
        assert!(Frame { status: 5, ..frame }.validate_request(0).is_err());
        assert!(Frame { value: 1, ..frame }.validate_request(0).is_err());
        assert!(request_frame(u64::MAX).validate_request(u64::MAX).is_err());
        assert!(Frame::decode(&request_frame(0).encode()).is_err());
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread};

    #[test]
    fn identification_reverts_before_backend_and_valid_requests_round_trip() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        let stop = StopSignal::new().unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                listener.accept(&stop).unwrap();
                let frame = listener.request(0, &stop).unwrap();
                let mut token = ptr::null_mut();
                // SAFETY: this thread's pseudo-handle is valid and output is writable.
                let result = unsafe {
                    windows_sys::Win32::System::Threading::OpenThreadToken(
                        windows_sys::Win32::System::Threading::GetCurrentThread(),
                        TOKEN_QUERY,
                        1,
                        &mut token,
                    )
                };
                assert_eq!(result, 0, "identification token leaked into backend work");
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1008));
                listener
                    .respond(Frame { value: 1, ..frame }, &stop)
                    .unwrap();
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            assert_eq!(
                fixtures::request(&client, Method::Start, 1).unwrap().value,
                1
            );
            server.join().unwrap();
        });
    }

    #[test]
    fn service_sid_and_account_checks_reject_unrelated_callers() {
        for expected in [SERVICE_SID, "S-1-5-19"] {
            let (listener, name) = fixtures::listener(expected);
            let stop = StopSignal::new().unwrap();
            thread::scope(|scope| {
                let server = scope.spawn(|| {
                    listener.accept(&stop).unwrap();
                    let error = listener.request(0, &stop).unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                    listener.disconnect();
                });
                let _cleanup = fixtures::StopOnDrop(stop.clone());
                let client = fixtures::connect_pipe(&name);
                assert!(fixtures::request(&client, Method::Start, 1).is_err());
                server.join().unwrap();
            });
        }
    }

    #[test]
    fn pipe_acl_denies_unrelated_clients_and_additional_server_instances() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        assert!(Listener::with_policy(&name, "S-1-1-0", "S-1-1-0").is_err());
        let other_name = format!("{name}.restricted");
        let restricted = Listener::with_policy(&other_name, SERVICE_SID, "S-1-5-19").unwrap();
        assert_eq!(
            connect(&other_name).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(restricted);
        let name = wide(&name);
        // SAFETY: terminated fixture name; no borrowed buffers or inherited handle.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                windows_sys::Win32::Foundation::GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        assert_eq!(
            raw, INVALID_HANDLE_VALUE,
            "clients must lack pipe creation rights"
        );
        assert_eq!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(listener);
    }

    #[test]
    fn oversized_native_messages_are_rejected() {
        let (listener, name) = fixtures::listener("S-1-1-0");
        let stop = StopSignal::new().unwrap();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                listener.accept(&stop).unwrap();
                assert!(listener.request(0, &stop).is_err());
                listener.disconnect();
            });
            let _cleanup = fixtures::StopOnDrop(stop.clone());
            let client = fixtures::connect_pipe(&name);
            let mut bytes = Frame {
                method: Method::Start,
                sequence: 1,
                status: 0,
                value: 0,
            }
            .encode()
            .to_vec();
            bytes.push(0);
            let _ = write_bytes(&client, &bytes, None);
            server.join().unwrap();
        });
    }

    #[test]
    fn shutdown_drains_pending_connect_and_read_operations() {
        for connected in [false, true] {
            let (listener, name) = fixtures::listener("S-1-1-0");
            let stop = StopSignal::new().unwrap();
            let (ready, waiting) = mpsc::channel();
            thread::scope(|scope| {
                let server = scope.spawn(|| {
                    if connected {
                        listener.accept(&stop).unwrap();
                    }
                    ready.send(()).unwrap();
                    let result = if connected {
                        listener.request(0, &stop).map(|_| ())
                    } else {
                        listener.accept(&stop)
                    };
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
                });
                let _cleanup = fixtures::StopOnDrop(stop.clone());
                let _client = connected.then(|| fixtures::connect_pipe(&name));
                waiting.recv_timeout(Duration::from_secs(3)).unwrap();
                stop.signal().unwrap();
                server.join().unwrap();
            });
        }
    }

    #[test]
    fn client_rejects_a_pipe_outside_the_scm_broker_process() {
        let (_listener, name) = fixtures::listener("S-1-1-0");
        let client = fixtures::connect_pipe(&name);
        assert!(verify_server(&client).is_err());
        assert!(require_broker_identity().is_err());
    }
}

pub(crate) struct Client {
    pipe: Option<OwnedHandle>,
    sequence: u64,
}
impl Client {
    pub(crate) fn new() -> Self {
        Self {
            pipe: None,
            sequence: 0,
        }
    }
    pub(crate) fn maintain(&mut self) -> io::Result<bool> {
        if let Some(pipe) = &self.pipe {
            // SAFETY: peek only checks the live overlapped pipe; no buffers are supplied.
            if unsafe {
                PeekNamedPipe(
                    pipe.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } != 0
            {
                return Ok(false);
            }
            self.pipe = None;
        }
        let pipe = connect(PIPE)?;
        verify_server(&pipe)?;
        self.pipe = Some(pipe);
        self.sequence = 0;
        Ok(true)
    }
    fn exchange(&mut self, method: Method) -> io::Result<Frame> {
        self.maintain()?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("BGP sequence exhausted"))?;
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| invalid("missing BGP pipe"))?;
        let result = (|| {
            write(
                pipe,
                Frame {
                    method,
                    sequence: self.sequence,
                    status: 0,
                    value: 0,
                },
                None,
            )?;
            let response = read(pipe, Some(Instant::now() + IO_TIMEOUT), None)?;
            if response.sequence != self.sequence || response.method != method || response.value > 1
            {
                return Err(invalid("invalid BGP response"));
            }
            Ok(response)
        })();
        if result.is_err() {
            self.pipe = None;
        }
        result
    }
    pub(crate) fn probe(&mut self) -> io::Result<()> {
        self.exchange(Method::Get).map(|_| ())
    }
    pub(crate) fn started(&mut self) -> io::Result<bool> {
        let response = self.exchange(Method::Get)?;
        if response.status != 0 {
            return Err(io::Error::from_raw_os_error(response.status as i32));
        }
        Ok(response.value != 0)
    }
    pub(crate) fn invoke(&mut self, method: Method) -> io::Result<()> {
        let response = self.exchange(method)?;
        if response.status != 0 {
            return Err(io::Error::from_raw_os_error(response.status as i32));
        }
        Ok(())
    }
}

fn connect(name: &str) -> io::Result<OwnedHandle> {
    let name = wide(name);
    // Individual write rights exclude FILE_CREATE_PIPE_INSTANCE, unlike GENERIC_WRITE.
    // SAFETY: terminated name; no inherited handle; identification prevents token misuse.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open transferred unique handle ownership.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn verify_server(pipe: &OwnedHandle) -> io::Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let mut pid = 0;
    // SAFETY: live connected pipe and writable PID output. Windows supplies server identity.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SCM owns the service PID. Querying it works from LocalService and avoids
    // requesting access to a privileged process's token or trusting a claimed PID.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(io::Error::other)?;
    let service = manager
        .open_service(BROKER_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(io::Error::other)?;
    let status = service.query_status().map_err(io::Error::other)?;
    if status.current_state != ServiceState::Running || status.process_id != Some(pid) {
        return Err(denied());
    }
    Ok(())
}

pub(crate) struct Listener {
    pipe: OwnedHandle,
    client_sid: String,
    account_sid: String,
}
impl Listener {
    pub(crate) fn new() -> io::Result<Self> {
        Self::with_policy(PIPE, SERVICE_SID, "S-1-5-19")
    }
    fn with_policy(name: &str, client_sid: &str, account_sid: &str) -> io::Result<Self> {
        // Only the broker service may create another server instance. The BFD
        // service gets data read/write, read-attributes (implicit in CreateFile),
        // and synchronization rights, never pipe creation or ACL mutation.
        let sddl = wide(&format!(
            "D:P(A;;FA;;;{BROKER_SID})(A;;0x100083;;;{client_sid})"
        ));
        let mut descriptor = ptr::null_mut();
        // SAFETY: terminated SDDL and writable output; ownership goes to LocalAllocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide(name);
        // SAFETY: names/SD/attributes stay live through creation; Windows copies security.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                FRAME_SIZE as u32,
                FRAME_SIZE as u32,
                0,
                &attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pipe creation transferred unique handle ownership.
        let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
        Ok(Self {
            pipe,
            client_sid: client_sid.into(),
            account_sid: account_sid.into(),
        })
    }
    pub(crate) fn accept(&self, stop: &StopSignal) -> io::Result<()> {
        let (event, mut overlap) = operation()?;
        // SAFETY: live pipe and OVERLAPPED retained through completion/cancellation.
        let immediate = unsafe { ConnectNamedPipe(self.pipe.as_raw_handle(), &mut overlap) } != 0;
        let initiated = initiation(immediate);
        if initiated
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32))
        {
            return Ok(());
        }
        complete(
            &self.pipe,
            &mut overlap,
            &event,
            initiated,
            None,
            Some(stop),
        )
        .map(|_| ())
    }
    pub(crate) fn request(&self, previous: u64, stop: &StopSignal) -> io::Result<Frame> {
        let frame = read(
            &self.pipe,
            (previous == 0).then(|| Instant::now() + IO_TIMEOUT),
            Some(stop),
        )?;
        // Identification and reversion finish before any privileged provider operation.
        identify_client(&self.pipe, &self.client_sid, &self.account_sid)?;
        frame.validate_request(previous)
    }
    pub(crate) fn respond(&self, frame: Frame, stop: &StopSignal) -> io::Result<()> {
        write(&self.pipe, frame, Some(stop))
    }
    pub(crate) fn disconnect(&self) {
        // SAFETY: all I/O has completed/drained before resetting this owned pipe instance.
        unsafe {
            DisconnectNamedPipe(self.pipe.as_raw_handle());
        }
    }
}
