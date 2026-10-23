//! Native isolated fixtures use the real test account, never installed services.
use super::*;
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
};
use tempfile::TempDir;
use windows_sys::Win32::System::Com::{RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_ANONYMOUS};
use windows_sys::Win32::System::Rpc::{
    RpcBindingFree, RpcBindingFromStringBindingW, RpcBindingSetAuthInfoExW, RpcBindingSetOption,
    RpcMgmtInqStats, RpcMgmtStatsVectorFree, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
    RPC_C_OPT_UNIQUE_BINDING, RPC_SECURITY_QOS,
};

const WORLD: &str = "S-1-1-0";
const FIXTURE: &str = "BFD_BGP_RPC_FIXTURE";

fn queued_request() -> Request {
    Request {
        method: Method::Get,
        response: mpsc::sync_channel(1).0,
        cancelled: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

#[test]
fn dispatcher_wakes_for_requests_and_preserves_the_queue_bound() {
    let (sender, dispatcher) = Dispatcher::new().unwrap();
    let stop = StopSignal::new().unwrap();
    // Prequeued and subsequent requests must each retain their own notification.
    for _ in 0..128 {
        sender.try_send(queued_request()).unwrap();
        assert_eq!(sender.try_send(queued_request()).unwrap_err(), ERROR_BUSY);
        assert!(dispatcher.request(&stop).unwrap().is_some());
    }
    thread::scope(|scope| {
        let wait_stop = &stop;
        let waiting = scope.spawn(move || dispatcher.request(wait_stop).unwrap());
        sender.try_send(queued_request()).unwrap();
        assert!(waiting.join().unwrap().is_some());
    });
}

#[test]
fn dispatcher_stop_wakes_an_idle_wait_and_takes_priority_over_queued_work() {
    let (_sender, dispatcher) = Dispatcher::new().unwrap();
    let stop = StopSignal::new().unwrap();
    thread::scope(|scope| {
        let (finished, completion) = mpsc::sync_channel(1);
        let wait_stop = &stop;
        let waiting = scope.spawn(move || {
            assert!(dispatcher.request(wait_stop).unwrap().is_none());
            finished.send(()).unwrap();
        });
        assert_eq!(
            completion.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        stop.signal().unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
        waiting.join().unwrap();
    });

    let (sender, dispatcher) = Dispatcher::new().unwrap();
    sender.try_send(queued_request()).unwrap();
    assert!(dispatcher.request(&stop).unwrap().is_none());
    assert!(dispatcher.receiver.try_recv().is_ok());
}

struct Fixture {
    child: Child,
    directory: TempDir,
    endpoint: String,
}
impl Fixture {
    fn start(user: &str, group: &str, delay: u32, configured: bool) -> Self {
        Self::with_provider(user, group, delay, configured, false)
    }
    fn with_provider(
        user: &str,
        group: &str,
        delay: u32,
        configured: bool,
        provider: bool,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = format!(
            "BfdBgpTest.{}.{}",
            std::process::id(),
            rand::random::<u64>()
        );
        let output = fs::File::create(directory.path().join("log")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bgp::ipc::tests::server_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BFD_BGP_PROVIDER", if provider { "1" } else { "0" })
            .env(FIXTURE, directory.path())
            .env("BFD_BGP_ENDPOINT", &endpoint)
            .env("BFD_BGP_USER", user)
            .env("BFD_BGP_GROUP", group)
            .env("BFD_BGP_DELAY", delay.to_string())
            .env("BFD_BGP_CONFIGURED", if configured { "1" } else { "0" })
            .stdin(Stdio::piped())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let mut fixture = Self {
            child,
            directory,
            endpoint,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !fixture.directory.path().join("ready").exists() {
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "{}",
                fixture.log()
            );
            assert!(Instant::now() < deadline, "{}", fixture.log());
            thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    fn log(&self) -> String {
        fs::read_to_string(self.directory.path().join("log")).unwrap_or_default()
    }
    fn calls(&self) -> String {
        fs::read_to_string(self.directory.path().join("calls")).unwrap_or_default()
    }
    fn call(&self, operation: u32) -> io::Result<WireResult> {
        call_with_policy(&self.endpoint, &user(), WORLD, operation, 5_000, None)
    }
    fn stop(mut self) {
        self.child
            .stdin
            .take()
            .unwrap()
            .write_all(b"stop\n")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "{}", self.log());
                assert!(self.directory.path().join("stopped").exists());
                return;
            }
            assert!(Instant::now() < deadline, "{}", self.log());
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn user() -> String {
    crate::service_identity::current_user_sid().unwrap()
}
fn wrong_user() -> &'static str {
    if user() == "S-1-5-18" {
        "S-1-5-19"
    } else {
        "S-1-5-18"
    }
}

#[test]
#[ignore = "native BGP fixture; launched by parent tests"]
fn server_child() {
    let Some(directory) = std::env::var_os(FIXTURE) else {
        return;
    };
    let directory = PathBuf::from(directory);
    if std::env::var("BFD_BGP_PROVIDER").is_ok_and(|value| value == "1") {
        crate::bgp_broker::test_rpc_with_provider(|provider| {
            serve_fixture(directory, Some(provider))
        })
        .unwrap();
    } else {
        serve_fixture(directory, None);
    }
}

fn serve_fixture(directory: PathBuf, provider: Option<fn() -> io::Result<()>>) {
    crate::runtime::drop_rpc_privileges().unwrap();
    let stop = StopSignal::new().unwrap();
    let listener = Listener::with_policy(
        &std::env::var("BFD_BGP_ENDPOINT").unwrap(),
        &std::env::var("BFD_BGP_USER").unwrap(),
        &std::env::var("BFD_BGP_GROUP").unwrap(),
        stop.clone(),
    )
    .unwrap();
    let delay: u64 = std::env::var("BFD_BGP_DELAY").unwrap().parse().unwrap();
    let configured = std::env::var("BFD_BGP_CONFIGURED").unwrap() == "1";
    let calls = directory.join("calls");
    fs::write(directory.join("ready"), b"ready").unwrap();
    let handler_stop = stop.clone();
    let reader = thread::spawn(move || {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        handler_stop.signal().unwrap();
    });
    crate::bgp_broker::serve_with_backend(
        &listener,
        configured,
        &stop,
        &mut crate::runtime::Logger::new().unwrap(),
        |method, _| {
            if let Some(provider) = provider {
                provider()?;
            }
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&calls)
                .unwrap();
            writeln!(file, "{}", method.name()).unwrap();
            thread::sleep(Duration::from_millis(delay));
            Ok(u32::from(method != Method::Stop))
        },
    )
    .unwrap();
    reader.join().unwrap();
    drop(listener);
    fs::write(directory.join("stopped"), b"stopped").unwrap();
}

#[test]
fn native_control_round_trip_exposes_only_get_start_and_stop() {
    let fixture = Fixture::start(&user(), WORLD, 0, true);
    for (operation, value) in [(1, 1), (2, 1), (3, 0)] {
        let reply = fixture.call(operation).unwrap();
        assert_eq!((reply.status, reply.value), (0, value));
    }
    // Each call uses a new connection; closing it causes no provider operation.
    assert_eq!(fixture.calls(), "Get\nStart\nStop\n");
    for operation in [0, 4, 99, u32::MAX] {
        assert_eq!(
            fixture.call(operation).unwrap_err().raw_os_error(),
            Some(1783)
        );
    }
    assert_eq!(fixture.calls(), "Get\nStart\nStop\n");
    fixture.call(1).unwrap();
    fixture.stop();
}

#[test]
fn native_control_denies_wrong_caller_account_and_missing_service_group() {
    for (account, group) in [(wrong_user().to_owned(), WORLD), (user(), SERVICE_SID)] {
        let fixture = Fixture::start(&account, group, 0, true);
        for operation in 1..=3 {
            assert_eq!(
                fixture.call(operation).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(fixture.calls().is_empty());
        fixture.stop();
    }
}

#[test]
fn native_control_pins_server_account_and_group() {
    // Separate processes avoid Windows caching changes of expected identity policy.
    for (account, group) in [(wrong_user().to_owned(), WORLD), (user(), SERVICE_SID)] {
        let fixture = Fixture::start(&user(), WORLD, 0, true);
        assert!(call_with_policy(&fixture.endpoint, &account, group, 2, 2_000, None).is_err());
        assert!(fixture.calls().is_empty());
        fixture.stop();
    }
}

#[test]
fn unconfigured_control_authenticates_but_never_calls_provider() {
    let fixture = Fixture::start(&user(), WORLD, 0, false);
    for operation in 1..=3 {
        assert_eq!(fixture.call(operation).unwrap().status, NOT_CONFIGURED);
    }
    assert!(fixture.calls().is_empty());
    fixture.stop();
}

#[test]
fn cancellation_returns_promptly_and_control_recovers_without_replay() {
    let fixture = Fixture::start(&user(), WORLD, 700, true);
    let cancel = StopSignal::new().unwrap();
    thread::scope(|scope| {
        let cancelling = scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while fixture.calls().is_empty() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            cancel.signal().unwrap();
        });
        let start = Instant::now();
        let error = call_with_policy(&fixture.endpoint, &user(), WORLD, 2, 5_000, Some(&cancel))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_millis(650));
        cancelling.join().unwrap();
    });
    thread::sleep(Duration::from_millis(850));
    fixture.call(1).unwrap();
    assert_eq!(fixture.calls(), "Start\nGet\n");
    fixture.stop();
}

#[test]
fn bounded_dispatch_discards_a_cancelled_queued_mutation() {
    let fixture = Fixture::start(&user(), WORLD, 1_200, true);
    let first_cancel = StopSignal::new().unwrap();
    thread::scope(|scope| {
        let first = scope.spawn(|| {
            call_with_policy(
                &fixture.endpoint,
                &user(),
                WORLD,
                2,
                5_000,
                Some(&first_cancel),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while fixture.calls().is_empty() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        // The first manager owns admission; a concurrent request cannot queue.
        assert_eq!(
            fixture.call(3).unwrap_err().raw_os_error(),
            Some(ERROR_BUSY as i32)
        );
        first_cancel.signal().unwrap();
        assert_eq!(
            first.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        // Allow the server to observe cancellation and release admission. The
        // provider remains busy; the next mutation can only enter the queue.
        thread::sleep(Duration::from_millis(100));
        let second_cancel = StopSignal::new().unwrap();
        let cancel_signal = second_cancel.clone();
        let cancelling = scope.spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancel_signal.signal().unwrap();
        });
        let error = call_with_policy(
            &fixture.endpoint,
            &user(),
            WORLD,
            3,
            5_000,
            Some(&second_cancel),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        cancelling.join().unwrap();
    });
    thread::sleep(Duration::from_millis(1_250));
    fixture.call(1).unwrap();
    assert_eq!(fixture.calls(), "Start\nGet\n");
    fixture.stop();
}

#[test]
fn production_entrypoints_require_installed_service_identity() {
    assert!(require_broker_identity().is_err());
    assert!(Client::default().started().is_err());
    assert!(Client::default().invoke(Method::Start).is_err());
    assert!(Listener::new(StopSignal::new().unwrap()).is_err());
}

#[test]
fn anonymous_control_and_runtime_management_are_denied() {
    let fixture = Fixture::start(&user(), WORLD, 0, true);
    let text: Vec<u16> = format!("ncalrpc:[{}]", fixture.endpoint)
        .encode_utf16()
        .chain([0])
        .collect();
    let mut raw = ptr::null_mut();
    // SAFETY: terminated string and writable native binding output.
    local_rpc::check(unsafe { RpcBindingFromStringBindingW(text.as_ptr(), &mut raw) }).unwrap();
    let mut stats = ptr::null_mut();
    // SAFETY: live classic binding and writable statistics output.
    let result = unsafe { RpcMgmtInqStats(raw, &mut stats) };
    assert_eq!(result, ERROR_ACCESS_DENIED as i32);
    if !stats.is_null() {
        // SAFETY: native returned vector remains owned until release.
        local_rpc::check(unsafe { RpcMgmtStatsVectorFree(&mut stats) }).unwrap();
    }
    let qos = RPC_SECURITY_QOS {
        Version: 1,
        ImpersonationType: RPC_C_IMP_LEVEL_ANONYMOUS,
        ..Default::default()
    };
    // SAFETY: live isolated binding and initialized QOS; no borrowed identity.
    local_rpc::check(unsafe { RpcBindingSetOption(raw, RPC_C_OPT_UNIQUE_BINDING, 1) }).unwrap();
    // SAFETY: QOS outlives native synchronous configuration and call.
    local_rpc::check(unsafe {
        RpcBindingSetAuthInfoExW(
            raw,
            ptr::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            RPC_C_AUTHZ_NONE,
            &qos,
        )
    })
    .unwrap();
    let mut output = WireResult::default();
    // SAFETY: binding and record outlive asynchronous completion inside C.
    let result = unsafe { bgp_rpc_call(raw, 2_000, ptr::null_mut(), 2, &mut output) };
    assert_eq!(result, ERROR_ACCESS_DENIED);
    // SAFETY: no native call retains the uniquely owned classic binding.
    local_rpc::check(unsafe { RpcBindingFree(&mut raw) }).unwrap();
    assert!(fixture.calls().is_empty());
    fixture.call(1).unwrap();
    fixture.stop();
}

#[test]
fn wire_result_matches_midl_layout() {
    extern "C" {
        fn bgp_rpc_result_layout(field: u32) -> u32;
    }
    for (field, expected) in [
        std::mem::size_of::<WireResult>(),
        std::mem::align_of::<WireResult>(),
        std::mem::offset_of!(WireResult, status),
        std::mem::offset_of!(WireResult, value),
    ]
    .into_iter()
    .enumerate()
    {
        // SAFETY: helper returns compile-time native layout constants only.
        let actual = unsafe { bgp_rpc_result_layout(field as u32) } as usize;
        assert_eq!(actual, expected);
    }
}

mod restricted;

#[test]
#[ignore = "read-only native MI with the BGP RPC listener and management deny policy"]
fn native_bgp_rpc_and_provider_security_coexist() {
    let fixture = Fixture::with_provider(&user(), WORLD, 0, true, true);
    fixture.call(1).unwrap();
    fixture.call(1).unwrap();
    assert_eq!(fixture.calls(), "Get\nGet\n");
    fixture.stop();
}

#[test]
#[ignore = "installer harness only; requires the installed broker"]
fn installed_broker_rejects_unrelated_rpc_caller() {
    assert_eq!(
        std::env::var("BFD_TEST_INSTALLED_BGP_RPC").as_deref(),
        Ok("1")
    );
    // The installer leaves BGP unconfigured; even a regression cannot select a
    // live peer. Exercise every valid opcode, including Start and Stop.
    for operation in 1..=3 {
        let error =
            call_with_policy(ENDPOINT, "S-1-5-18", BROKER_SID, operation, 2_000, None).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "operation {operation}: {error}"
        );
    }
}
