//! Cross-process native RPC tests use the real test account and an existing
//! enabled group. Each server has a private endpoint and isolated RPC globals.

use super::*;
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use windows_sys::Win32::System::Rpc::{RpcBindingSetAuthInfoExW, RPC_C_AUTHZ_NONE};

const AUTHENTICATED_USERS: &str = "S-1-5-11";
const SYSTEM: &str = "S-1-5-18";
const LOCAL_SERVICE: &str = "S-1-5-19";
const FIXTURE_ENDPOINT: &str = "BFD_LRPC_FIXTURE_ENDPOINT";
const FIXTURE_USER: &str = "BFD_LRPC_FIXTURE_USER";
const FIXTURE_MARKER: &str = "BFD_LRPC_FIXTURE_MARKER";
const FIXTURE_DELAY: &str = "BFD_LRPC_FIXTURE_DELAY_MS";
const FIXTURE_CORRUPT: &str = "BFD_LRPC_FIXTURE_CORRUPT";
const FIXTURE_STOP_MARKER: &str = "BFD_LRPC_FIXTURE_STOP_MARKER";
const CLIENT_ENDPOINT: &str = "BFD_LRPC_CLIENT_ENDPOINT";
const CLIENT_USER: &str = "BFD_LRPC_CLIENT_USER";
const CLIENT_GROUP: &str = "BFD_LRPC_CLIENT_GROUP";
const CLIENT_RESULT: &str = "BFD_LRPC_CLIENT_RESULT";
const CHILD_TIMEOUT: Duration = Duration::from_secs(20);
static NEXT_ENDPOINT: AtomicU64 = AtomicU64::new(0);

struct RpcFixture {
    child: Child,
    directory: TempDir,
    marker: PathBuf,
    endpoint: String,
}

impl RpcFixture {
    fn start(expected_caller_user: &str) -> Self {
        Self::start_with_delay(expected_caller_user, 0)
    }

    fn start_with_delay(expected_caller_user: &str, delay_ms: u32) -> Self {
        Self::start_status(expected_caller_user, delay_ms, 0)
    }

    fn start_status(expected_caller_user: &str, delay_ms: u32, corrupt: u32) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("rpc-state");
        let output = File::create(directory.path().join("child.log")).unwrap();
        let endpoint = format!(
            "BfdLrpcTest.{}.{}",
            std::process::id(),
            NEXT_ENDPOINT.fetch_add(1, Ordering::Relaxed)
        );
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_rpc::tests::rpc_fixture_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FIXTURE_ENDPOINT, &endpoint)
            .env(FIXTURE_USER, expected_caller_user)
            .env(FIXTURE_MARKER, &marker)
            .env(FIXTURE_DELAY, delay_ms.to_string())
            .env(FIXTURE_CORRUPT, corrupt.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let mut fixture = Self {
            child,
            directory,
            marker,
            endpoint,
        };
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if fs::read(&fixture.marker).is_ok_and(|bytes| bytes == b"ready") {
                return fixture;
            }
            if let Some(status) = fixture.child.try_wait().unwrap() {
                panic!(
                    "RPC fixture exited before readiness ({status}): {}",
                    fixture.diagnostics()
                );
            }
            assert!(
                Instant::now() < deadline,
                "RPC fixture did not become ready: {}",
                fixture.diagnostics()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn diagnostics(&self) -> String {
        fs::read_to_string(self.directory.path().join("child.log"))
            .unwrap_or_else(|error| format!("cannot read child output: {error}"))
    }

    fn stop(mut self) {
        let mut input = self.child.stdin.take().unwrap();
        input.write_all(b"stop\n").unwrap();
        drop(input);
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "RPC fixture failed during shutdown ({status}): {}",
                    self.diagnostics()
                );
                assert_eq!(fs::read(&self.marker).unwrap(), b"stopped");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "RPC fixture did not shut down: {}",
                self.diagnostics()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RpcFixture {
    fn drop(&mut self) {
        // A failing parent assertion must not leave a child holding its private
        // endpoint or prevent TempDir cleanup by keeping the log file open.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn current_user() -> String {
    crate::service_identity::current_user_sid().unwrap()
}

fn unrelated_account(actual: &str) -> &'static str {
    if actual == SYSTEM {
        LOCAL_SERVICE
    } else {
        SYSTEM
    }
}

fn isolated_client_result(endpoint: &str, user: &str, group: &str) -> i32 {
    let directory = tempfile::tempdir().unwrap();
    let result = directory.path().join("result");
    let output = File::create(directory.path().join("child.log")).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "local_rpc::tests::rpc_fixture_client_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CLIENT_ENDPOINT, endpoint)
        .env(CLIENT_USER, user)
        .env(CLIENT_GROUP, group)
        .env(CLIENT_RESULT, &result)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output))
        .spawn()
        .unwrap();
    let mut fixture = RpcFixture {
        child,
        directory,
        marker: result.clone(),
        endpoint: endpoint.to_owned(),
    };
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(status) = fixture.child.try_wait().unwrap() {
            assert!(
                status.success(),
                "RPC client fixture failed ({status}): {}",
                fixture.diagnostics()
            );
            return fs::read_to_string(result).unwrap().parse().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "RPC client fixture timed out: {}",
            fixture.diagnostics()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn authenticated_native_lrpc_round_trip_and_shutdown() {
    let user = current_user();
    let fixture = RpcFixture::start(&user);
    let endpoint = fixture.endpoint.clone();
    probe_with_policy(&endpoint, &user, AUTHENTICATED_USERS).unwrap();
    probe_with_policy(&endpoint, &user, AUTHENTICATED_USERS).unwrap();
    fixture.stop();
    assert!(probe_with_policy(&endpoint, &user, AUTHENTICATED_USERS).is_err());
}

#[test]
fn session_status_round_trip_is_typed_and_reads_the_published_view() {
    let user = current_user();
    let fixture = RpcFixture::start(&user);
    let status = query_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    assert_eq!(status.local_state, crate::packet::State::Down);
    assert_eq!(status.peer_state, None);
    assert_eq!(status.last_valid_receive, None);
    let next = query_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    assert_eq!(next.engine_instance_id, status.engine_instance_id);
    assert_eq!(next.publication_sequence, status.publication_sequence);
    fixture.stop();
}

#[test]
fn native_robust_stub_rejects_out_of_range_status_without_killing_the_client() {
    let user = current_user();
    let fixture = RpcFixture::start_status(&user, 0, 1);
    let error = query_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap_err();
    assert!(error.invalid_data(), "{error}");
    probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    fixture.stop();
}

#[test]
fn session_status_rejects_an_unauthorized_caller_and_bounds_cancellation() {
    let user = current_user();
    let rejected = RpcFixture::start(unrelated_account(&user));
    let error = query_with_policy(&rejected.endpoint, &user, AUTHENTICATED_USERS).unwrap_err();
    assert!(matches!(error, SessionStatusQueryError::Rpc(ref e) if e.raw_os_error() == Some(5)));
    rejected.stop();
    let delayed = RpcFixture::start_with_delay(&user, 2_500);
    let started = Instant::now();
    assert!(query_with_policy(&delayed.endpoint, &user, AUTHENTICATED_USERS).is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
    delayed.stop();
}

#[test]
fn rust_conversion_rejects_schema_errors_allowed_by_the_native_integer_range() {
    let user = current_user();
    let fixture = RpcFixture::start_status(&user, 0, 2);
    let error = query_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap_err();
    assert!(matches!(
        error,
        SessionStatusQueryError::InvalidData("schema")
    ));
    fixture.stop();
}

#[test]
#[ignore = "read-only native CIM/RPC coexistence; requires a normal Windows token"]
fn native_provider_traffic_preserves_fixed_rpc_policy_and_replacement_rejection() {
    const MIXED: &str = "BFD_RPC_PROVIDER_MIX_FIXTURE";
    if std::env::var_os(MIXED).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "local_rpc::tests::native_provider_traffic_preserves_fixed_rpc_policy_and_replacement_rejection",
                "--ignored", "--nocapture", "--test-threads=1"])
            .env(MIXED, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let user = current_user();
    let original = RpcFixture::start(&user);
    let endpoint = original.endpoint.clone();
    crate::bgp_broker::test_rpc_with_provider(|provider| {
        provider().unwrap();
        query_with_policy(&endpoint, &user, AUTHENTICATED_USERS).unwrap();
        provider().unwrap();
        original.stop();
        let replacement = restricted::RestrictedFixture::start(&endpoint, &user).unwrap();
        for _ in 0..3 {
            provider().unwrap();
            assert!(query_with_policy(&endpoint, &user, AUTHENTICATED_USERS).is_err());
        }
        replacement.stop().unwrap();
        let recovered = RpcFixture::start(&user);
        std::thread::scope(|scope| {
            let traffic = scope.spawn(|| {
                for _ in 0..3 {
                    provider().unwrap();
                }
            });
            for _ in 0..10 {
                query_with_policy(&recovered.endpoint, &user, AUTHENTICATED_USERS).unwrap();
            }
            traffic.join().unwrap();
        });
        recovered.stop();
    })
    .unwrap();
}

#[test]
fn fresh_client_processes_authenticate_server_account_and_group() {
    let user = current_user();
    let fixture = RpcFixture::start(&user);
    probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    // RPC can cache an authorization decision for the same actual server token
    // across bindings. A fresh process is required when changing expected policy.
    assert_eq!(
        isolated_client_result(
            &fixture.endpoint,
            unrelated_account(&user),
            AUTHENTICATED_USERS
        ),
        5
    );
    assert_eq!(
        isolated_client_result(&fixture.endpoint, &user, unrelated_account(&user)),
        5
    );
    probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    fixture.stop();
}

#[test]
fn callback_rejects_wrong_account_even_when_interface_acl_admits_its_group() {
    let user = current_user();
    // AU admits the real caller to the native interface. Only the per-call
    // exact-account check differs from the successful fixture.
    let fixture = RpcFixture::start(unrelated_account(&user));
    let error = probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    fixture.stop();
}

#[test]
fn delayed_native_call_is_cancelled_before_the_server_handler_finishes() {
    let user = current_user();
    let fixture = RpcFixture::start_with_delay(&user, 5_000);
    let started = Instant::now();
    let error = probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap_err();
    let elapsed = started.elapsed();
    assert_eq!(error.raw_os_error(), Some(1818), "{error}"); // RPC_S_CALL_CANCELLED
    assert!(
        elapsed < Duration::from_millis(4_500),
        "the client waited {elapsed:?} for a handler that sleeps five seconds"
    );
    // Unregister drains the still-running manager before the child exits. The
    // client has already returned, and no async call may retain its Rust buffers.
    fixture.stop();
}

#[test]
fn anonymous_native_client_is_denied() {
    use windows_sys::Win32::System::{
        Com::RPC_C_IMP_LEVEL_ANONYMOUS,
        Rpc::{RpcBindingFromStringBindingW, RPC_SECURITY_QOS},
    };

    let user = current_user();
    let fixture = RpcFixture::start(&user);
    let text = wide(&format!("ncalrpc:[{}]", fixture.endpoint));
    let mut raw = ptr::null_mut();
    // SAFETY: live terminated endpoint string and writable binding output.
    check(unsafe { RpcBindingFromStringBindingW(text.as_ptr(), &mut raw) }).unwrap();
    let binding = Binding {
        raw,
        bound: false,
        uncertain: retain_uncertain_binding,
    };
    // SAFETY: isolate this binding from cached authenticated associations.
    check(unsafe { RpcBindingSetOption(binding.raw, RPC_C_OPT_UNIQUE_BINDING, 1) }).unwrap();
    let qos = RPC_SECURITY_QOS {
        Version: 1,
        Capabilities: 0,
        IdentityTracking: RPC_C_QOS_IDENTITY_STATIC,
        ImpersonationType: RPC_C_IMP_LEVEL_ANONYMOUS,
    };
    // ncalrpc always upgrades the authentication level to packet privacy, even
    // when SetAuthInfo is omitted. Explicit anonymous QOS instead withholds the
    // caller's identity; WINNT honors this mode on ncalrpc.
    // https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos
    // SAFETY: live isolated binding and initialized native QOS; no custom
    // credentials or server identity pointers are borrowed by this test.
    check(unsafe {
        RpcBindingSetAuthInfoExW(
            binding.raw,
            ptr::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            RPC_C_AUTHZ_NONE,
            &qos,
        )
    })
    .unwrap();
    // SAFETY: the native wrapper retains asynchronous state until completion;
    // the uniquely owned classic binding remains live throughout the call.
    let status = unsafe { bfd_rpc_call_probe(binding.raw, CALL_TIMEOUT_MS) };
    let error = check(status as i32).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    drop(binding);
    fixture.stop();
}

#[test]
fn runtime_management_queries_are_denied_without_disrupting_the_probe() {
    use windows_sys::Win32::System::Rpc::{
        RpcBindingFromStringBindingW, RpcMgmtInqStats, RpcMgmtIsServerListening,
        RpcMgmtStatsVectorFree,
    };

    let user = current_user();
    let fixture = RpcFixture::start(&user);
    let text = wide(&format!("ncalrpc:[{}]", fixture.endpoint));
    let mut raw = ptr::null_mut();
    // SAFETY: terminated endpoint text and writable binding output.
    check(unsafe { RpcBindingFromStringBindingW(text.as_ptr(), &mut raw) }).unwrap();
    let binding = Binding {
        raw,
        bound: false,
        uncertain: retain_uncertain_binding,
    };
    let mut statistics = ptr::null_mut();
    // SAFETY: a live binding to the fixture and writable statistics output.
    let status = unsafe { RpcMgmtInqStats(binding.raw, &mut statistics) };
    if !statistics.is_null() {
        // SAFETY: the RPC runtime owns this returned vector until this release.
        check(unsafe { RpcMgmtStatsVectorFree(&mut statistics) }).unwrap();
    }
    assert_eq!(status, ERROR_ACCESS_DENIED as i32);
    // SAFETY: the classic binding remains live; this checks the separate runtime
    // management interface rather than the application interface's callback.
    let listening = unsafe { RpcMgmtIsServerListening(binding.raw) };
    assert_eq!(listening, ERROR_ACCESS_DENIED as i32);
    probe_with_policy(&fixture.endpoint, &user, AUTHENTICATED_USERS).unwrap();
    fixture.stop();
}

#[test]
#[ignore = "native RPC child fixture; started by the parent tests"]
fn rpc_fixture_child() {
    let Some(endpoint) = std::env::var_os(FIXTURE_ENDPOINT) else {
        return;
    };
    let endpoint = endpoint.into_string().unwrap();
    let user = std::env::var(FIXTURE_USER).unwrap();
    let marker = PathBuf::from(std::env::var_os(FIXTURE_MARKER).unwrap());
    let delay_ms = std::env::var(FIXTURE_DELAY).unwrap().parse().unwrap();
    TEST_PROBE_DELAY_MS.store(delay_ms, Ordering::Relaxed);
    TEST_STATUS_CORRUPT.store(
        std::env::var(FIXTURE_CORRUPT)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        Ordering::Relaxed,
    );
    // Only this disposable child loses privileges. Positive probes therefore
    // exercise RPC registration and Authz checks without SeImpersonatePrivilege,
    // SeDebugPrivilege, or any other privilege the service removes at startup.
    crate::runtime::drop_privileges().unwrap();
    let (_publisher, observer) = status::tests::fixture();
    let server =
        LocalRpcServer::with_status_policy(&endpoint, &user, AUTHENTICATED_USERS, Some(observer))
            .unwrap();
    fs::write(&marker, b"ready").unwrap();
    if let Some(stop_marker) = std::env::var_os(FIXTURE_STOP_MARKER) {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if fs::read(&stop_marker).is_ok_and(|bytes| bytes == b"stop") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "RPC fixture stop marker timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    } else {
        let mut command = String::new();
        std::io::stdin().read_line(&mut command).unwrap();
        assert_eq!(command, "stop\n");
    }
    drop(server);
    fs::write(marker, b"stopped").unwrap();
}

#[test]
#[ignore = "native RPC client fixture; started by the parent tests"]
fn rpc_fixture_client_child() {
    let Some(endpoint) = std::env::var_os(CLIENT_ENDPOINT) else {
        return;
    };
    let endpoint = endpoint.into_string().unwrap();
    let user = std::env::var(CLIENT_USER).unwrap();
    let group = std::env::var(CLIENT_GROUP).unwrap();
    let result = PathBuf::from(std::env::var_os(CLIENT_RESULT).unwrap());
    crate::runtime::drop_rpc_privileges().unwrap();
    let status = probe_with_policy(&endpoint, &user, &group)
        .err()
        .map_or(0, |error| error.raw_os_error().unwrap_or(-1));
    fs::write(result, status.to_string()).unwrap();
}

mod restricted;
mod seh;
