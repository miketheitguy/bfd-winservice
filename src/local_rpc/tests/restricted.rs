//! Native replacement-server regression. The replacement keeps the real account
//! but disables an existing group; it never acquires a service SID or privilege.

use super::*;
use std::{
    ffi::OsString,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_INFORMATION, STARTUPINFOW,
    },
};

pub(super) struct RestrictedFixture {
    process: OwnedHandle,
    _directory: TempDir,
    marker: PathBuf,
    stop: PathBuf,
}

impl RestrictedFixture {
    pub(super) fn start(endpoint: &str, caller_user: &str) -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let marker = directory.path().join("rpc-state");
        let stop = directory.path().join("stop");
        let token = reduced_token()?;
        let executable = std::env::current_exe()?;
        let application: Vec<u16> = executable.as_os_str().encode_wide().chain([0]).collect();
        let mut command = OsString::from("\"");
        command.push(executable.as_os_str());
        command.push(
            "\" --exact local_rpc::tests::rpc_fixture_child --ignored --nocapture --test-threads=1",
        );
        let mut command: Vec<u16> = command.encode_wide().chain([0]).collect();
        let environment = environment_block(&[
            (FIXTURE_ENDPOINT, OsString::from(endpoint)),
            (FIXTURE_USER, OsString::from(caller_user)),
            (FIXTURE_MARKER, marker.as_os_str().to_owned()),
            (FIXTURE_STOP_MARKER, stop.as_os_str().to_owned()),
            (FIXTURE_DELAY, OsString::from("0")),
        ]);
        let startup = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: the token is a restricted version of this process's own
        // primary token. No special privilege is enabled or acquired. All native
        // input buffers remain live, the command line is writable, environment
        // is double-NUL-terminated UTF-16, and output storage is initialized.
        // No handles are inherited; readiness and Stop use private marker files.
        if unsafe {
            CreateProcessAsUserW(
                token.as_raw_handle(),
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                ptr::null(),
                &startup,
                &mut information,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transfers uniquely owned process/thread
        // handles. Close the unused thread handle immediately.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
        // SAFETY: the same successful creation transfers this distinct handle.
        drop(unsafe { OwnedHandle::from_raw_handle(information.hThread) });
        let fixture = Self {
            process,
            _directory: directory,
            marker,
            stop,
        };
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if fs::read(&fixture.marker).is_ok_and(|bytes| bytes == b"ready") {
                return Ok(fixture);
            }
            // SAFETY: the owned process handle remains live and supports waits.
            match unsafe { WaitForSingleObject(fixture.process.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => {
                    return Err(io::Error::other(format!(
                        "restricted RPC fixture exited before readiness: {}",
                        fixture.exit_code()?
                    )));
                }
                WAIT_TIMEOUT => {}
                _ => return Err(io::Error::last_os_error()),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "restricted RPC fixture did not become ready",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn exit_code(&self) -> io::Result<u32> {
        let mut result = 0;
        // SAFETY: owned process handle and writable native exit-code output.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut result) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    pub(super) fn stop(self) -> io::Result<()> {
        fs::write(&self.stop, b"stop")?;
        // SAFETY: the process handle is live; fixture shutdown has a fixed bound.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 20_000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "restricted RPC fixture did not stop",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
        let code = self.exit_code()?;
        if code != 0 {
            return Err(io::Error::other(format!(
                "restricted RPC fixture exited with {code}"
            )));
        }
        if fs::read(&self.marker)? != b"stopped" {
            return Err(io::Error::other("restricted RPC fixture did not drain"));
        }
        Ok(())
    }
}

impl Drop for RestrictedFixture {
    fn drop(&mut self) {
        // SAFETY: the handle belongs only to this disposable test child. Failed
        // assertions and startup failures must not leave a listener behind.
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
            // SAFETY: termination is restricted to the child this fixture created.
            let _ = unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
            // SAFETY: keep temporary files alive until termination is observed.
            let _ = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 20_000) };
        }
    }
}

fn reduced_token() -> io::Result<OwnedHandle> {
    let mut raw = ptr::null_mut();
    // SAFETY: own process pseudo-handle and writable output. These are the
    // documented token handle rights required by CreateProcessAsUserW.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut raw,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transfers one uniquely owned handle.
    let original = unsafe { OwnedHandle::from_raw_handle(raw) };
    let authenticated_users = LocalAllocation::sid(AUTHENTICATED_USERS)?;
    let disabled = SID_AND_ATTRIBUTES {
        Sid: authenticated_users.0,
        Attributes: 0,
    };
    let mut raw = ptr::null_mut();
    // SAFETY: all token/SID allocations remain live, and a single correctly
    // sized disable entry narrows the current account's rights. This API cannot
    // grant an enabled service SID or privilege and never changes the parent.
    if unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &disabled,
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut raw,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful restriction transfers one uniquely owned primary token.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn environment_block(overrides: &[(&str, OsString)]) -> Vec<u16> {
    let mut variables: Vec<_> = std::env::vars_os().collect();
    for (name, value) in overrides {
        variables.retain(|(existing, _)| !existing.to_string_lossy().eq_ignore_ascii_case(name));
        variables.push((OsString::from(*name), value.clone()));
    }
    variables.sort_by_cached_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut block = Vec::new();
    for (name, value) in variables {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

#[test]
fn fixed_policy_denies_same_account_replacement_with_its_group_disabled() {
    let user = current_user();
    let original = RpcFixture::start(&user);
    let endpoint = original.endpoint.clone();
    query_with_policy(&endpoint, &user, AUTHENTICATED_USERS).unwrap();
    original.stop();
    let replacement = RestrictedFixture::start(&endpoint, &user).unwrap();
    // Expected policy stays identical across every call. The server's actual
    // native token changes, and an old association must never produce success.
    // A stale association may first report CALL_FAILED_DNE before fresh binds
    // report ACCESS_DENIED, so check failure of the entire status operation.
    for _ in 0..3 {
        assert!(query_with_policy(&endpoint, &user, AUTHENTICATED_USERS).is_err());
    }
    assert_eq!(
        isolated_client_result(&endpoint, &user, AUTHENTICATED_USERS),
        5
    );
    replacement.stop().unwrap();
}
