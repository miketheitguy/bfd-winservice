//! The exact privilege policy installed only after the MSI transaction succeeds.
use std::io::{self, Write};
use windows_service::service::Service;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_REQUIRED_PRIVILEGES_INFOW,
};

fn minimum_multisz() -> Vec<u16> {
    "SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0\0"
        .encode_utf16()
        .collect()
}

pub(super) fn set_minimum(service: &Service) -> io::Result<()> {
    let mut names = minimum_multisz();
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: names.as_mut_ptr(),
    };
    // SAFETY: the fixed BFD service handle has CHANGE_CONFIG. The aligned input
    // and its double-NUL-terminated UTF-16 MULTI_SZ stay live through this call.
    // SCM copies the policy; this does not alter the currently running token.
    if unsafe {
        ChangeServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&info as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn commit_with(
    set_minimum: impl FnOnce() -> io::Result<()>,
    cleanup: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    set_minimum()?;
    // Windows does not document how to reset an absent/default privilege policy.
    // Once SCM accepts the new policy, a cleanup error must not trigger rollback
    // that would need that unsupported reset. Retain and report the snapshot;
    // a later install fails safely until an administrator resolves the file.
    if let Err(error) = cleanup() {
        cleanup_diagnostic(&mut io::stderr().lock(), &error);
    }
    Ok(())
}

fn cleanup_diagnostic(writer: &mut impl Write, error: &io::Error) {
    let _ = writeln!(
        writer,
        "BFD service privileges were committed, but service-policy.rollback \
         could not be removed: {error}. Resolve the protected snapshot before \
         another install or repair."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn required_privileges_is_exact_minimum_terminated_multisz() {
        let expected: Vec<u16> = "SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0\0"
            .encode_utf16()
            .collect();
        assert_eq!(minimum_multisz(), expected);
        assert!(!String::from_utf16(&minimum_multisz())
            .unwrap()
            .contains("SeImpersonatePrivilege"));
    }

    #[test]
    fn commit_sets_minimum_before_cleanup_and_preserves_snapshot_on_api_failure() {
        let calls = RefCell::new(Vec::new());
        commit_with(
            || {
                calls.borrow_mut().push("set");
                Ok(())
            },
            || {
                calls.borrow_mut().push("cleanup");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["set", "cleanup"]);
        calls.borrow_mut().clear();
        assert!(commit_with(
            || {
                calls.borrow_mut().push("set");
                Err(io::Error::other("SCM rejected policy"))
            },
            || {
                calls.borrow_mut().push("cleanup");
                Ok(())
            },
        )
        .is_err());
        assert_eq!(*calls.borrow(), ["set"]);
    }

    #[test]
    fn snapshot_cleanup_failure_cannot_fail_commit_after_privilege_change() {
        let calls = RefCell::new(Vec::new());
        assert!(commit_with(
            || {
                calls.borrow_mut().push("set");
                Ok(())
            },
            || {
                calls.borrow_mut().push("cleanup");
                Err(io::Error::other("snapshot still locked"))
            },
        )
        .is_ok());
        assert_eq!(*calls.borrow(), ["set", "cleanup"]);
    }

    #[test]
    fn post_commit_diagnostic_ignores_broken_stderr() {
        struct BrokenWriter(bool);
        impl Write for BrokenWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                self.0 = true;
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed stderr"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = BrokenWriter(false);
        cleanup_diagnostic(&mut writer, &io::Error::other("snapshot still locked"));
        assert!(writer.0);
    }
}
