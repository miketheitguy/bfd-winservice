//! The exact privilege policy installed only after the MSI transaction succeeds.
use std::{
    io::{self, Write},
    ptr,
};
use windows_service::service::Service;
use windows_sys::{
    core::w,
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::{
            Registry::{
                RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
                HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_MULTI_SZ,
            },
            Services::{
                ChangeServiceConfig2W, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                SERVICE_REQUIRED_PRIVILEGES_INFOW,
            },
        },
    },
};

pub(super) const MAX_UNITS: usize = 2048;

// None preserves an absent/default policy; Some preserves the exact MULTI_SZ,
// including a pre-existing explicit empty registry value.
pub(super) type Policy = Option<Vec<u16>>;

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: owns one successful RegOpenKeyExW result.
        unsafe { RegCloseKey(self.0) };
    }
}

fn key(name: &str, access: u32) -> io::Result<Key> {
    if !super::NAMES.contains(&name) {
        return Err(io::Error::other("unexpected service privilege target"));
    }
    let path: Vec<u16> = format!("SYSTEM\\CurrentControlSet\\Services\\{name}")
        .encode_utf16()
        .chain([0])
        .collect();
    let mut handle = ptr::null_mut();
    // SAFETY: terminated fixed service path and writable owned-handle output.
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, access, &mut handle) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(Key(handle))
}

pub(super) fn validate(units: &[u16]) -> io::Result<()> {
    if units.len() > MAX_UNITS {
        return Err(io::Error::other("service privilege list is too large"));
    }
    if units.iter().all(|unit| *unit == 0) {
        return Ok(());
    }
    if units[0] == 0
        || !units.ends_with(&[0, 0])
        || units[..units.len() - 2]
            .windows(2)
            .any(|pair| pair == [0, 0])
    {
        return Err(io::Error::other("invalid service privilege MULTI_SZ"));
    }
    for name in units[..units.len() - 1].split(|unit| *unit == 0) {
        if !name.is_empty() {
            String::from_utf16(name).map_err(io::Error::other)?;
        }
    }
    Ok(())
}

pub(super) fn query(name: &str) -> io::Result<Policy> {
    let key = key(name, KEY_QUERY_VALUE)?;
    let mut kind = 0;
    let mut bytes = 0;
    // SAFETY: live key, static value name, and writable size/type outputs.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            w!("RequiredPrivileges"),
            ptr::null(),
            &mut kind,
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if kind != REG_MULTI_SZ || bytes as usize > MAX_UNITS * 2 || bytes % 2 != 0 {
        return Err(io::Error::other("invalid service privilege registry value"));
    }
    let mut units = vec![0u16; bytes as usize / 2];
    let capacity = bytes;
    // SAFETY: aligned initialized storage has capacity bytes; Windows reports
    // any growth as an error. The returned type and byte count are rechecked.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            w!("RequiredPrivileges"),
            ptr::null(),
            &mut kind,
            units.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if kind != REG_MULTI_SZ || bytes > capacity || bytes % 2 != 0 {
        return Err(io::Error::other("service privilege registry value changed"));
    }
    units.truncate(bytes as usize / 2);
    validate(&units)?;
    Ok(Some(units))
}

pub(super) fn restore(service: &Service, name: &str, policy: &Policy) -> io::Result<()> {
    if query(name)? == *policy {
        return Ok(());
    }
    let empty = [0, 0];
    let units = policy.as_deref().unwrap_or(&empty);
    validate(units)?;
    let is_empty = units.iter().all(|unit| *unit == 0);
    // SCM accepts an empty list to clear its explicit policy. Verify the result
    // rather than substituting a guessed list of account-default privileges.
    set(service, if is_empty { &empty } else { units })?;
    if policy.is_some() && is_empty {
        let key = key(name, KEY_SET_VALUE)?;
        // SCM removes empty policies from the registry. Restore only the exact
        // empty representation after clearing SCM's policy through its API.
        // SAFETY: fixed value name, live key, bounded UTF-16 byte storage.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                w!("RequiredPrivileges"),
                0,
                REG_MULTI_SZ,
                units.as_ptr().cast(),
                (units.len() * 2) as u32,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    if query(name)? != *policy {
        return Err(io::Error::other(
            "service privilege rollback did not restore the exact policy",
        ));
    }
    Ok(())
}

fn set(service: &Service, units: &[u16]) -> io::Result<()> {
    let mut names = units.to_vec();
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: names.as_mut_ptr(),
    };
    // SAFETY: the fixed service handle has CHANGE_CONFIG. The aligned input
    // and double-NUL-terminated MULTI_SZ stay live while SCM copies the policy.
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

fn minimum_multisz() -> Vec<u16> {
    crate::runtime::REQUIRED_PRIVILEGE
        .encode_utf16()
        .chain([0, 0])
        .collect()
}

pub(super) fn set_minimum(service: &Service) -> io::Result<()> {
    set(service, &minimum_multisz())
}

pub(super) fn commit_with(
    set_minimum: impl FnOnce() -> io::Result<()>,
    cleanup: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    set_minimum()?;
    // Once SCM accepts both policies, a cleanup error need not trigger rollback.
    // Retain and report the snapshot;
    // a later install fails safely until an administrator resolves the file.
    if let Err(error) = cleanup() {
        cleanup_diagnostic(&mut io::stderr().lock(), &error);
    }
    Ok(())
}

fn cleanup_diagnostic(writer: &mut impl Write, error: &io::Error) {
    let _ = writeln!(
        writer,
        "BFD and broker service privileges were committed, but service-policy.rollback \
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
        let expected: Vec<u16> = "SeChangeNotifyPrivilege\0\0".encode_utf16().collect();
        assert_eq!(minimum_multisz(), expected);
        assert!(!String::from_utf16(&minimum_multisz())
            .unwrap()
            .contains("SeImpersonatePrivilege"));
    }

    #[test]
    fn rollback_privileges_reject_malformed_or_oversized_multisz() {
        for units in [
            vec![1],
            vec![0, 1, 0, 0],
            vec![1, 0, 0, 1, 0, 0],
            vec![0xd800, 0, 0],
            vec![0; MAX_UNITS + 1],
        ] {
            assert!(validate(&units).is_err());
        }
        for units in [vec![], vec![0], vec![0, 0], minimum_multisz()] {
            validate(&units).unwrap();
        }
    }

    #[test]
    fn partial_service_privilege_commit_keeps_snapshot_for_rollback() {
        let calls = RefCell::new(Vec::new());
        assert!(commit_with(
            || {
                calls.borrow_mut().push("bfd changed");
                calls.borrow_mut().push("broker rejected");
                Err(io::Error::other("second SCM mutation failed"))
            },
            || {
                calls.borrow_mut().push("snapshot removed");
                Ok(())
            },
        )
        .is_err());
        assert_eq!(*calls.borrow(), ["bfd changed", "broker rejected"]);
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
