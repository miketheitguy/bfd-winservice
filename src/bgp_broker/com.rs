//! Private COM lifetime and security for the BGP broker's native MI client.
//!
//! This module registers no class factory or Automation interface; BFD hosts
//! its private local RPC interface and uses no COM. Local SYSTEM is the only
//! principal admitted by the broker's descriptor.
#![allow(unsafe_code)] // COM lifetime and Windows security calls are confined here.

use std::{
    io,
    marker::PhantomData,
    ptr,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};
use windows::{
    core::{w, Error, Result, BOOL},
    Win32::{
        Foundation::{LocalFree, E_INVALIDARG, HLOCAL, RPC_E_TOO_LATE},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorGroup,
            SetSecurityDescriptorOwner, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
        },
        System::Com::{
            CoInitializeEx, CoInitializeSecurity, CoUninitialize, COINIT_MULTITHREADED,
            EOAC_DISABLE_AAA, EOAC_NO_CUSTOM_MARSHAL, EOLE_AUTHENTICATION_CAPABILITIES,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_IMP_LEVEL_IDENTIFY,
        },
    },
};

// COM process security cannot be reset, even after its hosting thread exits.
static SECURITY_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Keeps a dedicated MTA initialized until the broker's providers finish.
pub(super) struct ComHost {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ComHost {
    /// Completes explicit process security before starting any MI operation.
    pub(super) fn initialize() -> io::Result<Self> {
        let (stop, stopped) = mpsc::channel();
        let (ready, initialized) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("bfd-broker-com".into())
            .spawn(move || {
                let _apartment = match ComApartment::initialize() {
                    Ok(apartment) => apartment,
                    Err(error) => {
                        let _ = ready.send(Err(com_error("initialize COM security", error)));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                // MTA calls run on COM's RPC threads; no message pump is needed.
                let _ = stopped.recv();
                // Apartment Drop calls CoUninitialize on its owning thread.
            })?;
        // Own the worker before waiting so every error path joins it through Drop.
        let host = Self {
            stop,
            worker: Some(worker),
        };
        initialized
            .recv()
            .map_err(|_| io::Error::other("COM thread exited before initialization completed"))??;
        Ok(host)
    }

    /// Uninitializes COM on its owner thread and joins that thread.
    pub(super) fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.send(());
            worker
                .join()
                .map_err(|_| io::Error::other("COM thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ComHost {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn com_error(context: &str, error: Error) -> io::Error {
    // Keep COM's error-info object and its teardown on the originating thread.
    io::Error::other(format!("{context} ({:#010x}): {error}", error.code().0))
}

// Never moves outside the dedicated thread, including on initialization failure.
struct ComApartment {
    // COM initialization and uninitialization must occur on the same thread.
    _thread_bound: PhantomData<Rc<()>>,
}

impl ComApartment {
    fn initialize() -> Result<Self> {
        // SAFETY: no reserved data is passed; this thread owns the matching teardown.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        let apartment = Self {
            _thread_bound: PhantomData,
        };
        initialize_security()?;
        // Apply both exception and unmarshaling policies before opening MI.
        crate::com_security::configure_global_options()?;
        Ok(apartment)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: construction succeeded in CoInitializeEx on this same thread;
        // PhantomData<Rc<()>> prevents safe transfer to another thread.
        unsafe { CoUninitialize() };
    }
}

// COM requires an absolute descriptor. Borrow its SID/ACL fields from the
// self-relative SDDL allocation, keeping that allocation alive through initialization.
fn initialize_security() -> Result<()> {
    // One attempt per process, including failed attempts. No later host can retry
    // or accept different defaults. The startup channel publishes successful
    // initialization; this flag protects only the right to attempt it.
    if SECURITY_ATTEMPTED.swap(true, Ordering::Relaxed) {
        return Err(RPC_E_TOO_LATE.into());
    }
    let mut relative = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the SDDL is static and terminated; the output pointer is valid.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("O:SYG:SYD:(A;;0x3;;;SY)"),
            SDDL_REVISION_1,
            &mut relative,
            None,
        )?
    };
    let relative = SecurityAllocation(relative);
    let mut absolute = SECURITY_DESCRIPTOR::default();
    let descriptor = PSECURITY_DESCRIPTOR(ptr::from_mut(&mut absolute).cast());
    let mut owner = PSID::default();
    let mut group = PSID::default();
    let mut dacl = ptr::null_mut();
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    // SAFETY: the relative descriptor came from Windows and remains allocated;
    // all outputs point to writable locals. The absolute descriptor borrows its
    // SID/ACL pointers only until CoInitializeSecurity copies their contents.
    unsafe {
        GetSecurityDescriptorOwner(relative.0, &mut owner, &mut defaulted)?;
        GetSecurityDescriptorGroup(relative.0, &mut group, &mut defaulted)?;
        GetSecurityDescriptorDacl(relative.0, &mut present, &mut dacl, &mut defaulted)?;
    }
    if !present.as_bool() || dacl.is_null() || owner.0.is_null() || group.0.is_null() {
        return Err(E_INVALIDARG.into());
    }
    // SAFETY: the descriptor has a non-null owner, group, and DACL, all borrowed
    // from the live SDDL allocation; CoInitializeSecurity copies these values.
    unsafe {
        InitializeSecurityDescriptor(descriptor, SDDL_REVISION_1)?;
        SetSecurityDescriptorOwner(descriptor, Some(owner), false)?;
        SetSecurityDescriptorGroup(descriptor, Some(group), false)?;
        SetSecurityDescriptorDacl(descriptor, true, Some(dacl), false)?;
        CoInitializeSecurity(
            Some(descriptor),
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            // Least privilege for outgoing proxies, not a cap on incoming
            // callers. The local MI client explicitly opts into IMPERSONATE
            // on its own destination; this server never impersonates callers.
            RPC_C_IMP_LEVEL_IDENTIFY,
            None,
            EOLE_AUTHENTICATION_CAPABILITIES(EOAC_DISABLE_AAA.0 | EOAC_NO_CUSTOM_MARSHAL.0),
            None,
        )
    }
}

struct SecurityAllocation(PSECURITY_DESCRIPTOR);

impl Drop for SecurityAllocation {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by the SDDL conversion function
        // and must be freed once with LocalFree; no borrowed SID/ACL remains in use.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn private_host_initializes_security_once() {
        const HOST: &str = "BFD_TEST_COM_PRIVATE_HOST";
        if std::env::var_os(HOST).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bgp_broker::com::tests::private_host_initializes_security_once",
                    "--nocapture",
                ])
                .env(HOST, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let server = ComHost::initialize().unwrap();
        // Process security has been claimed and cannot be applied again.
        assert!(ComHost::initialize()
            .err()
            .unwrap()
            .to_string()
            .contains("0x80010119"));
        server.shutdown().unwrap();
    }

    #[test]
    fn dedicated_host_rejects_preexisting_process_security() {
        const HOST: &str = "BFD_TEST_COM_EXISTING_SECURITY";
        if std::env::var_os(HOST).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bgp_broker::com::tests::dedicated_host_rejects_preexisting_process_security",
                    "--nocapture",
                ])
                .env(HOST, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Simulate another library initializing process security before startup.
        // SAFETY: no reserved data. The guard balances initialization on this
        // thread, including if an assertion unwinds. No class is registered.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .unwrap();
        let _apartment = ComApartment {
            _thread_bound: PhantomData,
        };
        // SAFETY: all reserved pointers are null and constants are valid. This
        // isolated process exposes no server; its security is set by this fixture.
        unsafe {
            CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                RPC_C_IMP_LEVEL_IDENTIFY,
                None,
                windows::Win32::System::Com::EOAC_NONE,
                None,
            )
        }
        .unwrap();
        let error = ComHost::initialize().err().unwrap();
        assert!(error.to_string().contains("0x80010119")); // RPC_E_TOO_LATE
    }
}
