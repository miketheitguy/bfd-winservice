//! Local, read-only Automation access to the service's live BFD session.
//!
//! The MSI registers `BfdWinService.SessionState` as an out-of-process COM
//! service. Its `IDispatch` exposes `State` (LONG), `StateName` (BSTR), and
//! `GetState()` (LONG). State codes follow RFC 5880: AdminDown=0, Down=1,
//! Init=2, Up=3. Type information is built in memory; no registered type library
//! or custom proxy is required for late binding.
//!
//! Authenticated callers include standard users. The factory and dispatch objects
//! receive only a read-only state observer, never engine, logging, file, registry,
//! or management capabilities. Caller-directed resource access would require a
//! separate authorization design and scoped COM impersonation on the RPC thread.
#![allow(unsafe_code)] // COM ABI and Windows security calls are confined here.
#![allow(clippy::not_unsafe_ptr_arg_deref)] // Generated COM implementation traits use safe signatures.

use crate::{packet::State, runtime::StateObserver};
use std::{
    ffi::c_void,
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
    core::{implement, w, Error, IUnknown, Interface, Ref, Result, BOOL, GUID, PCWSTR},
    Win32::{
        Foundation::{
            LocalFree, CLASS_E_NOAGGREGATION, CO_E_OBJNOTCONNECTED, DISP_E_BADINDEX,
            DISP_E_BADPARAMCOUNT, DISP_E_MEMBERNOTFOUND, DISP_E_NONAMEDARGS,
            DISP_E_UNKNOWNINTERFACE, DISP_E_UNKNOWNNAME, E_INVALIDARG, E_POINTER, HLOCAL,
            RPC_E_TOO_LATE,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorGroup,
            SetSecurityDescriptorOwner, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
        },
        System::{
            Com::{
                CoInitializeEx, CoInitializeSecurity, CoRegisterClassObject, CoRevokeClassObject,
                CoUninitialize, IClassFactory, IClassFactory_Impl, IDispatch, IDispatch_Impl,
                ITypeInfo, CC_STDCALL, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, DISPATCH_FLAGS,
                DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPPARAMS, ELEMDESC, EOAC_DISABLE_AAA,
                EOAC_NO_CUSTOM_MARSHAL, EOLE_AUTHENTICATION_CAPABILITIES, EXCEPINFO, FUNCDESC,
                FUNC_DISPATCH, INVOKE_FUNC, INVOKE_PROPERTYGET, REGCLS_MULTIPLEUSE,
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_IMP_LEVEL_IDENTIFY, SYS_WIN64,
                TKIND_DISPATCH, TYPEDESC,
            },
            Ole::{CreateTypeLib2, TYPEFLAG_FDISPATCHABLE},
            Variant::{VARIANT, VT_BSTR, VT_I4},
        },
    },
};

/// Stable class identifier for `BfdWinService.SessionState`.
pub const SESSION_STATE_CLSID: GUID = GUID::from_u128(0x4b19a10f_8cd1_46f1_a1ea_6c68ecba7657);
/// Stable Automation programmatic identifier installed by the MSI.
pub const SESSION_STATE_PROGID: &str = "BfdWinService.SessionState";

const STATE_ID: i32 = 1;
const STATE_NAME_ID: i32 = 2;
const GET_STATE_ID: i32 = 3;
const UNKNOWN_ID: i32 = -1;
// COM process security cannot be reset, even after its hosting thread exits.
static SECURITY_ATTEMPTED: AtomicBool = AtomicBool::new(false);
// Distinguishes this in-memory type description in Automation clients' caches.
const SESSION_STATE_TYPE_ID: GUID = GUID::from_u128(0xf8efee55_bd2b_42f3_ad46_f97a4e0b62e3);

/// Controls a dedicated MTA thread that owns COM initialization and registration.
/// Initialization completes process security before returning to the caller.
/// Shut it down after the BFD worker and management providers have finished.
pub struct ComServer {
    commands: mpsc::Sender<ComCommand>,
    worker: Option<thread::JoinHandle<()>>,
}

enum ComCommand {
    Register {
        clsid: GUID,
        state: StateObserver,
        reply: mpsc::SyncSender<io::Result<()>>,
    },
    Shutdown,
}

impl ComServer {
    /// Starts the COM thread and waits for MTA and process security initialization.
    /// Call once during service startup, before creating management workers.
    ///
    /// # Errors
    /// Returns thread creation, COM initialization, or security errors. Security
    /// already initialized elsewhere is an error; system defaults are never accepted.
    pub fn initialize() -> io::Result<Self> {
        let (commands, receiver) = mpsc::channel();
        let (ready, initialized) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("bfd-com".into())
            .spawn(move || {
                let mut apartment = match ComApartment::initialize() {
                    Ok(apartment) => apartment,
                    Err(error) => {
                        let _ = ready.send(Err(com_error("initialize COM security", error)));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                // An MTA uses COM's RPC threads for incoming calls and needs no
                // window-message pump. This thread waits only for lifecycle commands.
                while let Ok(command) = receiver.recv() {
                    match command {
                        ComCommand::Register {
                            clsid,
                            state,
                            reply,
                        } => {
                            let result = apartment
                                .register_class(&clsid, state)
                                .map_err(|error| com_error("register COM class", error));
                            let _ = reply.send(result);
                        }
                        ComCommand::Shutdown => break,
                    }
                }
                // Apartment Drop revokes the class and calls CoUninitialize here.
            })?;
        // Own the worker before waiting so every error path joins it through Drop.
        let server = Self {
            commands,
            worker: Some(worker),
        };
        initialized
            .recv()
            .map_err(|_| io::Error::other("COM thread exited before initialization completed"))??;
        Ok(server)
    }

    /// Registers the live state on the COM thread, waiting for the result.
    ///
    /// # Errors
    /// Returns registration errors or an error if the COM thread has exited.
    pub fn register(&mut self, state: StateObserver) -> io::Result<()> {
        self.register_class(SESSION_STATE_CLSID, state)
    }

    fn register_class(&mut self, clsid: GUID, state: StateObserver) -> io::Result<()> {
        let (reply, result) = mpsc::sync_channel(1);
        self.commands
            .send(ComCommand::Register {
                clsid,
                state,
                reply,
            })
            .map_err(|_| io::Error::other("COM thread exited before class registration"))?;
        result
            .recv()
            .map_err(|_| io::Error::other("COM thread exited during class registration"))?
    }

    /// Revokes the class, uninitializes COM on its owner thread, and joins that thread.
    ///
    /// # Errors
    /// Returns an error if the COM thread panicked. Drop provides the same cleanup
    /// for startup failures and unwinding, without returning an error.
    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker.take() {
            let _ = self.commands.send(ComCommand::Shutdown);
            worker
                .join()
                .map_err(|_| io::Error::other("COM thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ComServer {
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
    cookie: Option<u32>,
    // COM initialization and uninitialization must occur on the same thread.
    _thread_bound: PhantomData<Rc<()>>,
}

impl ComApartment {
    fn initialize() -> Result<Self> {
        // SAFETY: no reserved data is passed; this thread owns the matching teardown.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        let server = Self {
            cookie: None,
            _thread_bound: PhantomData,
        };
        initialize_security()?;
        Ok(server)
    }

    fn register_class(&mut self, clsid: &GUID, state: StateObserver) -> Result<()> {
        if self.cookie.is_some() {
            return Err(E_INVALIDARG.into());
        }
        let factory: IClassFactory = StateFactory { state }.into();
        // SAFETY: COM is initialized on this thread. The factory has a generated
        // IClassFactory vtable and owns its shared state. COM retains its own ref.
        self.cookie = Some(unsafe {
            CoRegisterClassObject(clsid, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE)?
        });
        Ok(())
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if let Some(cookie) = self.cookie.take() {
            // SAFETY: this cookie belongs to this registration on this initialized
            // thread. Revoking prevents new activations during service teardown.
            let _ = unsafe { CoRevokeClassObject(cookie) };
        }
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
    // COM execute + execute-local only (0x3): no remote or anonymous access.
    // SAFETY: the SDDL is static and terminated; the output pointer is valid.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("O:SYG:SYD:(A;;0x3;;;SY)(A;;0x3;;;BA)(A;;0x3;;;AU)"),
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

#[implement(IClassFactory)]
struct StateFactory {
    state: StateObserver,
}

impl IClassFactory_Impl for StateFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<'_, IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> Result<()> {
        if object.is_null() {
            return Err(E_POINTER.into());
        }
        // SAFETY: COM callers provide a writable output slot when non-null.
        unsafe { object.write(ptr::null_mut()) };
        if iid.is_null() {
            return Err(E_POINTER.into());
        }
        if !outer.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let dispatch: IDispatch = SessionDispatch {
            state: self.state.clone(),
        }
        .into();
        // SAFETY: COM supplies a valid IID and writable output. QueryInterface
        // transfers one reference to the caller, independent of this local ref.
        unsafe { dispatch.query(iid, object) }.ok()
    }

    fn LockServer(&self, _lock: BOOL) -> Result<()> {
        // SCM owns the service lifetime; client references never prevent Stop.
        Ok(())
    }
}

#[implement(IDispatch)]
struct SessionDispatch {
    // Security boundary: COM requests can read a snapshot, but cannot control the
    // LocalSystem engine or supply paths to its privileged resource operations.
    state: StateObserver,
}

impl IDispatch_Impl for SessionDispatch_Impl {
    fn GetTypeInfoCount(&self) -> Result<u32> {
        Ok(1)
    }

    fn GetTypeInfo(&self, index: u32, _locale: u32) -> Result<ITypeInfo> {
        if index != 0 {
            return Err(DISP_E_BADINDEX.into());
        }
        create_type_info()
    }

    fn GetIDsOfNames(
        &self,
        iid: *const GUID,
        names: *const PCWSTR,
        count: u32,
        _locale: u32,
        ids: *mut i32,
    ) -> Result<()> {
        // SAFETY: the COM ABI provides a valid IID when non-null.
        unsafe { check_dispatch_iid(iid) }?;
        if count == 0 {
            return Err(E_INVALIDARG.into());
        }
        if names.is_null() || ids.is_null() {
            return Err(E_POINTER.into());
        }
        let mut unknown = false;
        for index in 0..count as usize {
            // SAFETY: COM guarantees arrays of count elements. Only the first
            // name identifies a member; remaining names would be parameters,
            // which this zero-argument interface does not support.
            let name = unsafe { names.add(index).read() };
            let id = if index == 0 && !name.is_null() {
                // SAFETY: COM name strings are terminated UTF-16 and live for this call.
                let name = unsafe { name.to_string() }.map_err(|_| Error::from(E_INVALIDARG))?;
                if name.eq_ignore_ascii_case("State") {
                    STATE_ID
                } else if name.eq_ignore_ascii_case("StateName") {
                    STATE_NAME_ID
                } else if name.eq_ignore_ascii_case("GetState") {
                    GET_STATE_ID
                } else {
                    UNKNOWN_ID
                }
            } else {
                UNKNOWN_ID
            };
            unknown |= id == UNKNOWN_ID;
            // SAFETY: ids has count writable slots, supplied by the COM caller.
            unsafe { ids.add(index).write(id) };
        }
        if unknown {
            Err(DISP_E_UNKNOWNNAME.into())
        } else {
            Ok(())
        }
    }

    fn Invoke(
        &self,
        id: i32,
        iid: *const GUID,
        _locale: u32,
        flags: DISPATCH_FLAGS,
        params: *const DISPPARAMS,
        result: *mut VARIANT,
        _exception: *mut EXCEPINFO,
        _argument_error: *mut u32,
    ) -> Result<()> {
        if !result.is_null() {
            // SAFETY: a non-null COM output points to writable VARIANT storage.
            // Initialize even on failure so the marshaler can safely clean up.
            unsafe { result.write(VARIANT::default()) };
        }
        // SAFETY: the COM ABI provides a valid IID when non-null.
        unsafe { check_dispatch_iid(iid) }?;
        let permitted = match id {
            STATE_ID | STATE_NAME_ID => DISPATCH_PROPERTYGET,
            GET_STATE_ID => DISPATCH_METHOD,
            _ => return Err(DISP_E_MEMBERNOTFOUND.into()),
        };
        // Some late-bound clients request METHOD | PROPERTYGET together.
        if !flags.contains(permitted)
            || flags.0 & !(DISPATCH_METHOD.0 | DISPATCH_PROPERTYGET.0) != 0
        {
            return Err(DISP_E_MEMBERNOTFOUND.into());
        }
        if params.is_null() {
            return Err(E_POINTER.into());
        }
        // SAFETY: a non-null DISPPARAMS from COM is readable for this call.
        let params = unsafe { &*params };
        if params.cNamedArgs != 0 {
            return Err(DISP_E_NONAMEDARGS.into());
        }
        if params.cArgs != 0 {
            return Err(DISP_E_BADPARAMCOUNT.into());
        }
        // This is the complete query operation. It performs no resource access
        // on the caller's behalf and requires no assumption about caller privileges.
        let state = self.state.current().ok_or(CO_E_OBJNOTCONNECTED)?;
        if !result.is_null() {
            let value = if id == STATE_NAME_ID {
                VARIANT::from(match state {
                    State::AdminDown => "AdminDown",
                    State::Down => "Down",
                    State::Init => "Init",
                    State::Up => "Up",
                })
            } else {
                VARIANT::from(i32::from(state as u8))
            };
            // SAFETY: COM supplies an empty writable VARIANT output slot;
            // write transfers its BSTR/value ownership to the caller without Drop.
            unsafe { result.write(value) };
        }
        Ok(())
    }
}

fn create_type_info() -> Result<ITypeInfo> {
    // SAFETY: the names are static, terminated UTF-16. This library stays in
    // memory: SaveAllChanges is never called, so no .tlb file is written.
    let library = unsafe { CreateTypeLib2(SYS_WIN64, w!("BfdWinService.SessionState.tlb")) }?;
    // SAFETY: the name is static and terminated; a pure dispatch interface uses
    // IDispatch::Invoke, without describing any extra native vtable slots.
    let info = unsafe { library.CreateTypeInfo(w!("SessionState"), TKIND_DISPATCH) }?;
    // SAFETY: a valid type description and GUID are supplied. Clients request
    // the standard IDispatch IID; this GUID only identifies its member metadata.
    unsafe {
        info.SetGuid(&SESSION_STATE_TYPE_ID)?;
        info.SetTypeFlags(TYPEFLAG_FDISPATCHABLE.0 as u32)?;
    }
    for (index, (name, id, kind, variant_type)) in [
        (w!("State"), STATE_ID, INVOKE_PROPERTYGET, VT_I4),
        (w!("StateName"), STATE_NAME_ID, INVOKE_PROPERTYGET, VT_BSTR),
        (w!("GetState"), GET_STATE_ID, INVOKE_FUNC, VT_I4),
    ]
    .into_iter()
    .enumerate()
    {
        let function = FUNCDESC {
            memid: id,
            funckind: FUNC_DISPATCH,
            invkind: kind,
            callconv: CC_STDCALL,
            elemdescFunc: ELEMDESC {
                tdesc: TYPEDESC {
                    vt: variant_type,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: these methods copy the descriptor and name synchronously.
        // There are no parameters or borrowed nested fields in the descriptor.
        unsafe {
            info.AddFuncDesc(index as u32, &function)?;
            info.SetFuncAndParamNames(index as u32, &[name])?;
        }
    }
    // SAFETY: all member descriptions are complete; Windows finalizes their layout.
    unsafe { info.LayOut() }?;
    info.cast()
}

/// # Safety
/// A non-null IID must be valid for one GUID, as required by the COM ABI.
unsafe fn check_dispatch_iid(iid: *const GUID) -> Result<()> {
    if iid.is_null() {
        return Err(E_POINTER.into());
    }
    // SAFETY: the caller guarantees a readable GUID.
    if unsafe { *iid } != GUID::zeroed() {
        return Err(DISP_E_UNKNOWNINTERFACE.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::state::StatePublisher;
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    fn invoke(dispatch: &IDispatch, name: PCWSTR, flags: DISPATCH_FLAGS) -> Result<VARIANT> {
        let iid = GUID::zeroed();
        let mut id = UNKNOWN_ID;
        let params = DISPPARAMS::default();
        let mut result = VARIANT::default();
        // SAFETY: all pointers refer to correctly typed locals that live throughout
        // the calls. The name is static, terminated UTF-16; result is an empty VARIANT.
        unsafe {
            dispatch.GetIDsOfNames(&iid, &name, 1, 0, &mut id)?;
            dispatch.Invoke(id, &iid, 0, flags, &params, Some(&mut result), None, None)?;
        }
        Ok(result)
    }

    #[test]
    fn automation_reports_all_states_and_rejects_mutation_or_stale_state() {
        let publisher = StatePublisher::new(State::Down);
        let dispatch: IDispatch = SessionDispatch {
            state: publisher.observer(),
        }
        .into();
        for (state, name) in [
            (State::AdminDown, "AdminDown"),
            (State::Down, "Down"),
            (State::Init, "Init"),
            (State::Up, "Up"),
        ] {
            publisher.publish(state);
            let value = invoke(&dispatch, w!("sTaTe"), DISPATCH_PROPERTYGET).unwrap();
            assert_eq!(i32::try_from(&value).unwrap(), state as i32);
            let value = invoke(&dispatch, w!("StateName"), DISPATCH_PROPERTYGET).unwrap();
            assert_eq!(
                windows::core::BSTR::try_from(&value).unwrap().to_string(),
                name
            );
            let value = invoke(&dispatch, w!("GetState"), DISPATCH_METHOD).unwrap();
            assert_eq!(i32::try_from(&value).unwrap(), state as i32);
        }
        assert_eq!(
            invoke(&dispatch, w!("SetState"), DISPATCH_METHOD)
                .err()
                .unwrap()
                .code(),
            DISP_E_UNKNOWNNAME
        );
        assert_eq!(
            invoke(
                &dispatch,
                w!("State"),
                windows::Win32::System::Com::DISPATCH_PROPERTYPUT
            )
            .err()
            .unwrap()
            .code(),
            DISP_E_MEMBERNOTFOUND
        );
        drop(publisher);
        assert_eq!(
            invoke(&dispatch, w!("State"), DISPATCH_PROPERTYGET)
                .err()
                .unwrap()
                .code(),
            CO_E_OBJNOTCONNECTED
        );
    }

    #[test]
    fn dispatch_rejects_caller_resource_paths_and_all_property_writes() {
        let publisher = StatePublisher::new(State::Down);
        let dispatch: IDispatch = SessionDispatch {
            state: publisher.observer(),
        }
        .into();
        for supplied_path in [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters",
        ] {
            let mut argument = VARIANT::from(supplied_path);
            let params = DISPPARAMS {
                rgvarg: ptr::from_mut(&mut argument),
                cArgs: 1,
                ..Default::default()
            };
            for (id, flags) in [
                (STATE_ID, DISPATCH_PROPERTYGET),
                (STATE_NAME_ID, DISPATCH_PROPERTYGET),
                (GET_STATE_ID, DISPATCH_METHOD),
            ] {
                let mut result = VARIANT::default();
                // SAFETY: all inputs and the actual BSTR argument are valid and
                // live for the call. This exercises the server with caller paths.
                let error = unsafe {
                    dispatch.Invoke(
                        id,
                        &GUID::zeroed(),
                        0,
                        flags,
                        &params,
                        Some(&mut result),
                        None,
                        None,
                    )
                }
                .unwrap_err();
                assert_eq!(error.code(), DISP_E_BADPARAMCOUNT);
            }
        }
        let mut value = VARIANT::from(3i32);
        let mut named_id = windows::Win32::System::Ole::DISPID_PROPERTYPUT;
        let params = DISPPARAMS {
            rgvarg: ptr::from_mut(&mut value),
            rgdispidNamedArgs: ptr::from_mut(&mut named_id),
            cArgs: 1,
            cNamedArgs: 1,
        };
        for id in [STATE_ID, STATE_NAME_ID, GET_STATE_ID] {
            for flags in [
                windows::Win32::System::Com::DISPATCH_PROPERTYPUT,
                windows::Win32::System::Com::DISPATCH_PROPERTYPUTREF,
            ] {
                let mut result = VARIANT::default();
                // SAFETY: a complete property-write request with live inputs.
                // Neither write form may reach a privileged service operation.
                let error = unsafe {
                    dispatch.Invoke(
                        id,
                        &GUID::zeroed(),
                        0,
                        flags,
                        &params,
                        Some(&mut result),
                        None,
                        None,
                    )
                }
                .unwrap_err();
                assert_eq!(error.code(), DISP_E_MEMBERNOTFOUND);
            }
        }
        assert_eq!(publisher.observer().current(), Some(State::Down));
        assert_eq!(
            i32::try_from(&invoke(&dispatch, w!("GetState"), DISPATCH_METHOD).unwrap()).unwrap(),
            1
        );
    }

    #[test]
    fn factory_validates_query_interface_and_dispatch_arguments() {
        let publisher = StatePublisher::new(State::Down);
        let factory: IClassFactory = StateFactory {
            state: publisher.observer(),
        }
        .into();
        // SAFETY: a valid generated factory is called without aggregation. The
        // Windows wrappers own the returned interfaces and their reference counts.
        let dispatch: IDispatch = unsafe { factory.CreateInstance(None) }.unwrap();
        // SAFETY: requesting an unsupported IID is a supported QueryInterface operation.
        assert!(unsafe { factory.CreateInstance::<_, ITypeInfo>(None) }.is_err());
        let mut result = VARIANT::default();
        let mut params = DISPPARAMS {
            cArgs: 1,
            ..Default::default()
        };
        // SAFETY: the pointers are valid locals. The server rejects counts before
        // reading arguments, so no argument array is needed for these negative cases.
        let error = unsafe {
            dispatch.Invoke(
                STATE_ID,
                &GUID::zeroed(),
                0,
                DISPATCH_PROPERTYGET,
                &params,
                Some(&mut result),
                None,
                None,
            )
        }
        .unwrap_err();
        assert_eq!(error.code(), DISP_E_BADPARAMCOUNT);
        params.cNamedArgs = 1;
        // SAFETY: as above, the invalid named-argument count is rejected before access.
        let error = unsafe {
            dispatch.Invoke(
                STATE_ID,
                &GUID::zeroed(),
                0,
                DISPATCH_PROPERTYGET,
                &params,
                Some(&mut result),
                None,
                None,
            )
        }
        .unwrap_err();
        assert_eq!(error.code(), DISP_E_NONAMEDARGS);
        // SAFETY: null IID is intentionally supplied to exercise its validation.
        let error = unsafe {
            dispatch.Invoke(
                STATE_ID,
                ptr::null(),
                0,
                DISPATCH_PROPERTYGET,
                &DISPPARAMS::default(),
                Some(&mut result),
                None,
                None,
            )
        }
        .unwrap_err();
        assert_eq!(error.code(), E_POINTER);
    }

    #[test]
    fn dedicated_host_rejects_preexisting_process_security() {
        const HOST: &str = "BFD_TEST_COM_EXISTING_SECURITY";
        if std::env::var_os(HOST).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "com::tests::dedicated_host_rejects_preexisting_process_security",
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
            cookie: None,
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
        let error = ComServer::initialize().err().unwrap();
        assert!(error.to_string().contains("0x80010119")); // RPC_E_TOO_LATE
    }

    #[test]
    fn powershell_queries_live_state_across_processes() {
        const HOST: &str = "BFD_TEST_COM_HOST";
        // Isolate process-wide COM security from other tests that may initialize COM.
        if std::env::var_os(HOST).is_none() {
            for teardown in ["shutdown", "drop"] {
                let output = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "com::tests::powershell_queries_live_state_across_processes",
                        "--nocapture",
                    ])
                    .env(HOST, teardown)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{teardown}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let mut server = ComServer::initialize().unwrap();
        let worker = server.worker.as_ref().unwrap().thread();
        assert_eq!(worker.name(), Some("bfd-com"));
        assert_ne!(worker.id(), thread::current().id());
        // The caller must still be free to select STA. Hosting on this thread
        // would have initialized it as MTA and caused RPC_E_CHANGED_MODE here.
        // SAFETY: the probe uses no reserved data. On success, immediately balance
        // this thread's CoInitializeEx without creating or moving any interface.
        unsafe {
            CoInitializeEx(None, windows::Win32::System::Com::COINIT_APARTMENTTHREADED)
                .ok()
                .unwrap();
            CoUninitialize();
        }
        // A second initialization must fail closed, without silently accepting
        // security previously installed by this process or another library.
        let duplicate = ComServer::initialize().err().unwrap();
        assert!(duplicate.to_string().contains("0x80010119")); // RPC_E_TOO_LATE
        let publisher = StatePublisher::new(State::Down);
        // SAFETY: CoCreateGuid has no pointer inputs; the returned value is owned.
        let clsid = unsafe { windows::Win32::System::Com::CoCreateGuid() }.unwrap();
        server.register_class(clsid, publisher.observer()).unwrap();
        let duplicate = server
            .register_class(clsid, publisher.observer())
            .unwrap_err();
        assert!(duplicate.to_string().contains("0x80070057")); // E_INVALIDARG
                                                               // Activation uses a random CLSID registered with COM's SCM. No registry,
                                                               // service installation, elevation, or changes to the installed class are needed.
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class BfdComTestClient {{
    [DllImport("ole32.dll", ExactSpelling = true)]
    private static extern int CoSetProxyBlanket(IntPtr proxy, uint authn, uint authz,
        IntPtr principal, uint authnLevel, uint impLevel, IntPtr identity, uint capabilities);
    public static void IdentifyOnly(object session) {{
        IntPtr proxy = Marshal.GetIDispatchForObject(session);
        try {{
            // Packet integrity and IDENTIFY on the caller's own proxy.
            Marshal.ThrowExceptionForHR(CoSetProxyBlanket(proxy, uint.MaxValue, uint.MaxValue,
                new IntPtr(-1), 5, 2, new IntPtr(-1), 0));
        }} finally {{ Marshal.Release(proxy); }}
    }}
    public static int ReadState(object session) {{
        return (int)session.GetType().InvokeMember("GetState",
            System.Reflection.BindingFlags.InvokeMethod, null, session, new object[0]);
    }}
}}
'@
$session = [Activator]::CreateInstance([type]::GetTypeFromCLSID([guid]'{clsid:?}'))
try {{
    [BfdComTestClient]::IdentifyOnly($session)
    if ([BfdComTestClient]::ReadState($session) -ne 1) {{ throw 'C# state query failed' }}
    if ($session.State -ne 1 -or $session.StateName -cne 'Down' -or $session.GetState() -ne 1) {{ throw "Initial state mismatch: State=$($session.State), StateName=$($session.StateName), GetState=$($session.GetState())" }}
    [Console]::WriteLine('READY')
    [void][Console]::ReadLine()
    if ($session.State -ne 3 -or $session.StateName -cne 'Up' -or $session.GetState() -ne 3) {{ throw 'Live transition mismatch' }}
    if ([BfdComTestClient]::ReadState($session) -ne 3) {{ throw 'C# returned stale state' }}
    [Console]::WriteLine('UPDATED')
    [void][Console]::ReadLine()
    $failed = $false
    try {{ [void]$session.GetState() }} catch {{ $failed = $true }}
    if (-not $failed) {{ throw 'Closed engine returned stale state' }}
}} finally {{ [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) }}
[Console]::WriteLine('DONE')
"#
        );
        for executable in ["powershell.exe", "pwsh.exe"] {
            publisher.publish(State::Down);
            let client = Command::new(executable)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &script,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            let mut child = match client {
                Ok(child) => child,
                Err(error)
                    if executable == "pwsh.exe" && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    eprintln!("PowerShell 7 is unavailable; skipping its optional client check");
                    continue;
                }
                Err(error) => panic!("starting {executable}: {error}"),
            };
            let output = child.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if tx.send(line.unwrap()).is_err() {
                        break;
                    }
                }
            });
            let result = (|| -> std::result::Result<(), String> {
                let line = rx
                    .recv_timeout(Duration::from_secs(45))
                    .map_err(|e| e.to_string())?;
                if line != "READY" {
                    return Err(line);
                }
                publisher.publish(State::Up);
                writeln!(child.stdin.as_mut().unwrap(), "continue").unwrap();
                let line = rx
                    .recv_timeout(Duration::from_secs(20))
                    .map_err(|e| e.to_string())?;
                if line != "UPDATED" {
                    return Err(line);
                }
                publisher.close();
                writeln!(child.stdin.as_mut().unwrap(), "continue").unwrap();
                let line = rx
                    .recv_timeout(Duration::from_secs(20))
                    .map_err(|e| e.to_string())?;
                if line != "DONE" {
                    return Err(line);
                }
                Ok(())
            })();
            if result.is_err() {
                let _ = child.kill();
            }
            let output = child.wait_with_output().unwrap();
            reader.join().unwrap();
            assert!(
                result.is_ok() && output.status.success(),
                "{executable}: {result:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // Observe registration removal through COM itself, for both normal
        // shutdown and Drop cleanup (the service's startup-error path).
        // SAFETY: successful STA initialization is balanced by this local guard.
        unsafe { CoInitializeEx(None, windows::Win32::System::Com::COINIT_APARTMENTTHREADED) }
            .ok()
            .unwrap();
        let _caller_apartment = ComApartment {
            cookie: None,
            _thread_bound: PhantomData,
        };
        let factory = || {
            // SAFETY: the CLSID is live; only local activation is requested.
            // COM supplies an IClassFactory proxy for this caller's apartment.
            unsafe {
                windows::Win32::System::Com::CoGetClassObject::<IClassFactory>(
                    &clsid,
                    CLSCTX_LOCAL_SERVER,
                    None,
                )
            }
        };
        assert!(factory().is_ok());
        if std::env::var(HOST).is_ok_and(|teardown| teardown == "drop") {
            drop(server);
        } else {
            server.shutdown().unwrap();
        }
        assert!(
            factory().is_err(),
            "COM class remained registered after host teardown"
        );
    }
}
