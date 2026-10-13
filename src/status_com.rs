//! Read-only local COM Automation status endpoint hosted by the service.
#![allow(unsafe_code)] // Windows COM ABI and caller token inspection are isolated here.

use crate::runtime::status::{StatusObserver, StatusSnapshot};
use std::{
    ffi::c_void,
    io,
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows::{
    core::{implement, w, Error, IUnknown, Interface, Ref, Result, BOOL, GUID, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, CLASS_E_NOAGGREGATION, DISP_E_BADINDEX, DISP_E_BADPARAMCOUNT,
            DISP_E_MEMBERNOTFOUND, DISP_E_UNKNOWNINTERFACE, DISP_E_UNKNOWNNAME, E_ACCESSDENIED,
            E_INVALIDARG, E_POINTER, HANDLE, HLOCAL, RPC_E_TOO_LATE,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            CheckTokenMembership, CreateWellKnownSid, GetSecurityDescriptorDacl,
            GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, InitializeSecurityDescriptor,
            SetSecurityDescriptorDacl, SetSecurityDescriptorGroup, SetSecurityDescriptorOwner,
            WinBuiltinAdministratorsSid, WinLocalSystemSid, PSECURITY_DESCRIPTOR, PSID,
            SECURITY_DESCRIPTOR, TOKEN_QUERY,
        },
        System::{
            Com::{
                CoGetCallContext, CoInitializeEx, CoInitializeSecurity, CoRegisterClassObject,
                CoRevokeClassObject, CoUninitialize, IClassFactory, IClassFactory_Impl, IDispatch,
                IDispatch_Impl, IServerSecurity, ITypeInfo, CC_STDCALL, CLSCTX_LOCAL_SERVER,
                COINIT_MULTITHREADED, DISPATCH_FLAGS, DISPATCH_METHOD, DISPATCH_PROPERTYGET,
                DISPPARAMS, ELEMDESC, EOAC_DISABLE_AAA, EOAC_NO_CUSTOM_MARSHAL,
                EOLE_AUTHENTICATION_CAPABILITIES, EXCEPINFO, FUNCDESC, FUNC_DISPATCH, INVOKE_FUNC,
                INVOKE_PROPERTYGET, REGCLS_MULTIPLEUSE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                RPC_C_IMP_LEVEL_IDENTIFY, TKIND_DISPATCH, TYPEDESC,
            },
            Ole::{CreateTypeLib2, SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement},
            Rpc::{
                rcclLocal, RpcServerInqCallAttributesW, RPC_CALL_ATTRIBUTES_V2_W, RPC_PROTSEQ_LRPC,
                RPC_QUERY_IS_CLIENT_LOCAL, RPC_S_OK,
            },
            Threading::{GetCurrentThread, OpenThreadToken},
            Variant::{
                VARENUM, VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_ARRAY, VT_BOOL,
                VT_BSTR, VT_DATE, VT_DISPATCH, VT_UI4, VT_UI8, VT_VARIANT,
            },
        },
    },
};

/// Registered by the installer as `BfdWinService.Status.1`.
pub const STATUS_CLSID: GUID = GUID::from_u128(0xe4a97d25_73e2_4e6c_9a35_281b6ae697c3);
/// Service-hosted activation and access policy registered by the installer.
pub const STATUS_APPID: GUID = GUID::from_u128(0x954e4bd0_8b46_4a93_b43a_35a4a40ed8f7);

// Distinct metadata identities prevent Automation clients from caching the
// endpoint's method list as the snapshot's property list (or vice versa).
const ENDPOINT_TYPE_ID: GUID = GUID::from_u128(0x81d562de_bd95_42e5_bdc1_3c6a6f0ee42b);
const SNAPSHOT_TYPE_ID: GUID = GUID::from_u128(0x4cf1dd76_4b3f_45c5_8f03_c012df05546b);

// Tests never claim the installed service's CLSID or its SCM-hosted AppID.
#[cfg(test)]
const TEST_CLSID: GUID = GUID::from_u128(0x0bdd3e1a_83a5_4d84_9a4f_706304391e25);
#[cfg(test)]
const TEST_CALLER_CLSID: GUID = GUID::from_u128(0x94ad089b_1317_4605_b61e_72065fce6185);

#[derive(Clone, Copy)]
enum SecurityPolicy {
    AdministratorsAndSystem,
    // Permits native transport access only; the production per-call guard
    // still rejects users without enabled Administrator or SYSTEM identity.
    #[cfg(test)]
    LocalAuthenticatedFixture,
}

#[cfg(test)]
static CALLER_TOKEN_INSPECTIONS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

static SECURITY_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Owns the service's dedicated COM apartment and class registration.
/// Queries run on COM RPC threads and read the observer's published `Arc` only.
pub struct StatusComServer {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl StatusComServer {
    /// Starts the local read-only Automation endpoint before the service runs.
    ///
    /// # Errors
    /// Fails closed if COM security was already initialized or registration fails.
    pub fn start(observer: StatusObserver) -> io::Result<Self> {
        Self::start_registered(
            observer,
            STATUS_CLSID,
            SecurityPolicy::AdministratorsAndSystem,
        )
    }

    #[cfg(test)]
    fn start_fixture(observer: StatusObserver) -> io::Result<Self> {
        Self::start_registered(
            observer,
            TEST_CLSID,
            SecurityPolicy::AdministratorsAndSystem,
        )
    }

    #[cfg(test)]
    fn start_caller_fixture(observer: StatusObserver) -> io::Result<Self> {
        Self::start_registered(
            observer,
            TEST_CALLER_CLSID,
            SecurityPolicy::LocalAuthenticatedFixture,
        )
    }

    fn start_registered(
        observer: StatusObserver,
        clsid: GUID,
        policy: SecurityPolicy,
    ) -> io::Result<Self> {
        let (stop, stopped) = mpsc::channel();
        let (ready, initialized) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("bfd-status-com".into())
            .spawn(move || {
                let initialized_host = Apartment::initialize(policy).and_then(|apartment| {
                    let factory: IClassFactory = StatusFactory { observer }.into();
                    // SAFETY: factory is live, supports IClassFactory, and registration
                    // stays owned by this thread until its explicit revocation.
                    let cookie = unsafe {
                        CoRegisterClassObject(
                            &clsid,
                            &factory,
                            CLSCTX_LOCAL_SERVER,
                            REGCLS_MULTIPLEUSE,
                        )
                    }?;
                    Ok((apartment, Registration(cookie), factory))
                });
                match initialized_host {
                    Ok((apartment, registration, factory)) => {
                        if ready.send(Ok(())).is_ok() {
                            let _ = stopped.recv();
                        }
                        // Revoke before releasing the class and uninitializing COM.
                        drop(registration);
                        drop(factory);
                        drop(apartment);
                    }
                    Err(error) => {
                        // Format Windows' thread-local error info on its owner thread.
                        let _ = ready.send(Err(io::Error::other(format!(
                            "initialize status COM ({:#010x}): {error}",
                            error.code().0
                        ))));
                    }
                }
            })?;
        let host = Self {
            stop,
            worker: Some(worker),
        };
        initialized
            .recv()
            .map_err(|_| io::Error::other("status COM thread exited during initialization"))??;
        Ok(host)
    }

    /// Revokes the endpoint and joins its COM apartment thread.
    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker.take() {
            let _ = self.stop.send(());
            worker
                .join()
                .map_err(|_| io::Error::other("status COM thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for StatusComServer {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

struct Registration(u32);
impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: cookie came from successful registration on this live apartment.
        let _ = unsafe { CoRevokeClassObject(self.0) };
    }
}

struct Apartment {
    _thread_bound: PhantomData<Rc<()>>,
}
impl Apartment {
    fn initialize(policy: SecurityPolicy) -> Result<Self> {
        // SAFETY: this thread owns a matching CoUninitialize through the guard.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
        let apartment = Self {
            _thread_bound: PhantomData,
        };
        initialize_security(policy)?;
        Ok(apartment)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: successful initialization on this thread; guard is !Send.
        unsafe { CoUninitialize() };
    }
}

fn initialize_security(policy: SecurityPolicy) -> Result<()> {
    if SECURITY_ATTEMPTED.swap(true, Ordering::Relaxed) {
        return Err(RPC_E_TOO_LATE.into());
    }
    let mut relative = PSECURITY_DESCRIPTOR::default();
    let permissions = match policy {
        SecurityPolicy::AdministratorsAndSystem => w!("O:SYG:SYD:(A;;0x3;;;SY)(A;;0x3;;;BA)"),
        #[cfg(test)]
        SecurityPolicy::LocalAuthenticatedFixture => {
            w!("O:SYG:SYD:(A;;0x3;;;SY)(A;;0x3;;;BA)(A;;0x3;;;AU)")
        }
    };
    // SAFETY: static terminated SDDL, valid writable output. Rights 0x3 permit
    // only local execution. Production grants SYSTEM and enabled Administrators;
    // the test-only policy also permits authenticated transport to test the guard.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            permissions,
            SDDL_REVISION_1,
            &mut relative,
            None,
        )
    }?;
    let relative = SecurityAllocation(relative);
    let mut absolute = SECURITY_DESCRIPTOR::default();
    let descriptor = PSECURITY_DESCRIPTOR(ptr::from_mut(&mut absolute).cast());
    let mut owner = PSID::default();
    let mut group = PSID::default();
    let mut dacl = ptr::null_mut();
    let mut present = BOOL::default();
    let mut defaulted = BOOL::default();
    // SAFETY: Windows descriptor remains allocated; writable outputs borrow its
    // fields only until CoInitializeSecurity copies the absolute descriptor.
    unsafe {
        GetSecurityDescriptorOwner(relative.0, &mut owner, &mut defaulted)?;
        GetSecurityDescriptorGroup(relative.0, &mut group, &mut defaulted)?;
        GetSecurityDescriptorDacl(relative.0, &mut present, &mut dacl, &mut defaulted)?;
    }
    if !present.as_bool() || dacl.is_null() || owner.0.is_null() || group.0.is_null() {
        return Err(E_INVALIDARG.into());
    }
    // SAFETY: non-null ACL/SIDs remain alive through process security setup;
    // COM copies them and neither the relative nor absolute pointer escapes.
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
        // SAFETY: owns the SDDL allocation; all borrowed descriptor fields expired.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

struct TokenHandle(HANDLE);
impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: owns the non-pseudo handle returned by OpenThreadToken.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct CallerImpersonation(Option<IServerSecurity>);
impl CallerImpersonation {
    fn revert(mut self) -> Result<()> {
        if let Some(security) = &self.0 {
            // SAFETY: this guard owns successful impersonation on this RPC
            // thread. Failure keeps the guard armed for Drop's fallback.
            unsafe { security.RevertToSelf() }.map_err(|_| Error::from_hresult(E_ACCESSDENIED))?;
        }
        self.0 = None;
        Ok(())
    }
}
impl Drop for CallerImpersonation {
    fn drop(&mut self) {
        if let Some(security) = &self.0 {
            // SAFETY: successful impersonation on this RPC thread. COM restores
            // identity at call completion if this fallback also fails.
            let _ = unsafe { security.RevertToSelf() };
        }
    }
}

fn authorize_caller() -> Result<()> {
    // No fallback to the service process identity: direct calls and absent RPC
    // contexts are denied, as are unknown locality and remote transports.
    // SAFETY: COM obtains the interface for this RPC call on this thread only.
    let security = unsafe { CoGetCallContext::<IServerSecurity>() }
        .map_err(|_| Error::from_hresult(E_ACCESSDENIED))?;
    let mut attributes = RPC_CALL_ATTRIBUTES_V2_W {
        Version: 2,
        Flags: RPC_QUERY_IS_CLIENT_LOCAL,
        ..Default::default()
    };
    // SAFETY: attributes has the requested v2 layout and valid writable storage.
    let status =
        unsafe { RpcServerInqCallAttributesW(None, ptr::from_mut(&mut attributes).cast()) };
    if status != RPC_S_OK
        || attributes.IsClientLocal != rcclLocal
        || attributes.ProtocolSequence != RPC_PROTSEQ_LRPC
        || attributes.NullSession.as_bool()
    {
        return Err(E_ACCESSDENIED.into());
    }
    // SAFETY: security belongs to this current authenticated local COM call.
    unsafe { security.ImpersonateClient() }.map_err(|_| Error::from_hresult(E_ACCESSDENIED))?;
    let impersonation = CallerImpersonation(Some(security));
    let mut token = HANDLE::default();
    // OpenAsSelf permits querying an identification-level client token without
    // SeImpersonatePrivilege. This never opens or substitutes the process token.
    // SAFETY: current thread pseudo-handle, valid writable output, query only.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
        .map_err(|_| Error::from_hresult(E_ACCESSDENIED))?;
    let token = TokenHandle(token);
    let authorized = authorized_token(token.0).map_err(|_| Error::from_hresult(E_ACCESSDENIED))?;
    // Counts only inspection of a real authenticated COM RPC caller token;
    // direct predicate tests and missing-context calls cannot increment it.
    #[cfg(test)]
    CALLER_TOKEN_INSPECTIONS.fetch_add(1, Ordering::Relaxed);
    drop(token);
    // Revert before any formatting or object construction.
    impersonation.revert()?;
    if authorized {
        Ok(())
    } else {
        Err(E_ACCESSDENIED.into())
    }
}

fn authorized_token(token: HANDLE) -> Result<bool> {
    for principal in [WinLocalSystemSid, WinBuiltinAdministratorsSid] {
        // A SID is at most SECURITY_MAX_SID_SIZE (68 bytes); usize ensures
        // alignment and the buffer is used only for this Windows call.
        let mut storage = [0usize; 9];
        let sid = PSID(storage.as_mut_ptr().cast());
        let mut length = u32::try_from(std::mem::size_of_val(&storage))
            .map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        // SAFETY: sufficiently large, aligned writable SID buffer.
        unsafe { CreateWellKnownSid(principal, None, Some(sid), &mut length) }?;
        let mut member = BOOL::default();
        // SAFETY: live identification/impersonation token and initialized SID.
        // Deny-only Administrator SIDs in UAC-filtered tokens do not qualify.
        unsafe { CheckTokenMembership(Some(token), sid, &mut member) }?;
        if member.as_bool() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[implement(IClassFactory)]
struct StatusFactory {
    observer: StatusObserver,
}
impl IClassFactory_Impl for StatusFactory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        iid: *const GUID,
        result: *mut *mut c_void,
    ) -> Result<()> {
        if result.is_null() || iid.is_null() {
            return Err(E_POINTER.into());
        }
        // SAFETY: COM supplies a writable output; clear it on every failure.
        unsafe { result.write(ptr::null_mut()) };
        authorize_caller()?;
        if !outer.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let object: IDispatch = StatusObject {
            observer: self.observer.clone(),
        }
        .into();
        // SAFETY: COM supplies a readable IID and writable interface output;
        // QueryInterface adds the reference owned by the returned pointer.
        unsafe { object.query(iid, result) }.ok()
    }
    fn LockServer(&self, _: BOOL) -> Result<()> {
        authorize_caller()
    }
}

#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    kind: VARENUM,
}
const ENDPOINT_MEMBERS: &[Member] = &[Member {
    name: "GetSnapshot",
    kind: VT_DISPATCH,
}];

#[implement(IDispatch)]
struct StatusObject {
    observer: StatusObserver,
}

#[implement(IDispatch)]
struct SnapshotObject {
    snapshot: Arc<StatusSnapshot>,
}

macro_rules! dispatch_metadata {
    ($members:expr) => {
        fn GetTypeInfoCount(&self) -> Result<u32> {
            authorize_caller()?;
            Ok(1)
        }
        fn GetTypeInfo(&self, index: u32, locale: u32) -> Result<ITypeInfo> {
            authorize_caller()?;
            if index != 0 {
                return Err(DISP_E_BADINDEX.into());
            }
            type_information($members, locale)
        }
        fn GetIDsOfNames(
            &self,
            iid: *const GUID,
            names: *const PCWSTR,
            count: u32,
            _: u32,
            ids: *mut i32,
        ) -> Result<()> {
            authorize_caller()?;
            dispatch_ids($members, iid, names, count, ids)
        }
    };
}

impl IDispatch_Impl for StatusObject_Impl {
    dispatch_metadata!(ENDPOINT_MEMBERS);
    fn Invoke(
        &self,
        id: i32,
        iid: *const GUID,
        _: u32,
        flags: DISPATCH_FLAGS,
        parameters: *const DISPPARAMS,
        result: *mut VARIANT,
        _: *mut EXCEPINFO,
        _: *mut u32,
    ) -> Result<()> {
        authorize_caller()?;
        validate_invoke(iid, parameters, result)?;
        if id != 1 || flags.0 & DISPATCH_METHOD.0 == 0 {
            return Err(DISP_E_MEMBERNOTFOUND.into());
        }
        let value = match self.observer.snapshot() {
            Some(snapshot) => dispatch_variant(SnapshotObject { snapshot }.into()),
            None => VARIANT::default(),
        };
        // SAFETY: validation established a writable COM result; ownership of
        // its interface reference transfers to the caller's VARIANT.
        unsafe { result.write(value) };
        Ok(())
    }
}

impl IDispatch_Impl for SnapshotObject_Impl {
    dispatch_metadata!(SNAPSHOT_MEMBERS);
    fn Invoke(
        &self,
        id: i32,
        iid: *const GUID,
        _: u32,
        flags: DISPATCH_FLAGS,
        parameters: *const DISPPARAMS,
        result: *mut VARIANT,
        _: *mut EXCEPINFO,
        _: *mut u32,
    ) -> Result<()> {
        authorize_caller()?;
        validate_invoke(iid, parameters, result)?;
        if flags.0 & DISPATCH_PROPERTYGET.0 == 0
            || flags.0 & !(DISPATCH_PROPERTYGET.0 | DISPATCH_METHOD.0) != 0
        {
            return Err(DISP_E_MEMBERNOTFOUND.into());
        }
        let index = usize::try_from(
            id.checked_sub(1)
                .ok_or_else(|| Error::from_hresult(DISP_E_MEMBERNOTFOUND))?,
        )
        .map_err(|_| Error::from_hresult(DISP_E_MEMBERNOTFOUND))?;
        if index >= SNAPSHOT_MEMBERS.len() {
            return Err(DISP_E_MEMBERNOTFOUND.into());
        }
        let value = property_value(&self.snapshot, index)?;
        // SAFETY: validation established the writable caller-owned result.
        unsafe { result.write(value) };
        Ok(())
    }
}

fn validate_invoke(
    iid: *const GUID,
    parameters: *const DISPPARAMS,
    result: *mut VARIANT,
) -> Result<()> {
    if iid.is_null() || parameters.is_null() || result.is_null() {
        return Err(E_POINTER.into());
    }
    // SAFETY: COM ABI inputs are readable for this call after null checks.
    if unsafe { *iid } != GUID::zeroed() {
        return Err(DISP_E_UNKNOWNINTERFACE.into());
    }
    // SAFETY: caller supplies valid DISPPARAMS storage for this call.
    if unsafe { (*parameters).cArgs != 0 || (*parameters).cNamedArgs != 0 } {
        return Err(DISP_E_BADPARAMCOUNT.into());
    }
    Ok(())
}

fn dispatch_ids(
    members: &[Member],
    iid: *const GUID,
    names: *const PCWSTR,
    count: u32,
    ids: *mut i32,
) -> Result<()> {
    if iid.is_null() || names.is_null() || ids.is_null() {
        return Err(E_POINTER.into());
    }
    // SAFETY: ABI supplies the readable IID after null checking.
    if unsafe { *iid } != GUID::zeroed() {
        return Err(DISP_E_UNKNOWNINTERFACE.into());
    }
    if count != 1 {
        return Err(DISP_E_UNKNOWNNAME.into());
    }
    // SAFETY: exactly one name and ID are required; COM supplies terminated
    // UTF-16 names. No raw input reference is retained after this call.
    let name_pointer = unsafe { *names };
    if name_pointer.is_null() {
        return Err(E_POINTER.into());
    }
    // SAFETY: the non-null COM name is terminated UTF-16 valid for this call.
    let name =
        unsafe { name_pointer.to_string() }.map_err(|_| Error::from_hresult(DISP_E_UNKNOWNNAME))?;
    let index = members
        .iter()
        .position(|member| member.name.eq_ignore_ascii_case(&name));
    // SAFETY: one writable ID is supplied by COM for the one requested name.
    unsafe { ids.write(index.and_then(|n| i32::try_from(n + 1).ok()).unwrap_or(-1)) };
    if index.is_some() {
        Ok(())
    } else {
        Err(DISP_E_UNKNOWNNAME.into())
    }
}

fn type_information(members: &[Member], locale: u32) -> Result<ITypeInfo> {
    #[cfg(target_pointer_width = "64")]
    let platform = windows::Win32::System::Com::SYS_WIN64;
    #[cfg(target_pointer_width = "32")]
    let platform = windows::Win32::System::Com::SYS_WIN32;
    // Build native owned dispatch metadata in memory; SaveAllChanges is never
    // called, so the nominal filename is never created. These APIs copy their
    // inputs, unlike simplified dispatch metadata that may retain raw buffers.
    // SAFETY: static terminated nominal path and supported platform kind.
    let library = unsafe { CreateTypeLib2(platform, w!("bfd-status-memory.tlb")) }?;
    // SAFETY: library is live and locale is the caller's Automation locale.
    unsafe { library.SetLcid(locale) }?;
    let is_endpoint = members
        .first()
        .is_some_and(|member| member.name == "GetSnapshot");
    let (name, identity) = if is_endpoint {
        (w!("BfdStatusEndpoint"), ENDPOINT_TYPE_ID)
    } else {
        (w!("BfdSessionStatus"), SNAPSHOT_TYPE_ID)
    };
    // SAFETY: static interface name and valid dispatch type kind.
    let description = unsafe { library.CreateTypeInfo(name, TKIND_DISPATCH) }?;
    // SAFETY: the owned type builder copies this unique metadata identity.
    unsafe { description.SetGuid(&identity) }?;
    for (index, member) in members.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        let function = FUNCDESC {
            memid: i32::try_from(index + 1).map_err(|_| Error::from_hresult(E_INVALIDARG))?,
            funckind: FUNC_DISPATCH,
            invkind: if member.name == "GetSnapshot" {
                INVOKE_FUNC
            } else {
                INVOKE_PROPERTYGET
            },
            callconv: CC_STDCALL,
            elemdescFunc: ELEMDESC {
                tdesc: TYPEDESC {
                    vt: member.kind,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let name: Vec<u16> = member.name.encode_utf16().chain([0]).collect();
        // SAFETY: native type builder copies the descriptor and terminated name
        // synchronously; their local storage remains valid for both calls.
        unsafe {
            description.AddFuncDesc(index, &function)?;
            description.SetFuncAndParamNames(index, &[PCWSTR(name.as_ptr())])?;
        }
    }
    // SAFETY: all function descriptions are complete; native typeinfo owns them.
    unsafe { description.LayOut() }?;
    description.cast()
}

fn dispatch_variant(value: IDispatch) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_DISPATCH,
                Anonymous: VARIANT_0_0_0 {
                    pdispVal: ManuallyDrop::new(Some(value)),
                },
                ..Default::default()
            }),
        },
    }
}

fn timestamp(value: SystemTime) -> Result<VARIANT> {
    let unix = match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    };
    // OLE DATE counts days from 1899-12-30. Public timestamps carry the Utc
    // suffix because Automation DATE has no timezone field.
    let date = unix / 86400.0 + 25569.0;
    if !(0.0..2958466.0).contains(&date) {
        return Err(E_INVALIDARG.into());
    }
    Ok(VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_DATE,
                Anonymous: VARIANT_0_0_0 { date },
                ..Default::default()
            }),
        },
    })
}

fn interval(value: Duration) -> Result<VARIANT> {
    Ok(VARIANT::from(
        u64::try_from(value.as_micros()).map_err(|_| Error::from_hresult(E_INVALIDARG))?,
    ))
}

fn optional<T>(value: Option<T>, convert: impl FnOnce(T) -> Result<VARIANT>) -> Result<VARIANT> {
    value
        .map(convert)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn string(value: impl ToString) -> VARIANT {
    VARIANT::from(value.to_string().as_str())
}
fn debug(value: impl std::fmt::Debug) -> VARIANT {
    VARIANT::from(format!("{value:?}").as_str())
}

fn address_array(addresses: &[std::net::IpAddr]) -> Result<VARIANT> {
    // SAFEARRAY element indices are signed LONGs. Reject oversized arrays
    // before allocating so no later index conversion can abandon ownership.
    let indexed_length =
        i32::try_from(addresses.len()).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
    let length = u32::try_from(indexed_length).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
    // SAFETY: Windows creates an owned one-dimensional BSTR array.
    let array = unsafe { SafeArrayCreateVector(VT_BSTR, 0, length) };
    if array.is_null() {
        return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
    }
    for (index, address) in addresses.iter().enumerate() {
        let index = i32::try_from(index).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        let text = windows::core::BSTR::from(address.to_string());
        // SAFETY: valid array/index; BSTR is copied by SafeArrayPutElement.
        if let Err(error) = unsafe { SafeArrayPutElement(array, &index, text.as_ptr().cast()) } {
            // SAFETY: own this array, not yet transferred into a VARIANT.
            let _ = unsafe { SafeArrayDestroy(array) };
            return Err(error);
        }
    }
    Ok(VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: ManuallyDrop::new(VARIANT_0_0 {
                vt: VARENUM(VT_ARRAY.0 | VT_BSTR.0),
                Anonymous: VARIANT_0_0_0 { parray: array },
                ..Default::default()
            }),
        },
    })
}

macro_rules! properties {
    ($(($name:literal, $kind:ident, $snapshot:ident => $value:expr)),* $(,)?) => {
        const SNAPSHOT_MEMBERS: &[Member] = &[$(Member { name: $name, kind: $kind }),*];
        fn property_value(snapshot: &StatusSnapshot, index: usize) -> Result<VARIANT> {
            let mut next = 0;
            $(if index == next { let $snapshot = snapshot; return $value; } next += 1;)*
            let _ = next;
            Err(DISP_E_MEMBERNOTFOUND.into())
        }
        #[cfg(test)]
        fn property_values(snapshot: &StatusSnapshot) -> Result<Vec<VARIANT>> {
            (0..SNAPSHOT_MEMBERS.len()).map(|index| property_value(snapshot, index)).collect()
        }
    };
}

properties! {
    ("LocalAddress", VT_BSTR, s => Ok(string(s.local_address))),
    ("PeerAddress", VT_VARIANT, s => optional(s.peer_address, |v| Ok(string(v)))),
    ("LastAcceptedSource", VT_VARIANT, s => optional(s.last_accepted_source, |v| Ok(string(v)))),
    ("InterfaceIndex", VT_VARIANT, s => optional(s.interface_index, |v| Ok(v.into()))),
    ("LocalSourcePort", VT_UI4, s => Ok(u32::from(s.local_source_port).into())),
    ("ControlPort", VT_UI4, s => Ok(u32::from(s.control_port).into())),
    ("SessionType", VT_BSTR, s => Ok(debug(s.session_type))),
    ("TransportMode", VT_BSTR, s => Ok(debug(s.transport_mode))),
    ("Passive", VT_BOOL, s => Ok(s.passive.into())),
    ("PointToPoint", VT_BOOL, s => Ok(s.point_to_point.into())),
    ("AllowedPeers", VT_VARIANT, s => address_array(&s.allowed_peers)),
    ("MinTtl", VT_VARIANT, s => optional(s.min_ttl, |v| Ok(u32::from(v).into()))),
    ("LocalDiscriminator", VT_UI4, s => Ok(s.local_discriminator.into())),
    ("RemoteDiscriminator", VT_VARIANT, s => optional(s.remote_discriminator, |v| Ok(v.into()))),
    ("LocalState", VT_BSTR, s => Ok(debug(s.local_state))),
    ("RemoteState", VT_VARIANT, s => optional(s.remote_state, |v| Ok(debug(v)))),
    ("LocalDiagnostic", VT_BSTR, s => Ok(debug(s.local_diagnostic))),
    ("RemoteDiagnostic", VT_VARIANT, s => optional(s.remote_diagnostic, |v| Ok(u32::from(v).into()))),
    ("Communicating", VT_VARIANT, s => optional(s.communicating, |v| Ok(v.into()))),
    ("StateSinceUtc", VT_DATE, s => timestamp(s.state_since_utc)),
    ("LastUpUtc", VT_VARIANT, s => optional(s.last_up_utc, timestamp)),
    ("LastDownUtc", VT_VARIANT, s => optional(s.last_down_utc, timestamp)),
    ("LastDownReason", VT_VARIANT, s => optional(s.last_down_reason, |v| Ok(debug(v)))),
    ("LastValidReceiveUtc", VT_VARIANT, s => optional(s.last_valid_receive_utc, timestamp)),
    ("LastSuccessfulSendUtc", VT_VARIANT, s => optional(s.last_successful_send_utc, timestamp)),
    ("ConfiguredMinTxIntervalMicroseconds", VT_UI8, s => interval(s.configured_min_tx_interval)),
    ("ConfiguredMinRxIntervalMicroseconds", VT_UI8, s => interval(s.configured_min_rx_interval)),
    ("StartupTxIntervalMicroseconds", VT_UI8, s => interval(s.startup_tx_interval)),
    ("LocalDetectMultiplier", VT_VARIANT, s => optional(s.local_detect_multiplier, |v| Ok(u32::from(v).into()))),
    ("RemoteDetectMultiplier", VT_VARIANT, s => optional(s.remote_detect_multiplier, |v| Ok(u32::from(v).into()))),
    ("RemoteMinTxIntervalMicroseconds", VT_VARIANT, s => optional(s.remote_min_tx_interval, interval)),
    ("RemoteMinRxIntervalMicroseconds", VT_VARIANT, s => optional(s.remote_min_rx_interval, interval)),
    ("EffectiveTxIntervalMicroseconds", VT_VARIANT, s => optional(s.effective_tx_interval, interval)),
    ("DetectionTimeMicroseconds", VT_VARIANT, s => optional(s.detection_time, interval)),
    ("PeriodicTransmitEnabled", VT_BOOL, s => Ok(s.periodic_transmit_enabled.into())),
    ("PollPending", VT_VARIANT, s => optional(s.poll_pending, |v| Ok(v.into()))),
    ("PacketsReceivedAccepted", VT_UI8, s => Ok(s.packets_received_accepted.into())),
    ("PacketsSentSuccessfully", VT_UI8, s => Ok(s.packets_sent_successfully.into())),
    ("PacketsRejected", VT_UI8, s => Ok(s.packets_rejected.into())),
    ("AuthenticationFailures", VT_UI8, s => Ok(s.authentication_failures.into())),
    ("MalformedPackets", VT_UI8, s => Ok(s.malformed_packets.into())),
    ("ProtocolRejections", VT_UI8, s => Ok(s.protocol_rejections.into())),
    ("TransportValidationFailures", VT_UI8, s => Ok(s.transport_validation_failures.into())),
    ("SocketErrors", VT_UI8, s => Ok(s.socket_errors.into())),
    ("DetectionTimeouts", VT_UI8, s => Ok(s.detection_timeouts.into())),
    ("UpTransitions", VT_UI8, s => Ok(s.up_transitions.into())),
    ("RepliesWithheld", VT_UI8, s => Ok(s.replies_withheld.into())),
    ("LastRejectionReason", VT_VARIANT, s => optional(s.last_rejection_reason.as_ref(), |v| Ok(string(v)))),
    ("LastRejectionUtc", VT_VARIANT, s => optional(s.last_rejection_utc, timestamp)),
    ("LastSocketErrorCode", VT_VARIANT, s => optional(s.last_socket_error_code, |v| Ok(v.into()))),
    ("LastSocketErrorUtc", VT_VARIANT, s => optional(s.last_socket_error_utc, timestamp)),
    ("AuthenticationType", VT_BSTR, s => Ok(debug(s.authentication_type))),
    ("AuthenticationKeyId", VT_VARIANT, s => optional(s.authentication_key_id, |v| Ok(u32::from(v).into()))),
    ("LastConfigurationReloadUtc", VT_VARIANT, s => optional(s.last_configuration_reload_utc, timestamp)),
    ("LastConfigurationReloadSucceeded", VT_VARIANT, s => optional(s.last_configuration_reload_succeeded, |v| Ok(v.into()))),
}

#[cfg(test)]
mod tests;
