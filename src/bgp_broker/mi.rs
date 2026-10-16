//! Minimal native MI client. Function signatures match Windows SDK mi.h.
//!
//! windows-sys represents MI function-table entries as isize. Each conversion
//! below restores the SDK's exact MI_CALL (extern "system") signature. Handles
//! remain on the calling thread and are released in dependency order.

// Native MI function tables and handle ownership require the Windows FFI boundary.
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use super::Method;
use crate::runtime::Logger;
use std::{
    ffi::c_void,
    io,
    mem::{size_of, transmute_copy},
    ptr,
};
use windows_sys::{core::w, Win32::System::Wmi::*};

type ApplicationClose = unsafe extern "system" fn(*mut MI_Application) -> MI_Result;
type NewSession = unsafe extern "system" fn(
    *mut MI_Application,
    *const u16,
    *const u16,
    *mut MI_DestinationOptions,
    *mut MI_SessionCallbacks,
    *mut *mut MI_Instance,
    *mut MI_Session,
) -> MI_Result;
type NewInstance = unsafe extern "system" fn(
    *mut MI_Application,
    *const u16,
    *const MI_ClassDecl,
    *mut *mut MI_Instance,
) -> MI_Result;
type NewOptions =
    unsafe extern "system" fn(*mut MI_Application, u8, *mut MI_OperationOptions) -> MI_Result;
type NewDestination =
    unsafe extern "system" fn(*mut MI_Application, *mut MI_DestinationOptions) -> MI_Result;
type DestinationSetString =
    unsafe extern "system" fn(*mut MI_DestinationOptions, *const u16, *const u16, u32) -> MI_Result;
type DestinationSetNumber =
    unsafe extern "system" fn(*mut MI_DestinationOptions, *const u16, u32, u32) -> MI_Result;
type DestinationDelete = unsafe extern "system" fn(*mut MI_DestinationOptions);
type SessionClose = unsafe extern "system" fn(
    *mut MI_Session,
    *mut c_void,
    Option<unsafe extern "system" fn(*mut c_void)>,
) -> MI_Result;
type Invoke = unsafe extern "system" fn(
    *mut MI_Session,
    u32,
    *mut MI_OperationOptions,
    *const u16,
    *const u16,
    *const u16,
    *const MI_Instance,
    *const MI_Instance,
    *mut MI_OperationCallbacks,
    *mut MI_Operation,
);
type InstanceDelete = unsafe extern "system" fn(*mut MI_Instance) -> MI_Result;
type AddElement = unsafe extern "system" fn(
    *mut MI_Instance,
    *const u16,
    *const MI_Value,
    MI_Type,
    u32,
) -> MI_Result;
type GetElement = unsafe extern "system" fn(
    *const MI_Instance,
    *const u16,
    *mut MI_Value,
    *mut MI_Type,
    *mut u32,
    *mut u32,
) -> MI_Result;
type OptionsDelete = unsafe extern "system" fn(*mut MI_OperationOptions);
type SetInterval = unsafe extern "system" fn(
    *mut MI_OperationOptions,
    *const u16,
    *const MI_Interval,
    u32,
) -> MI_Result;
type OperationClose = unsafe extern "system" fn(*mut MI_Operation) -> MI_Result;
type OperationCancel =
    unsafe extern "system" fn(*mut MI_Operation, MI_CancellationReason) -> MI_Result;
type GetInstance = unsafe extern "system" fn(
    *mut MI_Operation,
    *mut *const MI_Instance,
    *mut u8,
    *mut MI_Result,
    *mut *const u16,
    *mut *const MI_Instance,
) -> MI_Result;
type SessionGetClass = unsafe extern "system" fn(
    *mut MI_Session,
    u32,
    *mut MI_OperationOptions,
    *const u16,
    *const u16,
    *mut MI_OperationCallbacks,
    *mut MI_Operation,
);
type GetClass = unsafe extern "system" fn(
    *mut MI_Operation,
    *mut *const MI_Class,
    *mut u8,
    *mut MI_Result,
    *mut *const u16,
    *mut *const MI_Instance,
) -> MI_Result;
type ClassGetElement = unsafe extern "system" fn(
    *const MI_Class,
    *const u16,
    *mut MI_Value,
    *mut u8,
    *mut MI_Type,
    *mut *mut u16,
    *mut MI_QualifierSet,
    *mut u32,
    *mut u32,
) -> MI_Result;
type GetQualifier = unsafe extern "system" fn(
    *const MI_QualifierSet,
    *const u16,
    *mut MI_Type,
    *mut u32,
    *mut MI_Value,
    *mut u32,
) -> MI_Result;
type Next<T> = unsafe extern "system" fn(
    *mut MI_Operation,
    *mut *const T,
    *mut u8,
    *mut MI_Result,
    *mut *const u16,
    *mut *const MI_Instance,
) -> MI_Result;

/// Converts a windows-sys MI function-table entry, stored as `isize`, to its
/// mi.h signature. A zero entry is an error: transmuting it to a non-nullable
/// function pointer would be undefined behavior, not merely a failed call.
///
/// # Safety
/// `F` must be the exact `unsafe extern "system" fn` type that mi.h declares
/// for the table entry `raw` was read from.
unsafe fn entry<F: Copy>(raw: isize, name: &str) -> io::Result<F> {
    const { assert!(size_of::<F>() == size_of::<isize>()) };
    if raw == 0 {
        return Err(io::Error::other(format!(
            "MI function table has no {name} entry"
        )));
    }
    // SAFETY: the entry is nonzero and pointer-sized; the caller guarantees that
    // F is its exact function-pointer type.
    Ok(unsafe { transmute_copy::<isize, F>(&raw) })
}

/// Reports a failed close/delete, including a missing table entry.
fn finish_cleanup(result: io::Result<MI_Result>, context: &str, log: &Logger) {
    match result {
        Ok(result) => cleanup(result, context, log),
        Err(error) => log
            .clone()
            .broker_message(format_args!("{context}: {error}"), true),
    }
}

fn check(result: MI_Result, context: &str) -> io::Result<()> {
    if result == MI_RESULT_OK {
        Ok(())
    } else {
        Err(io::Error::other(format!("{context}: MI_Result={result}")))
    }
}

fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIM strings cannot contain NUL",
        ));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

struct Application(MI_Application, Logger);

impl Application {
    fn open(log: &Logger) -> io::Result<Self> {
        let mut handle = MI_Application::default();
        // SAFETY: writable zero-initialized handle; optional arguments are null.
        let result =
            unsafe { MI_Application_InitializeV1(0, ptr::null(), ptr::null_mut(), &mut handle) };
        check(result, "initialize MI application")?;
        Ok(Self(handle, log.clone()))
    }

    fn session(&mut self) -> io::Result<Session> {
        let mut destination = MI_DestinationOptions::default();
        // SAFETY: live application, exact SDK signature, writable output handle.
        let result = unsafe {
            let new: NewDestination =
                entry((*self.0.ft).NewDestinationOptions, "NewDestinationOptions")?;
            new(&mut self.0, &mut destination)
        };
        check(result, "create MI destination options")?;
        let mut destination = DestinationOptions(destination);
        // Local providers need IMPERSONATE to manage BGP. Scope this grant to
        // this destination instead of raising the process-wide COM default.
        // Equivalent to SDK MI_DestinationOptions_SetImpersonationType.
        // SAFETY: live destination options, exact SetNumber ABI from mi.h,
        // and a static terminated option name; no delegation or remote target.
        let result = unsafe {
            let set: DestinationSetNumber = entry((*destination.0.ft).SetNumber, "SetNumber")?;
            set(
                &mut destination.0,
                w!("__MI_DESTINATIONOPTIONS_IMPERSONATION_TYPE"),
                MI_DestinationOptions_ImpersonationType_Impersonate as u32,
                0,
            )
        };
        check(result, "set local MI impersonation level")?;
        // Values qualifiers are localized. Request English so status labels
        // have the same meaning even on a server with a different UI language.
        for name in [
            w!("__MI_DESTINATIONOPTIONS_UI_LOCALE"),
            w!("__MI_DESTINATIONOPTIONS_DATA_LOCALE"),
        ] {
            // SAFETY: live destination options, exact ABI and static UTF-16 strings.
            let result = unsafe {
                let set: DestinationSetString = entry((*destination.0.ft).SetString, "SetString")?;
                set(&mut destination.0, name, w!("en-US"), 0)
            };
            check(result, "set MI status metadata locale")?;
        }
        let mut session = MI_Session::default();
        // SAFETY: application is live; SDK NewSession signature and writable
        // output. Null protocol/destination select the local default transport.
        let result = unsafe {
            let new_session: NewSession = entry((*self.0.ft).NewSession, "NewSession")?;
            new_session(
                &mut self.0,
                ptr::null(),
                ptr::null(),
                &mut destination.0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut session,
            )
        };
        check(result, "create local MI session")?;
        Ok(Session {
            handle: session,
            _destination: destination,
            log: self.1.clone(),
        })
    }

    fn parameters(
        &mut self,
        method: Method,
        peer: &str,
        domain: Option<&str>,
    ) -> io::Result<Parameters> {
        let mut name = wide(peer)?;
        let mut domain = domain.map(wide).transpose()?;
        let mut instance = ptr::null_mut();
        let class = match method {
            Method::Get => w!("PS_BgpPeer_Get"),
            Method::Start => w!("PS_BgpPeer_Start"),
            Method::Stop => w!("PS_BgpPeer_Stop"),
        };
        // SAFETY: application is live; class is terminated UTF-16; null RTTI
        // requests a dynamic instance; output is writable. Signature is mi.h.
        let result = unsafe {
            let new_instance: NewInstance = entry((*self.0.ft).NewInstance, "NewInstance")?;
            new_instance(&mut self.0, class, ptr::null(), &mut instance)
        };
        check(result, "create MI method parameters")?;
        if instance.is_null() {
            return Err(io::Error::other("MI returned null method parameters"));
        }
        let mut parameters = Parameters(instance, self.1.clone());
        let mut names = [name.as_mut_ptr()];
        let value = MI_Value {
            stringa: MI_StringA {
                data: names.as_mut_ptr(),
                size: 1,
            },
        };
        // SAFETY: one terminated string and pointer array live through Add;
        // matching union type. MI copies the data before local buffers drop.
        unsafe {
            parameters.add(w!("Name"), &value, MI_STRINGA)?;
        }
        if let Some(domain) = &mut domain {
            let value = MI_Value {
                string: domain.as_mut_ptr(),
            };
            // SAFETY: terminated string lives through Add; matching union type.
            unsafe {
                parameters.add(w!("RoutingDomain"), &value, MI_STRING)?;
            }
        }
        if method == Method::Stop {
            let value = MI_Value { boolean: 1 };
            // SAFETY: MI_BOOLEAN matches initialized union member, static name.
            // Stop's documented Force parameter suppresses provider confirmation.
            unsafe {
                parameters.add(w!("Force"), &value, MI_BOOLEAN)?;
            }
        }
        Ok(parameters)
    }

    fn options(&mut self) -> io::Result<OperationOptions> {
        let mut options = MI_OperationOptions::default();
        // SAFETY: live application, exact SDK signature, writable output handle.
        let result = unsafe {
            let new_options: NewOptions =
                entry((*self.0.ft).NewOperationOptions, "NewOperationOptions")?;
            new_options(&mut self.0, 0, &mut options)
        };
        check(result, "create MI operation options")?;
        let mut options = OperationOptions(options);
        let interval = MI_Interval {
            seconds: 5,
            ..Default::default()
        };
        // SAFETY: live options and interval, exact SDK SetInterval signature.
        // This is the same option used by MI_OperationOptions_SetTimeout.
        let result = unsafe {
            let set_interval: SetInterval = entry((*options.0.ft).SetInterval, "SetInterval")?;
            set_interval(
                &mut options.0,
                w!("__MI_OPERATIONOPTIONS_TIMEOUT"),
                &interval,
                0,
            )
        };
        check(result, "set MI operation timeout")?;
        Ok(options)
    }
}

impl Drop for Application {
    fn drop(&mut self) {
        // SAFETY: live uniquely owned application. Callers declare it before
        // child handles, which drop first in reverse local-variable order.
        let result = unsafe {
            entry::<ApplicationClose>((*self.0.ft).Close, "Close").map(|close| close(&mut self.0))
        };
        finish_cleanup(result, "close MI application", &self.1);
    }
}

struct DestinationOptions(MI_DestinationOptions);
impl Drop for DestinationOptions {
    fn drop(&mut self) {
        // SAFETY: uniquely owned options; dependent session already closed.
        // A missing Delete entry leaves the options allocated rather than unsound.
        let _ = unsafe {
            entry::<DestinationDelete>((*self.0.ft).Delete, "Delete")
                .map(|delete| delete(&mut self.0))
        };
    }
}

struct Session {
    handle: MI_Session,
    _destination: DestinationOptions,
    log: Logger,
}
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: live session, exact SDK signature, no asynchronous callback;
        // its operations have been drained and closed before session destruction.
        let result = unsafe {
            entry::<SessionClose>((*self.handle.ft).Close, "Close")
                .map(|close| close(&mut self.handle, ptr::null_mut(), None))
        };
        finish_cleanup(result, "close MI session", &self.log);
    }
}

struct Parameters(*mut MI_Instance, Logger);
impl Parameters {
    /// The value's pointers must remain valid for the duration of this call.
    ///
    /// # Safety
    /// `value` must contain the union member specified by `kind`, with valid
    /// terminated strings/array storage where applicable. `name` must be a
    /// valid NUL-terminated UTF-16 string.
    unsafe fn add(&mut self, name: *const u16, value: &MI_Value, kind: MI_Type) -> io::Result<()> {
        // SAFETY: live instance; caller supplies matching union and valid name.
        // Flags 0 ask MI to copy the value, including pointed-to strings/arrays.
        let result = unsafe {
            let add: AddElement = entry((*(*self.0).ft).AddElement, "AddElement")?;
            add(self.0, name, value, kind, 0)
        };
        check(result, "add MI method parameter")
    }
}
impl Drop for Parameters {
    fn drop(&mut self) {
        // SAFETY: uniquely owned MI-allocated dynamic instance; exact signature.
        let result = unsafe {
            entry::<InstanceDelete>((*(*self.0).ft).Delete, "Delete").map(|delete| delete(self.0))
        };
        finish_cleanup(result, "delete MI parameters", &self.1);
    }
}

struct OperationOptions(MI_OperationOptions);
impl Drop for OperationOptions {
    fn drop(&mut self) {
        // SAFETY: live options, no operation still uses them; exact signature.
        // A missing Delete entry leaves the options allocated rather than unsound.
        let _ = unsafe {
            entry::<OptionsDelete>((*self.0.ft).Delete, "Delete").map(|delete| delete(&mut self.0))
        };
    }
}

struct Operation {
    handle: MI_Operation,
    drained: bool,
    class_result: bool,
    log: Logger,
}

impl Operation {
    fn finish(&mut self) -> io::Result<()> {
        self.finish_with(|_| Ok(()))
    }

    // The visitor must consume all borrowed data during the callback.
    fn finish_with(
        &mut self,
        mut visit: impl FnMut(*const MI_Instance) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut returned_value = false;
        // SAFETY: initialized instance operation, exact SDK GetInstance ABI.
        let next: GetInstance = unsafe { entry((*self.handle.ft).GetInstance, "GetInstance") }?;
        self.drain(next, |instance| {
            // SAFETY: drain lends a live instance until the next result fetch.
            unsafe {
                return_value(instance)?;
            }
            returned_value = true;
            visit(instance)
        })?;
        if returned_value {
            Ok(())
        } else {
            Err(io::Error::other("CIM method returned no ReturnValue"))
        }
    }

    // next must be the SDK accessor appropriate to this operation. All visitors
    // below consume borrowed pointers before another result fetch or Close.
    fn drain<T>(
        &mut self,
        next: Next<T>,
        mut visit: impl FnMut(*const T) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut failure = None;
        loop {
            let mut instance = ptr::null();
            let mut more = 0;
            let mut result = MI_RESULT_OK;
            let mut message = ptr::null();
            // SAFETY: live synchronous operation with no callbacks; all outputs
            // writable. Borrowed result/message are consumed before next call.
            let status = unsafe {
                next(
                    &mut self.handle,
                    &mut instance,
                    &mut more,
                    &mut result,
                    &mut message,
                    ptr::null_mut(),
                )
            };
            check(status, "retrieve MI method result")?;
            if result != MI_RESULT_OK {
                // SAFETY: MI supplies null or terminated UTF-16 valid until the
                // next result retrieval or Close. Copy now while operation is live.
                let message = unsafe { error_message(message) };
                failure.get_or_insert_with(|| {
                    io::Error::other(format!("CIM method failed: MI_Result={result} {message}"))
                });
            }
            if !instance.is_null() {
                if let Err(error) = visit(instance) {
                    failure.get_or_insert(error);
                }
            }
            if more == 0 {
                self.drained = true;
                break;
            }
            // Drain all results even after provider/ReturnValue errors: closing
            // an undrained synchronous MI operation can deadlock.
        }
        if let Some(error) = failure {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.drained {
            // SAFETY: live operation; exact Cancel signature, default reason 0.
            let result = unsafe {
                entry::<OperationCancel>((*self.handle.ft).Cancel, "Cancel")
                    .map(|cancel| cancel(&mut self.handle, 0))
            };
            finish_cleanup(result, "cancel MI operation", &self.log);
            let result = if self.class_result {
                // SAFETY: class operation; exact SDK GetClass accessor.
                unsafe { entry::<GetClass>((*self.handle.ft).GetClass, "GetClass") }
                    .and_then(|next| self.drain(next, |_| Ok(())))
            } else {
                // SAFETY: instance operation; exact SDK GetInstance accessor.
                unsafe { entry::<GetInstance>((*self.handle.ft).GetInstance, "GetInstance") }
                    .and_then(|next| self.drain(next, |_| Ok(())))
            };
            if let Err(error) = result {
                self.log
                    .clone()
                    .log(format_args!("drain canceled MI operation: {error}"));
            }
        }
        // SAFETY: uniquely owned initialized operation; exact SDK Close signature.
        // If normal draining failed, cancellation and draining were attempted above.
        let result = unsafe {
            entry::<OperationClose>((*self.handle.ft).Close, "Close")
                .map(|close| close(&mut self.handle))
        };
        finish_cleanup(result, "close MI operation", &self.log);
    }
}

fn cleanup(result: MI_Result, context: &str, log: &Logger) {
    if let Err(error) = check(result, context) {
        log.clone().broker_message(error, true);
    }
}

/// # Safety
/// `instance` must be a live MI instance with a valid function table.
unsafe fn return_value(instance: *const MI_Instance) -> io::Result<()> {
    let mut value = MI_Value::default();
    let mut kind = 0;
    let mut flags = 0;
    // SAFETY: caller guarantees instance validity; all outputs writable and
    // signature matches mi.h. Optional index output is null.
    let result = unsafe {
        let get: GetElement = entry((*(*instance).ft).GetElement, "GetElement")?;
        get(
            instance,
            w!("ReturnValue"),
            &mut value,
            &mut kind,
            &mut flags,
            ptr::null_mut(),
        )
    };
    check(result, "read CIM ReturnValue")?;
    if kind != MI_UINT32 || flags & MI_FLAG_NULL != 0 {
        return Err(io::Error::other("CIM ReturnValue is not a non-null uint32"));
    }
    // SAFETY: GetElement succeeded and reported non-null MI_UINT32.
    let code = unsafe { value.uint32 };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("CIM method ReturnValue={code}")))
    }
}

/// # Safety
/// `message` must be null or point to a live NUL-terminated UTF-16 string.
unsafe fn error_message(message: *const u16) -> String {
    if message.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: caller guarantees valid storage through the terminating NUL.
    unsafe {
        while *message.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(message, length))
    }
}

/// # Safety
/// instance must be live; name must be a terminated UTF-16 string. Any pointers
/// in the returned union remain borrowed from instance and must not outlive it.
unsafe fn element(
    instance: *const MI_Instance,
    name: *const u16,
    expected: MI_Type,
) -> io::Result<MI_Value> {
    let mut value = MI_Value::default();
    let mut kind = 0;
    let mut flags = 0;
    // SAFETY: caller guarantees live instance/name, exact ABI, writable outputs.
    let result = unsafe {
        let get: GetElement = entry((*(*instance).ft).GetElement, "GetElement")?;
        get(
            instance,
            name,
            &mut value,
            &mut kind,
            &mut flags,
            ptr::null_mut(),
        )
    };
    check(result, "read BGP status property")?;
    if kind != expected || flags & MI_FLAG_NULL != 0 {
        return Err(io::Error::other(
            "BGP status property has an unexpected type or null value",
        ));
    }
    Ok(value)
}

/// # Safety
/// qualifiers must be borrowed from a live MI_Class; name must be terminated.
unsafe fn qualifier_strings(
    qualifiers: &MI_QualifierSet,
    name: *const u16,
) -> io::Result<Vec<String>> {
    let mut value = MI_Value::default();
    let mut kind = 0;
    let mut flags = 0;
    let mut index = 0;
    // SAFETY: live qualifier set and terminated name, exact SDK signature.
    let result = unsafe {
        let get: GetQualifier = entry((*qualifiers.ft).GetQualifier, "GetQualifier")?;
        get(
            qualifiers, name, &mut kind, &mut flags, &mut value, &mut index,
        )
    };
    check(result, "read BGP status enum qualifier")?;
    if kind != MI_STRINGA || flags & MI_FLAG_NULL != 0 {
        return Err(io::Error::other(
            "BGP status enum qualifier is not a string array",
        ));
    }
    // SAFETY: successful accessor reported a non-null MI_STRINGA union member.
    let array = unsafe { value.stringa };
    if array.size == 0 {
        return Ok(Vec::new());
    }
    if array.data.is_null() {
        return Err(io::Error::other("null BGP status enum array"));
    }
    let length =
        usize::try_from(array.size).map_err(|_| io::Error::other("BGP enum array is too large"))?;
    // SAFETY: MI array contains size valid string pointers; class remains alive.
    unsafe {
        std::slice::from_raw_parts(array.data, length)
            .iter()
            .map(|&string| {
                if string.is_null() {
                    Err(io::Error::other("null BGP status enum string"))
                } else {
                    Ok(error_message(string))
                }
            })
            .collect()
    }
}

/// # Safety
/// class must be a live MI class; property must be terminated UTF-16.
unsafe fn enum_mapping(
    class: *const MI_Class,
    property: *const u16,
) -> io::Result<Vec<(u32, String)>> {
    let mut qualifiers = MI_QualifierSet::default();
    // SAFETY: caller guarantees live class/property; exact SDK signature.
    let result = unsafe {
        let get: ClassGetElement = entry((*(*class).ft).GetElement, "GetElement")?;
        get(
            class,
            property,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut qualifiers,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    check(result, "read BGP status enum metadata")?;
    if qualifiers.ft.is_null() {
        return Err(io::Error::other("BGP status enum metadata is missing"));
    }
    // SAFETY: qualifier set was populated from the still-live class above.
    let (values, labels) = unsafe {
        (
            qualifier_strings(&qualifiers, w!("ValueMap"))?,
            qualifier_strings(&qualifiers, w!("Values"))?,
        )
    };
    if values.is_empty() || values.len() != labels.len() {
        return Err(io::Error::other("BGP status enum metadata is incomplete"));
    }
    values
        .into_iter()
        .zip(labels)
        .map(|(value, label)| {
            value
                .parse::<u32>()
                .map(|value| (value, label))
                .map_err(|_| io::Error::other("BGP status enum has an unsupported numeric mapping"))
        })
        .collect()
}

fn status_started(code: u32, mapping: &[(u32, String)]) -> io::Result<bool> {
    let label = mapping
        .iter()
        .find(|(value, _)| *value == code)
        .map(|(_, label)| label.as_str())
        .ok_or_else(|| io::Error::other(format!("unknown BGP ConnectivityStatus={code}")))?;
    match label {
        "Stopped" => Ok(false),
        "Connecting" | "Connected" | "Disconnected" => Ok(true),
        _ => Err(io::Error::other(format!(
            "unrecognized BGP ConnectivityStatus label {label:?}"
        ))),
    }
}

/// # Safety
/// instance must be a live MI method result for the duration of this call.
unsafe fn peer_status(instance: *const MI_Instance, mapping: &[(u32, String)]) -> io::Result<bool> {
    // SAFETY: caller lends the live method result for this call.
    let output = unsafe { element(instance, w!("cmdletOutput"), MI_INSTANCEA)? };
    // SAFETY: element checked the MI_INSTANCEA union discriminator.
    let peers = unsafe { output.instancea };
    if peers.size != 1 || peers.data.is_null() {
        return Err(io::Error::other(
            "BGP status query must return exactly one peer",
        ));
    }
    // SAFETY: non-null MI array with one element, result still alive.
    let peer = unsafe { *peers.data };
    if peer.is_null() {
        return Err(io::Error::other("BGP status query returned a null peer"));
    }
    // SAFETY: embedded peer and properties remain owned by the live result.
    let code = unsafe { element(peer, w!("ConnectivityStatus"), MI_UINT32)?.uint32 };
    status_started(code, mapping)
}

fn schema_operation(
    session: &mut Session,
    options: &mut OperationOptions,
    namespace: *const u16,
    class: *const u16,
) -> io::Result<Operation> {
    let mut handle = MI_Operation::default();
    // SAFETY: private callers supply terminated static namespace/class names;
    // session/options are live, exact SDK signature, writable output.
    unsafe {
        let get: SessionGetClass = entry((*session.handle.ft).GetClass, "GetClass")?;
        get(
            &mut session.handle,
            MI_OPERATIONFLAGS_FULL_RTTI | MI_OPERATIONFLAGS_LOCALIZED_QUALIFIERS,
            &mut options.0,
            namespace,
            class,
            ptr::null_mut(),
            &mut handle,
        );
    }
    if handle.ft.is_null() {
        return Err(io::Error::other(
            "MI returned an uninitialized schema operation",
        ));
    }
    Ok(Operation {
        handle,
        drained: false,
        class_result: true,
        log: session.log.clone(),
    })
}

pub(super) fn started(peer: &str, domain: Option<&str>, log: &Logger) -> io::Result<bool> {
    let mut application = Application::open(log)?;
    let mut session = application.session()?;
    let parameters = application.parameters(Method::Get, peer, domain)?;
    let mut options = application.options()?;
    // Resolve enum values from the target provider's schema rather than assume
    // numeric values that Microsoft does not specify in the public class docs.
    let mapping = {
        let mut schema = schema_operation(
            &mut session,
            &mut options,
            w!("root/Microsoft/Windows/RemoteAccess"),
            w!("BgpPeerConfig"),
        )?;
        let mut mapping = None;
        // SAFETY: class operation; exact SDK GetClass result-accessor signature.
        let next: GetClass = unsafe { entry((*schema.handle.ft).GetClass, "GetClass") }?;
        schema.drain(next, |class| {
            // SAFETY: drain lends a live schema until next fetch/Close.
            mapping = Some(unsafe { enum_mapping(class, w!("ConnectivityStatus")) }?);
            Ok(())
        })?;
        mapping.ok_or_else(|| io::Error::other("BGP peer schema was not returned"))?
    };
    let mut handle = MI_Operation::default();
    // SAFETY: live handles, static terminated strings, exact SDK Invoke ABI;
    // Get reads configuration only; no callbacks means synchronous retrieval.
    unsafe {
        let invoke: Invoke = entry((*session.handle.ft).Invoke, "Invoke")?;
        invoke(
            &mut session.handle,
            0,
            &mut options.0,
            w!("root/Microsoft/Windows/RemoteAccess"),
            w!("PS_BgpPeer"),
            w!("Get"),
            ptr::null(),
            parameters.0,
            ptr::null_mut(),
            &mut handle,
        );
    }
    if handle.ft.is_null() {
        return Err(io::Error::other(
            "MI returned an uninitialized status operation",
        ));
    }
    let mut operation = Operation {
        handle,
        drained: false,
        class_result: false,
        log: session.log.clone(),
    };
    let mut started = None;
    operation.finish_with(|instance| {
        if started.is_some() {
            return Err(io::Error::other(
                "BGP status query must return exactly one peer",
            ));
        }
        // SAFETY: method result is lent by finish_with for this callback only.
        started = Some(unsafe { peer_status(instance, &mapping) }?);
        Ok(())
    })?;
    started.ok_or_else(|| io::Error::other("BGP status query returned no peer"))
}

pub(super) fn invoke(
    peer: &str,
    domain: Option<&str>,
    method: Method,
    log: &Logger,
) -> io::Result<()> {
    // Children are declared after application, so reverse local-variable drop
    // order closes them first. Native handles stay on the calling thread.
    let mut application = Application::open(log)?;
    let mut session = application.session()?;
    let parameters = application.parameters(method, peer, domain)?;
    let mut options = application.options()?;
    let mut handle = MI_Operation::default();
    let method_name = match method {
        Method::Get => w!("Get"),
        Method::Start => w!("Start"),
        Method::Stop => w!("Stop"),
    };
    // SAFETY: live session/options/parameters and exact SDK Invoke signature.
    // Null inboundInstance invokes a static class method; no callbacks means
    // synchronous result retrieval. The namespace uses MI forward-slash notation.
    unsafe {
        let invoke: Invoke = entry((*session.handle.ft).Invoke, "Invoke")?;
        invoke(
            &mut session.handle,
            0,
            &mut options.0,
            w!("root/Microsoft/Windows/RemoteAccess"),
            w!("PS_BgpPeer"),
            method_name,
            ptr::null(),
            parameters.0,
            ptr::null_mut(),
            &mut handle,
        );
    }
    if handle.ft.is_null() {
        return Err(io::Error::other("MI returned an uninitialized operation"));
    }
    let mut operation = Operation {
        handle,
        drained: false,
        class_result: false,
        log: session.log.clone(),
    };
    operation.finish()
}

#[cfg(test)]
pub(super) fn rpc_schema_fixture() -> io::Result<()> {
    let mut application = Application::open(&Logger::new(false)?)?;
    let mut session = application.session()?;
    let mut options = application.options()?;
    let mut schema = schema_operation(
        &mut session,
        &mut options,
        w!("root/StandardCimv2"),
        w!("MSFT_NetAdapter"),
    )?;
    // SAFETY: the class operation supplies the SDK GetClass accessor.
    let next: GetClass = unsafe { entry((*schema.handle.ft).GetClass, "GetClass") }?;
    schema.drain(next, |class| {
        // SAFETY: drain lends the live class for this callback only.
        let _ = unsafe { enum_mapping(class, w!("InterfaceOperationalStatus")) }?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_function_table_entries_are_errors_not_null_function_pointers() {
        // SAFETY: a zero entry is rejected before any conversion.
        let missing = unsafe { entry::<ApplicationClose>(0, "Close") };
        assert!(missing.unwrap_err().to_string().contains("no Close entry"));
        extern "system" fn close_probe(_: *mut MI_Application) -> MI_Result {
            MI_RESULT_NOT_SUPPORTED
        }
        let raw = isize::try_from(close_probe as *const () as usize).unwrap();
        // SAFETY: raw came from a function with exactly the ApplicationClose ABI.
        let close = unsafe { entry::<ApplicationClose>(raw, "Close") }.unwrap();
        // SAFETY: the probe ignores its argument.
        assert_eq!(unsafe { close(ptr::null_mut()) }, MI_RESULT_NOT_SUPPORTED);
    }

    #[test]
    fn connectivity_mapping_distinguishes_stopped_from_running_without_assuming_ids() {
        let mapping = vec![
            (71, "Stopped".into()),
            (42, "Connecting".into()),
            (99, "Connected".into()),
            (12, "Disconnected".into()),
            (3, "Unknown".into()),
        ];
        assert!(!status_started(71, &mapping).unwrap());
        for code in [42, 99, 12] {
            assert!(status_started(code, &mapping).unwrap());
        }
        assert!(status_started(0, &mapping).is_err());
        assert!(status_started(3, &mapping).is_err());
    }

    #[cfg(not(miri))]
    #[test]
    #[ignore = "requires access to Windows CIM namespaces; run explicitly outside a restricted sandbox"]
    fn native_mi_reads_enum_qualifiers_from_local_class_schema() {
        // The broker initializes private process-wide COM security before native MI.
        // Exercise a real provider under those defaults without changing BGP.
        let _com = super::super::com::ComHost::initialize().unwrap();
        let mut application = Application::open(&Logger::new(false).unwrap()).unwrap();
        let mut session = application.session().unwrap();
        let mut options = application.options().unwrap();
        // Read-only Windows network adapter schema; no BGP changes.
        let mut schema = schema_operation(
            &mut session,
            &mut options,
            w!("root/StandardCimv2"),
            w!("MSFT_NetAdapter"),
        )
        .unwrap();
        let mut mapping = None;
        // SAFETY: class operation, exact SDK accessor signature.
        let next: GetClass = unsafe { entry((*schema.handle.ft).GetClass, "GetClass") }.unwrap();
        schema
            .drain(next, |class| {
                // SAFETY: class is lent by drain until the next result fetch/Close.
                mapping = Some(unsafe { enum_mapping(class, w!("InterfaceOperationalStatus")) }?);
                Ok(())
            })
            .unwrap();
        let mapping = mapping.unwrap();
        assert!(mapping.iter().any(|(value, _)| *value == 3));
        assert!(schema.drained);
    }

    #[cfg(not(miri))]
    #[test]
    fn native_mi_parses_embedded_bgp_status_and_rejects_ambiguous_results() {
        let mut application = Application::open(&Logger::new(false).unwrap()).unwrap();
        let mapping = vec![(7, "Stopped".into()), (8, "Connecting".into())];
        for code in [7, 8, 9] {
            let mut peer = application.parameters(Method::Get, "test", None).unwrap();
            let value = MI_Value { uint32: code };
            // SAFETY: live instance, static name, matching initialized union.
            unsafe {
                peer.add(w!("ConnectivityStatus"), &value, MI_UINT32)
                    .unwrap();
            }
            for count in [0, 1, 2] {
                let mut result = application.parameters(Method::Get, "test", None).unwrap();
                let mut peers = [peer.0, peer.0];
                let value = MI_Value {
                    instancea: MI_InstanceA {
                        data: if count == 0 {
                            ptr::null_mut()
                        } else {
                            peers.as_mut_ptr()
                        },
                        size: count,
                    },
                };
                // SAFETY: valid array of count live instances, matching union type.
                unsafe {
                    result
                        .add(w!("cmdletOutput"), &value, MI_INSTANCEA)
                        .unwrap_or_else(|error| panic!("count={count} code={code}: {error}"));
                }
                // SAFETY: live locally allocated method-result fixture.
                let status = unsafe { peer_status(result.0, &mapping) };
                if count == 1 && code != 9 {
                    assert_eq!(status.unwrap(), code == 8);
                } else {
                    assert!(status.is_err());
                }
            }
        }
    }

    #[test]
    fn cim_strings_preserve_unicode_and_reject_embedded_nul() {
        let encoded = wide("peer-\u{1f642}").unwrap();
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
            "peer-\u{1f642}"
        );
        assert!(wide("peer\0other").is_err());
    }

    // Miri cannot execute mi.dll. The following fixtures use local MI objects or
    // a nonexistent class in root/cimv2; they never invoke a BGP provider method.
    // The opt-in schema test above reads a real class without mutating it.
    #[cfg(not(miri))]
    #[test]
    fn native_mi_parameters_copy_strings_and_force_stop_without_confirmation() {
        let mut application = Application::open(&Logger::new(false).unwrap()).unwrap();
        for method in [Method::Start, Method::Stop] {
            let parameters = application
                .parameters(method, "peer-\u{1f642}", Some("Rd001"))
                .unwrap();
            for (name, expected_kind) in [
                (w!("Name"), MI_STRINGA),
                (w!("RoutingDomain"), MI_STRING),
                (w!("Force"), MI_BOOLEAN),
            ] {
                let mut value = MI_Value::default();
                let mut kind = 0;
                // SAFETY: live locally allocated instance, exact signature,
                // static property name and writable outputs.
                let status = unsafe {
                    let get: GetElement =
                        entry((*(*parameters.0).ft).GetElement, "GetElement").unwrap();
                    get(
                        parameters.0,
                        name,
                        &mut value,
                        &mut kind,
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if expected_kind == MI_BOOLEAN && method == Method::Start {
                    assert_eq!(status, MI_RESULT_NO_SUCH_PROPERTY);
                    continue;
                }
                assert_eq!(status, MI_RESULT_OK);
                assert_eq!(kind, expected_kind);
                // SAFETY: successful GetElement with checked union discriminator;
                // strings/array remain owned by the live parameters instance.
                unsafe {
                    match kind {
                        MI_STRINGA => {
                            assert_eq!(value.stringa.size, 1);
                            assert_eq!(error_message(*value.stringa.data), "peer-\u{1f642}");
                        }
                        MI_STRING => assert_eq!(error_message(value.string), "Rd001"),
                        MI_BOOLEAN => assert_eq!(value.boolean, 1),
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn native_mi_drains_provider_error_and_closes_handles() {
        let mut application = Application::open(&Logger::new(false).unwrap()).unwrap();
        let mut session = application.session().unwrap();
        let parameters = application.parameters(Method::Start, "test", None).unwrap();
        let mut options = application.options().unwrap();
        let mut handle = MI_Operation::default();
        // SAFETY: live handles, exact SDK signature, terminated static strings,
        // writable output. An absent class ensures no method can change state.
        unsafe {
            let invoke: Invoke = entry((*session.handle.ft).Invoke, "Invoke").unwrap();
            invoke(
                &mut session.handle,
                0,
                &mut options.0,
                w!("root/cimv2"),
                w!("BfdWinService_NonexistentClass_ForMiTest"),
                w!("Start"),
                ptr::null(),
                parameters.0,
                ptr::null_mut(),
                &mut handle,
            );
        }
        assert!(!handle.ft.is_null());
        let mut operation = Operation {
            handle,
            drained: false,
            class_result: false,
            log: session.log.clone(),
        };
        let error = operation.finish().unwrap_err().to_string();
        assert!(error.contains("CIM method failed"), "{error}");
        assert!(operation.drained);
    }

    #[cfg(not(miri))]
    #[test]
    fn native_mi_checks_cim_return_code_and_type() {
        let mut application = Application::open(&Logger::new(false).unwrap()).unwrap();
        for (value, kind, succeeds) in [
            (MI_Value { uint32: 0 }, MI_UINT32, true),
            (MI_Value { uint32: 5 }, MI_UINT32, false),
            (MI_Value { boolean: 0 }, MI_BOOLEAN, false),
        ] {
            let mut parameters = application.parameters(Method::Start, "test", None).unwrap();
            // SAFETY: union/type match in each fixture, name is terminated.
            unsafe {
                parameters.add(w!("ReturnValue"), &value, kind).unwrap();
            }
            // SAFETY: live locally allocated MI instance.
            assert_eq!(unsafe { return_value(parameters.0) }.is_ok(), succeeds);
        }
    }
}
