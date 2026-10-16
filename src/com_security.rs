//! Process-wide COM options for the BGP broker's native MI client.
#![allow(unsafe_code)]

use windows::{
    core::Result,
    Win32::System::Com::{
        CLSID_GlobalOptions, CoCreateInstance, IGlobalOptions, CLSCTX_INPROC_SERVER,
        COMGLB_EXCEPTION_DONOT_HANDLE_ANY, COMGLB_EXCEPTION_HANDLING, COMGLB_UNMARSHALING_POLICY,
        COMGLB_UNMARSHALING_POLICY_STRONG,
    },
};

/// Configures COM before exposing objects or connecting to a provider.
pub(crate) fn configure_global_options() -> Result<()> {
    // SAFETY: the calling thread has initialized COM; this built-in object is
    // used and released in that apartment before any application registration.
    let options: IGlobalOptions =
        unsafe { CoCreateInstance(&CLSID_GlobalOptions, None, CLSCTX_INPROC_SERVER) }?;
    // SAFETY: valid global option/value; any failure prevents host startup.
    unsafe {
        options.Set(
            COMGLB_EXCEPTION_HANDLING,
            COMGLB_EXCEPTION_DONOT_HANDLE_ANY.0 as usize,
        )
    }?;
    // SAFETY: valid global option/value. Native MI compatibility is covered by
    // the explicit read-only provider schema test under the broker's policy.
    unsafe {
        options.Set(
            COMGLB_UNMARSHALING_POLICY,
            COMGLB_UNMARSHALING_POLICY_STRONG.0 as usize,
        )
    }?;
    Ok(())
}
