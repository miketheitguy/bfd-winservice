//! Exercise the C exception boundary without raising faults across Rust frames.
use windows_sys::Win32::{
    Foundation::{
        RPC_X_BAD_STUB_DATA, STATUS_ACCESS_VIOLATION, STATUS_BREAKPOINT,
        STATUS_DATATYPE_MISALIGNMENT, STATUS_ILLEGAL_INSTRUCTION, STATUS_IN_PAGE_ERROR,
        STATUS_POSSIBLE_DEADLOCK, STATUS_STACK_BUFFER_OVERRUN, STATUS_STACK_OVERFLOW,
    },
    System::Rpc::{RPC_S_CALL_CANCELLED, RPC_S_SERVER_UNAVAILABLE},
};

extern "C" {
    fn bfd_rpc_test_exception_filter(code: u32) -> i32;
    fn bfd_rpc_test_raise(code: u32) -> u32;
}

#[test]
fn recoverable_rpc_exceptions_are_caught_entirely_inside_c() {
    for code in [
        RPC_S_SERVER_UNAVAILABLE,
        RPC_X_BAD_STUB_DATA,
        RPC_S_CALL_CANCELLED,
    ] {
        let code = u32::try_from(code).unwrap();
        // SAFETY: the helper only evaluates the shared Windows exception filter.
        assert_eq!(unsafe { bfd_rpc_test_exception_filter(code) }, 1);
        // SAFETY: these recoverable RPC exceptions are raised and handled inside
        // the native helper; no SEH unwinds a Rust frame or retains any storage.
        assert_eq!(unsafe { bfd_rpc_test_raise(code) }, code);
    }
}

#[test]
fn fatal_native_faults_are_excluded_from_rpc_recovery() {
    for code in [
        STATUS_ACCESS_VIOLATION,
        STATUS_STACK_OVERFLOW,
        STATUS_STACK_BUFFER_OVERRUN,
        STATUS_ILLEGAL_INSTRUCTION,
        STATUS_IN_PAGE_ERROR,
        STATUS_DATATYPE_MISALIGNMENT,
        STATUS_POSSIBLE_DEADLOCK,
        STATUS_BREAKPOINT,
    ] {
        // SAFETY: classify the code only; no fatal exception is actually raised.
        // NTSTATUS is signed; this cast preserves its native exception-code bits.
        assert_eq!(unsafe { bfd_rpc_test_exception_filter(code as u32) }, 0);
    }
}
