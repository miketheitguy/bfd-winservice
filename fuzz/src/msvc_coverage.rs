//! Late sanitizer-coverage registration for MSVC libFuzzer builds.

use std::{mem::size_of, ptr, sync::Once};

unsafe extern "C" {
    static mut __start___sancov_cntrs: usize;
    static mut __stop___sancov_cntrs: u8;
    static __start___sancov_pcs: usize;
    static __stop___sancov_pcs: usize;

    fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8);
    fn __sanitizer_cov_pcs_init(start: *const usize, stop: *const usize);
}

pub(super) fn initialize() {
    static REGISTER: Once = Once::new();

    REGISTER.call_once(|| {
        // The MSVC sanitizer thunk places one pointer-sized sentinel before
        // each section. The linker orders the A/M/Z subsections so these
        // ranges cover every retained module counter and PC pair.
        let counters_start = ptr::addr_of_mut!(__start___sancov_cntrs)
            .cast::<u8>()
            .wrapping_add(size_of::<usize>());
        let counters_stop = ptr::addr_of_mut!(__stop___sancov_cntrs);
        let pcs_start = ptr::addr_of!(__start___sancov_pcs).wrapping_add(1);
        let pcs_stop = ptr::addr_of!(__stop___sancov_pcs);

        // SAFETY: These symbols are supplied by the MSVC sanitizer runtime
        // linked by cargo-fuzz. Their ordered, process-lifetime image sections
        // satisfy libFuzzer's counter and PC-table range contracts. Once keeps
        // the late registration from being repeated for subsequent inputs.
        unsafe {
            __sanitizer_cov_8bit_counters_init(counters_start, counters_stop);
            __sanitizer_cov_pcs_init(pcs_start, pcs_stop);
        }
    });
}
