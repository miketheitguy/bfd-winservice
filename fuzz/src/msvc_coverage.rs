//! Late sanitizer-coverage registration for MSVC libFuzzer builds.

use std::sync::Once;

unsafe extern "C" {
    fn bfd_fuzz_initialize_coverage();
}

pub(super) fn initialize() {
    static REGISTER: Once = Once::new();

    REGISTER.call_once(|| {
        // SAFETY: The test-only C helper registers linker-owned, process-lifetime
        // sections without taking input or transferring ownership. Calling it
        // here ensures the C++ runtime has initialized; Once prevents repeats.
        // Keep sanitizer marker declarations outside instrumented LLVM modules:
        // the coverage pass creates globals with those same reserved names.
        unsafe {
            bfd_fuzz_initialize_coverage();
        }
    });
}
