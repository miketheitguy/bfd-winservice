/* Test-only late registration of MSVC sanitizer coverage sections. */
#include <stdint.h>

/* Compiler-rt supplies 64-bit start/end sentinels in ordered A/Z subsections.
 * LLVM places counters and PC pairs in the intervening M subsections.
 * Declare these only in this uninstrumented translation unit: LLVM's coverage
 * pass creates globals with the same names in instrumented modules. */
extern uint64_t __start___sancov_cntrs;
extern uint64_t __stop___sancov_cntrs;
extern uint64_t __start___sancov_pcs;
extern uint64_t __stop___sancov_pcs;

extern void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);
extern void __sanitizer_cov_pcs_init(const uintptr_t *start, const uintptr_t *stop);

void bfd_fuzz_initialize_coverage(void)
{
    /* Skip the start sentinels, matching LLVM's COFF section registration.
     * These linker-owned ranges live for the process lifetime. No allocation,
     * packet data, or ownership crosses this boundary. Rust calls it once,
     * after the C++ runtime has initialized. */
    __sanitizer_cov_8bit_counters_init(
        (uint8_t *)(&__start___sancov_cntrs + 1),
        (uint8_t *)&__stop___sancov_cntrs);
    __sanitizer_cov_pcs_init(
        (const uintptr_t *)(&__start___sancov_pcs + 1),
        (const uintptr_t *)&__stop___sancov_pcs);
}
