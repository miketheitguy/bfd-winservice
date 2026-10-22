# Build hardening and native safety

Cowabunga, build crew. Check the actual artifact protections. Developers and
release maintainers, let's check the hardening receipts. This reference explains
the Rust, MSVC, and native RPC protections applied to both executables, their
limits, and how to verify emitted artifacts. For service identities and access
controls, see the [security overview](../security.md).

On this page:

- [Rust compiler options](#rust-compiler-options)
- [MSVC linker options](#msvc-linker-options)
- [Diagnostics, lint policy, and security limits](#diagnostics-lint-policy-and-security-limits)
- [Native RPC compiler options](#native-rpc-compiler-options)
- [Native C exception policy](#native-c-exception-policy)
- [Test-profile differences](#test-profile-differences)
- [Verification](#verification)

The settings in [Cargo.toml](../../Cargo.toml) and
[.cargo/config.toml](../../.cargo/config.toml) apply to both executables. The
build targets `x86_64-pc-windows-msvc` and rejects other Windows architectures.
[rust-toolchain.toml](../../rust-toolchain.toml) pins the nightly compiler and
includes `rust-src` for rebuilding the standard library.

Compiler instrumentation and executable metadata make certain attacks harder or
terminate the process when checks fail. They do not replace authentication,
ACLs, or correct handling of untrusted packets. Gnarly inputs still need
validation, dude.

## Rust compiler options

Get the Rust side ready to kick shell against invalid behavior. Here's the
compiler and Cargo protection lineup, buddy:

| Setting | Security benefit and scope |
| --- | --- |
| `-C control-flow-guard=yes` | Inserts checks on indirect calls and emits valid-call-target metadata. Together with `/GUARD:CF`, lets Windows reject invalid call targets caused by corrupted function pointers. See [Rust CFG options](https://doc.rust-lang.org/rustc/codegen-options/index.html#control-flow-guard). |
| `-C relocation-model=pic` | Generates position-independent code suitable for relocation, supporting randomized load addresses. ASLR also needs linker metadata and Windows support. See [Rust relocation models](https://doc.rust-lang.org/rustc/codegen-options/index.html#relocation-model). |
| `-Z stack-protector=all` | Requests stack canaries in all functions and checks them on return to detect stack corruption. This is Rust's compiler instrumentation; MSVC's `/GS` is a C/C++ compiler option. Canaries detect some corruption, not every memory error. See [Rust stack protector](https://doc.rust-lang.org/unstable-book/compiler-flags/stack-protector.html). |
| `-Z ehcont-guard=yes` | Emits valid exception continuation targets for the linker. With `/GUARD:EHCONT`, supports Windows validation of resumed instruction pointers. See [EH continuation metadata](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata?view=msvc-170). |
| `overflow-checks = true` in development and release | Makes overflowing ordinary integer arithmetic panic instead of silently wrapping. Explicit `wrapping_*`, `saturating_*`, and `checked_*` operations retain their intended behavior. See [Cargo overflow checks](https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks). |
| `panic = "abort"` in production release | Immediately terminates on a panic rather than unwinding through the process. Destructors, BGP cleanup, and normal service-stop logging do not run on this path. Normal handled errors still use `Result` and cleanup. See [Cargo panic strategy](https://doc.rust-lang.org/cargo/reference/profiles.html#panic). |

`stack-protector` and `ehcont-guard` use nightly Rust. Cargo's
[`build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
configuration rebuilds `std` and `panic_unwind` with target flags, extending
instrumentation to the service, its Rust dependencies, and the target standard
library. Windows system DLLs retain their own build settings. The explicit
target keeps host build scripts and procedural macros on default host settings.

## MSVC linker options

Give the linker settings the Donatello treatment, dude. Rust passes these
options through `-C link-arg=...` to the MSVC linker:

| Option | Security benefit and scope |
| --- | --- |
| `/MACHINE:X64` | Selects the supported 64-bit executable architecture. This enables the x64 mitigation configuration; architecture selection alone is not an access control. |
| [`/DYNAMICBASE`](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170) | Marks the image for address space layout randomization (ASLR), making useful code/data locations less predictable. |
| [`/HIGHENTROPYVA`](https://learn.microsoft.com/en-us/cpp/build/reference/highentropyva?view=msvc-170) | Enables high-entropy 64-bit ASLR, increasing the address space available for randomization. Requires `/DYNAMICBASE` and `/LARGEADDRESSAWARE`. |
| [`/LARGEADDRESSAWARE`](https://learn.microsoft.com/en-us/cpp/build/reference/largeaddressaware-handle-large-addresses?view=msvc-170) | Lets the image use addresses above 2 GB and supports high-entropy ASLR. It is not a memory-safety check. |
| [`/NXCOMPAT`](https://learn.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention?view=msvc-170) | Declares compatibility with Data Execution Prevention (DEP/NX), which prevents execution from pages marked as data. Does not prevent corruption or reuse of existing executable code. |
| [`/GUARD:CF`](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks?view=msvc-170) | Includes CFG image flags and valid-call-target tables. Works with Rust's CFG instrumentation; the linker switch alone does not add call-site checks. |
| [`/GUARD:EHCONT`](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata?view=msvc-170) | Links EH continuation metadata for Windows instruction-pointer validation during context restoration. An enabled empty table is valid when the image has no continuation targets. |
| [`/CETCOMPAT`](https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170) | Marks compatibility with Control-flow Enforcement Technology (CET) shadow stacks, which protect return addresses against return-oriented attacks. Actual enforcement requires suitable hardware, Windows support, and process mitigation policy. |

## Diagnostics, lint policy, and security limits

Bodacious diagnostic settings still have a defined scope. AddressSanitizer
(ASan) adds runtime memory-error detection to test builds, and strict lints make
their configured violations fail the relevant checks. These settings control the
diagnostic vibe check and code checks:

| Setting | Benefit and limitation |
| --- | --- |
| Release `opt-level = 3` | Optimizes runtime code. Optimization is not an authentication or memory-safety mechanism. |
| Development `debug = 2`; ASan inherits development | Retains full debugging information and PDBs to investigate failures. AddressSanitizer is test instrumentation for detecting memory errors, not a production authorization check. |
| Release `debug = 0`, `strip = "symbols"`, and `/DEBUG:NONE` | Omits debug information/symbols and suppresses MSVC PDB generation, reducing distributed diagnostic metadata. Release crash dumps lack matching PDBs for source-level debugging. These settings do not make code secret or verify executable integrity. |
| `-Z src-hash-algorithm=sha256` | Uses SHA-256 source checksums when debug information is emitted, helping debuggers match source files. These are not an executable signature or runtime authentication. |
| `warnings`, `unsafe_code`, `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks`, and `clippy::unwrap_used` set to `deny` | Makes warnings, unapproved unsafe code, implicit unsafe operations, undocumented unsafe blocks, and production `unwrap()` calls fail the relevant checks. Narrow Windows API boundaries explicitly allow required unsafe code and still require safety explanations. |

Cargo's [profile
reference](https://doc.rust-lang.org/cargo/reference/profiles.html) describes
optimization and debug settings. Rust ownership, initialization, and bounds
checks protect safe Rust code; Windows API calls still depend on correctly
reviewed unsafe boundaries. The build also compiles native C for local RPC;
those files have a separate compiler configuration.

## Native RPC compiler options

The native bridge needs its own ninja training. Native code needs its own
guardrails, no cap. Native stack-buffer, control-flow, and additional compiler
checks complement the Rust settings. The native build has its own compiler
configuration.

[rpc/build.rs](../../rpc/build.rs) runs the Windows SDK MIDL compiler with
`/env x64 /robust /Oicf /app_config`. It generates separate client and server
stubs; the client ACF selects asynchronous calls. MSVC `cl.exe` compiles both
generated stubs and `rpc/client.c`, `rpc/server.c`, `rpc/bgp_server.c`, and
`rpc/allocator.c` with
`/TC /MD /GS /guard:cf /guard:ehcont /sdl /W4 /WX /D_WIN32_WINNT=0x0602`.
`lib.exe` combines the objects into `bfd_local_rpc.lib`, which links with
`Rpcrt4` into the Rust executables.

Every native translation unit is C, explicitly selected by `/TC`. The compiler
process ignores ambient `CL`/`_CL_` options so they cannot override the language
or hardening flags. `/EHsc` applies to C++ exception unwinding and is
unnecessary for these C SEH handlers. Future C++ requires a separate `/TP /EHsc`
policy and an exception boundary that prevents C++ unwinding through Rust.
`/EHa` recovery is not part of this policy. See [Microsoft's exception-handling
model](https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model?view=msvc-170).

`/GS` provides native stack-buffer checks, `/guard:cf` and `/guard:ehcont`
provide native control-flow metadata, and `/sdl` enables additional MSVC
security checks. `/W4` selects warnings and `/WX` treats them as errors.
Handwritten C also uses `/analyze /analyze:external-`, with analysis warnings
treated as errors. Generated MIDL translation units retain compiler warnings and
robust NDR checks. These C compiler options are separate from the Rust flags.
See Microsoft's [MSVC security
checks](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks?view=msvc-170).

Ordinary native builds omit `/Zi` and AddressSanitizer. When the Rust target
enables address sanitization, the native build adds `/fsanitize=address /Zi`
to maintained C files and generated MIDL stubs. `scripts/Test-Asan.ps1` verifies
the active Cargo build configuration and emitted native ASan hooks before
running the sanitized tests. Native stubs and wrappers remain outside safe
Rust's guarantees.

## Native C exception policy

Turtle power includes knowing which faults remain fatal. Both RPC clients use
`RpcTryExcept` with a shared wrapper around Microsoft's `RpcExceptionFilter`.
Recoverable RPC exceptions become error codes inside C. Hold up: documented
fatal classes, including access violations, stack overflow, and stack buffer
overrun, continue outside that handler. The bridge never resumes execution after
those faults or installs catch-all SEH around Rust server managers. The
generated NDR stubs and RPC runtime own server-side marshaling exceptions. See
[Microsoft's exception filter](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcexceptionfilter).

The Rust/native FFI boundary forbids cross-language unwinding in both
directions. The Rust callbacks use non-unwinding `extern "C"`/`extern "system"`
ABIs, and production panics abort the process. No `C-unwind` or `system-unwind`
boundary is used. A future C++ dependency must catch all C++ exceptions in its
C++ wrapper and convert them to integer error statuses before returning to Rust;
`/EHsc` and `noexcept` alone do not provide that conversion. Any recoverable
Rust panic must be caught entirely on the Rust side. Neither the RPC SEH filter
nor native code is a Rust panic handler. See [Rust's FFI unwinding
rules](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding).

Asynchronous state, events, bindings, and output storage stay live through
native completion, including cancellation. MIDL allocation callbacks inherit the
SDK's SAL allocation contracts. All native C compiles with `/W4 /WX`;
handwritten C also passes MSVC `/analyze`. The [native SEH
regression](../../src/local_rpc/tests/seh.rs) raises recoverable exceptions
entirely inside C and checks the fatal filter without raising fatal faults.
Static analysis and these tests supplement native ownership review. Native
ASan coverage comes from the explicit MSVC compiler option; Rust's sanitizer
option alone does not instrument separately compiled C.

## Test-profile differences

Keep the test and production settings straight, turtle crew. The `test-release`
alias overrides panic handling to `unwind` for the test graph. It tests release
optimizations but does not reproduce production's abort strategy. The `asan`
alias adds sanitizer instrumentation to tests, including the rebuilt standard
library, and retains the other target hardening settings.
The native build follows the target's sanitizer setting. CI runs this graph in
the separate `asan` job and uploads diagnostic logs only. Release publication
requires successful `asan`, `fuzz`, and `build-msi` jobs for the same source
revision.
The production MSI always uses the ordinary release graph from `build-msi`.

Cargo's nightly `profile-rustflags` feature adds release-only `/DEBUG:NONE`
alongside the shared target flags, preserving development and ASan debug output.

The fuzz harness uses a separate optimized development graph with ASan and
coverage instrumentation. Its wrapper uses a prebuilt standard library and omits
Rust EH-continuation instrumentation and the final `/GUARD:EHCONT` link flag.
For the target boundaries, C++ engine settings, coverage-registration lifetime,
and validation limits, see the [fuzz harness security reference](fuzzing.md).

## Verification

Pizza time follows artifact inspection and recorded checks. Cowabunga comes
after the build receipts, for sure. Recorded reviews link successful checks to
their revisions. Executable tests inspect what the build emits.

[tests/windows_hardening.rs](../../tests/windows_hardening.rs) checks both
executable images for architecture, relocations, ASLR/NX/CFG flags, CFG tables,
security-cookie metadata, EH continuation data, CET compatibility, and
profile-specific debug output. These checks verify emitted metadata. A
normal release image must also import no ASan runtime. A
security-cookie address alone does not prove every function has stack-protector
instrumentation, and a CET flag does not prove that the host enforces shadow
stacks.

### Check the production executable

Run from the repository root on the [Windows build host](../../CONTRIBUTING.md#before-you-begin).
Compile the release test harness first, then rebuild the production executables:

```powershell
$hardeningTests = @(
    cargo test-release --no-run --test windows_hardening --message-format=json |
        ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object {
            $_.reason -eq 'compiler-artifact' -and
            $_.target.name -eq 'windows_hardening' -and $_.executable
        } |
        Select-Object -ExpandProperty executable
)
if ($LASTEXITCODE -ne 0 -or $hardeningTests.Count -ne 1) {
    throw 'Expected one compiled release hardening test executable'
}
cargo build --locked --release
if ($LASTEXITCODE -ne 0) { throw 'Production build failed' }
$previousImage = $env:BFD_HARDENING_EXE
try {
    $env:BFD_HARDENING_EXE = (Resolve-Path `
        'target/x86_64-pc-windows-msvc/release/bfd-winservice.exe').Path
    & $hardeningTests[0]
    if ($LASTEXITCODE -ne 0) { throw 'Production hardening check failed' }
} finally {
    $env:BFD_HARDENING_EXE = $previousImage
}
```

Expect zero failures. The release harness applies release expectations, including
the absence of PDBs, to both production images. Running the debug harness against
a release image instead applies incompatible debug-output expectations.
`BFD_HARDENING_EXE` chooses the BFD image; the test also inspects its adjacent
broker executable. The `finally` block restores your previous image selection.

### Inspect compiler output

In Developer PowerShell, inspect the emitted metadata:

```powershell
dumpbin /headers /loadconfig `
    .\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe
```

Confirm x64/PE32+, high-entropy ASLR, dynamic base, NX, CFG instrumentation and
function table, a security-cookie address, EH continuation metadata, and CET
compatibility. A nonempty EH continuation table needs an address; an enabled
empty table is valid when the image has no continuation targets. Release images
omit PDBs; development images retain them. These are metadata checks, subject to
the limits described at the start of [Verification](#verification).

Recheck after changing the toolchain, profiles, or compiler/linker overrides.
For optimized tests and native/Rust ASan setup, use
[development validation](../development/validation.md).
