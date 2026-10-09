# Contribute to BFD Windows service

This guide is for developers building, testing, and changing BFD Windows service.
It also explains how to prepare the files that systems administrators install.
Run the commands from the repository root.

For service installation and configuration, see
[Set up a BFD session](docs/setup.md).

## Before you begin

You need:

- 64-bit Windows 10 or later, or a corresponding Windows Server release, on an
  x64 processor.
- Rust installed through rustup. The repository's `rust-toolchain.toml` selects
  nightly Rust, `x86_64-pc-windows-msvc`, Clippy, rustfmt, and `rust-src`.
- Visual Studio's **Desktop development with C++** workload, including the Microsoft Visual C++ (MSVC) toolchain and Windows Software Development Kit (SDK).

## Build the executable

Build the executable and inspect its command-line help:

```powershell
cargo build --locked --release
.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe --help
```

A successful build creates
`target\x86_64-pc-windows-msvc\release\bfd-winservice.exe`. The help lists
`--console`, `--help`, and `--version`; session settings come from the registry.
Event Tracing for Windows (ETW) metadata and English messages are embedded during
the build using the SDK's `mc.exe` and `rc.exe`.

Use Developer PowerShell if the MSVC linker is unavailable on `PATH`. The build finds the manifest tools on `PATH` or in the installed Windows 10/11 SDK. For a custom SDK location, set `BFD_MC_PATH` and `BFD_RC_PATH` to the absolute tool paths.

## Build security

Windows builds support only `x86_64-pc-windows-msvc`. This is the default target;
the build rejects other Windows targets, including 32-bit x86 and ARM64.

Debug and release builds use these protections:

| Protection | Compiler or linker setting |
| --- | --- |
| Address space layout randomization (ASLR) | `/DYNAMICBASE` |
| High-entropy ASLR | `/HIGHENTROPYVA` and `/LARGEADDRESSAWARE` |
| Non-executable memory (NX/DEP) | `/NXCOMPAT` |
| Control Flow Guard (CFG) | `-C control-flow-guard=yes` and `/GUARD:CF` |
| Position-independent code | `-C relocation-model=pic` |
| Stack buffer protection, equivalent to `/GS` | `-Z stack-protector=all` |
| Exception handling (EH) continuation metadata | `-Z ehcont-guard=yes` and `/GUARD:EHCONT` |
| Control-flow Enforcement Technology (CET) shadow-stack compatibility | `/CETCOMPAT` |
| Integer overflow detection | `overflow-checks = true` |
| Immediate termination on panic | `panic = "abort"` in the release profile |
| Full debug information | `debug = 2`; release symbols aren't stripped |
| SHA-256 source checksums in debug information | `-Z src-hash-algorithm=sha256` |

The Rust [stack protector](https://doc.rust-lang.org/unstable-book/compiler-flags/stack-protector.html)
inserts stack cookies and checks them when functions return.
[`/GS`](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-170)
is an MSVC C/C++ compiler option, so Rust uses its compiler's stack protector
instead. The stack protector and EH continuation compiler options require
nightly Rust.

The [EH continuation metadata](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata?view=msvc-170)
lists valid exception continuation targets for Windows instruction-pointer
validation. Both the compiler and linker generate this data. The
[`/CETCOMPAT` setting](https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170)
marks the executable as compatible with CET shadow stacks. Runtime enforcement
depends on Windows, supported hardware, and the process mitigation policy.

The Cargo configuration rebuilds the Rust standard library from source, applying
CFG, stack protection, and EH continuation metadata to it, the service, and its
Rust dependencies. This requires the `rust-src` component and Cargo's
[`build-std` feature](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
Windows system DLLs retain their own build settings.

Keep the repository's compiler flags when building. The build rejects overrides
that remove CFG checks, change the relocation or stack protector strategy,
disable EH continuation metadata, or change source checksums from SHA-256.
Check the build and executable again after updating nightly Rust.

Structured Exception Handling Overwrite Protection (SEHOP) is a
[Windows process policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/override-mitigation-options-for-app-related-security-policies),
so it isn't a compiler or PE-header flag. On x64, Windows records exception
handlers in `.pdata` and `.xdata`, rather than the stack-based handler chain
that SEHOP validates.
[`/SAFESEH`](https://learn.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers?view=msvc-170)
applies to x86 builds only. The installation
procedure [enables SEHOP for the executable](docs/setup.md#enable-sehop-for-the-executable)
through Windows Exploit Protection.

To inspect the release executable, run this command in Developer PowerShell:

```powershell
dumpbin /headers /loadconfig `
    .\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe
```

Confirm that the output includes:

- Machine `8664 (x64)` and optional-header magic `20B (PE32+)`.
- `Application can handle large (>2GB) addresses`, `High Entropy Virtual Addresses`,
  `Dynamic base`, `NX compatible`, and `Control Flow Guard` in the image headers.
- `CF instrumented` and `FID table present` in the guard flags, with a nonzero
  Guard CF function count.
- A nonzero `Security Cookie` address.
- `EH Continuation table present`. A nonzero count must have a table address;
  an empty enabled table is valid when the image has no continuation targets.
- `CET compatible` in the extended DLL characteristics.
- A `bfd_winservice.pdb` file beside the executable.

The cookie address confirms the image's stack-cookie support. The required
compiler setting supplies the Rust function instrumentation; the address alone
doesn't establish that every function was instrumented.

The default test suite checks the debug executable's architecture, image flags,
relocations, CFG function table, security-cookie metadata, CET compatibility,
and sorted EH continuation targets. Test the code with release optimizations:

```powershell
cargo test-release
```

The `test-release` alias selects unwinding for the test graph so the rebuilt
standard library matches the test harness. The other release settings remain
enabled. Use this alias instead of `cargo test --release`.

After testing, build the production executable with `panic = "abort"` and
check that artifact with the executable regression:

```powershell
cargo build --locked --release
$env:BFD_HARDENING_EXE = (Resolve-Path `
    '.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe').Path
cargo test --locked --test windows_hardening
Remove-Item Env:\BFD_HARDENING_EXE
```

Confirm that the build and executable check pass. `BFD_HARDENING_EXE` selects
the image inspected by the test; removing the variable restores Cargo's default
test-image selection.

A release executable panic terminates the process immediately. It doesn't run
destructors, BGP cleanup, or the normal service-stop logging path. Normal
configuration and I/O errors still use `Result` and the existing cleanup paths.
The overflow setting checks ordinary integer arithmetic; intentional
`wrapping_*`, `saturating_*`, and `checked_*` operations retain their behavior.

### Compiler flags and lint policy

The service compiles Rust with `rustc` and links with MSVC. It has no C/C++
source compilation step. The following table maps the requested C++ compiler
settings to this build:

| C++ setting | Rust implementation or applicability |
| --- | --- |
| `/GS` | Rust stack protector on all functions. |
| `/guard:cf` | Rust CFG instrumentation and the MSVC `/GUARD:CF` linker setting. |
| `/sdl` | C/C++ only. Rust uses compile-time initialization and ownership checks, denied unsafe operations outside the FFI boundaries, stack protection, and strict Clippy checks. These aren't identical to MSVC SDL analysis. |
| `/analyze` | C/C++ only. Run strict Clippy and Miri for Rust static and dynamic checks. |
| `/ZH:SHA_256` | Rust uses SHA-256 source checksums. `/ZH:SHA_SHA256` isn't a valid MSVC spelling. |
| `/Zi` | Rust full debug information and the generated PDB. |

See Microsoft's
[`/sdl` reference](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks?view=msvc-170),
[`/analyze` reference](https://learn.microsoft.com/en-us/cpp/build/reference/analyze-code-analysis?view=msvc-170),
and [source-checksum options](https://learn.microsoft.com/en-us/cpp/build/reference/zh?view=msvc-170).

Cargo denies warnings, `unsafe_code`, `unsafe_op_in_unsafe_fn`,
`clippy::undocumented_unsafe_blocks`, and `clippy::unwrap_used`. Packet,
session, and stateless-reflector modules also forbid unsafe code. The registry,
ETW, Winsock, and native MI modules explicitly allow the unsafe code required
to call Windows APIs; the UTC-clock function has its own narrow exception.
A crate-wide `unsafe_code = "forbid"` would reject those required FFI calls.
Unsafe operations still need explicit blocks and safety explanations.

Unit and integration test fixtures allow `unwrap()` so invalid setup fails
immediately. Production code retains the denied lint. Full PDBs support
debugging and source matching; retain the executable and PDB from the same
build in your symbol archive. Source checksums aren't a binary signature.

### Run AddressSanitizer checks

AddressSanitizer (ASan) detects memory errors during testing. The repository's
`cargo asan` alias enables `-Z sanitizer=address`, preserves the Windows
hardening flags, rebuilds the standard library, and writes to `target/asan`.
Its dedicated profile uses unwinding for the test harness.

Use **x64 Developer PowerShell** with the MSVC AddressSanitizer component
installed. Verify that the runtime DLL is beside the selected compiler:

```powershell
$msvcBin = Split-Path (Get-Command cl.exe -CommandType Application).Source
Test-Path (Join-Path $msvcBin 'clang_rt.asan_dynamic-x86_64.dll')
```

Confirm the output is `True` and that this directory is on `PATH`. Then run
the sanitized tests:

```powershell
cargo asan
```

Confirm that all default tests pass without an ASan report. A missing ASan
runtime DLL prevents the test executables from starting. The installed nightly
must support `address` for `x86_64-pc-windows-msvc`; check target support
again after a toolchain update.

ASan is a [testing tool](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html#addresssanitizer).
Distribute the normal release executable. ASan tests don't instrument Windows
system DLLs or the prebuilt MSVC runtime.

## Prepare installation files

Give administrators these files from the same source revision:

- `bfd-winservice.exe`: the release executable.
- `BFD-Service.man`: the Event Log provider manifest.
- `Initialize-Logging.ps1`: the script that provisions logging defaults.

Copy them into a deployment folder:

```powershell
$deploymentDirectory = Join-Path $PWD 'target\deployment'
New-Item -ItemType Directory -Path $deploymentDirectory -Force
Copy-Item `
    -LiteralPath '.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe' `
    -Destination $deploymentDirectory
Copy-Item -LiteralPath '.\events\BFD-Service.man' `
    -Destination $deploymentDirectory
Copy-Item -LiteralPath '.\scripts\Initialize-Logging.ps1' `
    -Destination $deploymentDirectory
Get-ChildItem -LiteralPath $deploymentDirectory | Select-Object Name
```

PowerShell displays the deployment folder and these filenames:

```text
Name
----
BFD-Service.man
bfd-winservice.exe
Initialize-Logging.ps1
```

Deliver the folder's contents with the [setup guide](docs/setup.md).
Administrators don't need Rust, the MSVC toolchain, or the Windows SDK to
follow that guide.

## Run development checks

Run these checks before committing Rust changes:

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- `
    -D warnings -D clippy::undocumented_unsafe_blocks
cargo fmt --check
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --locked --no-deps
```

Confirm that the commands complete without errors. The documentation check also rejects undocumented public API elements.

Configuration validation and protocol modules are portable. Registry loading, User Datagram Protocol (UDP) transport, ETW, native Management Infrastructure (MI), and Windows Service Control Manager (SCM) integration require Windows. IPv4 time-to-live (TTL) metadata requires `IP_RECVTTL` support.

Native tests use temporary `HKEY_CURRENT_USER` (HKCU) registry keys, local MI fixtures, and loopback UDP sockets. They do not change installed service settings or Border Gateway Protocol (BGP) peers. The read-only Common Information Model (CIM) schema test requires namespace access and is opt-in. Run it separately:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

The default suite reports this schema test as ignored. Install Miri for the
repository's nightly toolchain, then check portable logic:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
rustup component add miri
cargo +nightly miri test --locked --lib -- --test-threads=1
```

Miri checks the portable logic and synthetic ancillary-data parser. Native Winsock, MI, registry, ETW, and subprocess tests are excluded. To check the parser with both strict provenance and tree borrows, run:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance -Zmiri-tree-borrows'
cargo +nightly miri test --locked --lib ancillary_metadata
```

To check S-BFD state, reflection, timers, and authentication under Miri, run:

```powershell
cargo +nightly miri test --locked --test seamless
```

Native S-BFD tests additionally check IPv4/IPv6 sockets, source-port reflection,
return-route lookup, concurrent initiators, anycast response sources, and the
maintenance retry minimum. They use loopback endpoints and don't establish
interoperability with external router implementations.

Validate SCM lifecycle, Event Viewer delivery, and actual BGP Start/Stop on the target server using the [setup guide](docs/setup.md) and [BGP guide](docs/bgp.md). For BGP testing, cover initially stopped and running peers, then disconnect and restore Bidirectional Forwarding Detection (BFD) while watching the logs and BGP state.

See the [validation guide](RUST_SKILLS_VALIDATION.md) and
[code review](CODE_REVIEW.md) for recorded results and test limits.

## Submit a change

Before submitting a change:

1. Update the tests when protocol behavior or validation changes.
2. Update the administrator guides when registry values, service behavior, or
   logging changes. Keep build and test instructions in this file.
3. Run the applicable checks in [Run development checks](#run-development-checks).
4. Describe the resulting behavior, checks performed, and any validation limits
   in your change description.
