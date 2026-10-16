# Contribute to BFD Windows service

This guide is for developers building, testing, and changing BFD Windows service.
It also explains how to prepare the files that systems administrators install.
Run the commands from the repository root.

For service installation and configuration, see
[Set up a BFD session](docs/setup.md).

## Before you begin

You need:

- 64-bit Windows 10 or later, or Windows Server 2016 or later, on an
  x64 processor.
- Rust installed through rustup. The repository's `rust-toolchain.toml` pins a
  dated nightly Rust, `x86_64-pc-windows-msvc`, Clippy, rustfmt, and `rust-src`,
  so every build and release uses the same compiler. Update the date deliberately
  and rerun the full test, ASan, and hardening checks when you do.
- Visual Studio's **Desktop development with C++** workload, including the Microsoft Visual C++ (MSVC) toolchain and Windows Software Development Kit (SDK).

The Windows local RPC interface also needs the SDK's MIDL compiler (`midl.exe`)
and the x64 MSVC compiler and librarian (`cl.exe` and `lib.exe`). The build
generates RPC stubs from the interface definition and compiles a small native
wrapper that contains Windows RPC exceptions. Service logic and authentication
remain in Rust.

Before you ship, bring receipts: record the checks you ran and the deployment
behavior that still needs a provisioned Windows Server.

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
the build using the SDK's `mc.exe` and `rc.exe`. Windows file properties also
contain file and product versions generated from `Cargo.toml`.

The build finds `midl.exe`, `mc.exe`, and `rc.exe` on `PATH` or in the installed
Windows 10/11 SDK. It discovers the x64 MSVC environment through Visual Studio
environment variables or `vswhere.exe`, then loads `vcvars64.bat` for the native
RPC build. For custom installations, set `BFD_MIDL_PATH`, `BFD_MC_PATH`, and
`BFD_RC_PATH` to the corresponding absolute tool paths, and
`BFD_VCVARS64_PATH` to the absolute path of `vcvars64.bat`.

## Build security

For the runtime authentication boundaries, diagrams, and the security benefits
of each build option, see [Security, authentication, and build hardening](docs/security.md).

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
| Full Rust debug information for development and ASan | `debug = 2` in the development profile; ASan inherits it |
| Release builds without debug information or symbols | `debug = 0`, `strip = "symbols"`, and release-only `/DEBUG:NONE` |
| SHA-256 source checksums when debug information is enabled | `-Z src-hash-algorithm=sha256` |

The `dev` and `release` profiles in [Cargo.toml](Cargo.toml) set overflow checks,
debug information, and the release panic strategy. Target-specific `rustflags`
in [.cargo/config.toml](.cargo/config.toml) select compiler protections and pass
MSVC linker switches through `-C link-arg=...`. This single list applies across
profiles. The explicit build target keeps these flags out of host build scripts
and procedural macros, which use Rust's prebuilt host standard library.
The build script embeds ETW and executable version resources and checks the
supported Windows target.

The Rust [stack protector](https://doc.rust-lang.org/unstable-book/compiler-flags/stack-protector.html)
inserts stack cookies and checks them when functions return.
[`/GS`](https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-170)
is an MSVC C/C++ compiler option, so Rust uses its compiler's stack protector
instead. The stack protector and EH continuation compiler options require
nightly Rust.

The release-only `rustflags` profile in `.cargo/config.toml` adds `/DEBUG:NONE`
to suppress MSVC PDB generation. It uses Cargo's nightly
[`profile-rustflags` feature](https://doc.rust-lang.org/cargo/reference/unstable.html#profile-rustflags)
alongside the target hardening flags. Development and ASan retain debug output.

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

Keep the Cargo profiles and target configuration when building. Profile or
compiler-flag overrides can change the resulting protections. Verify compiler
output and run the executable hardening regression after changing profiles,
target flags, or nightly Rust; PE header checks alone do not prove stack protector
instrumentation.

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
- A `bfd_winservice.pdb` file beside the executable for development builds.
  Release builds do not generate PDBs for either service.

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

The build compiles service logic with `rustc`, generates robust x64 RPC stubs
with MIDL, and compiles those stubs plus `rpc/client.c`, `rpc/server.c`, and
`rpc/allocator.c` with MSVC `cl.exe`. The native bridge contains Windows RPC
exceptions before returning to Rust. [The native build](rpc/build.rs) uses
`/MD`, `/GS`, `/guard:cf`, `/guard:ehcont`, `/sdl`, and `/W4`; `lib.exe` packages
the objects, and MSVC links them into the executables.

The following table distinguishes Rust settings from native C settings:

| Compiler setting | Rust and native C implementation |
| --- | --- |
| `/GS` | Native C uses `/GS`; Rust uses `-Z stack-protector=all`. |
| `/guard:cf` | Native C and Rust both receive CFG instrumentation; the linker uses `/GUARD:CF`. |
| `/guard:ehcont` | Native C uses `/guard:ehcont`; Rust uses `-Z ehcont-guard=yes`; the linker uses `/GUARD:EHCONT`. |
| `/sdl` | Enabled for native C. Rust uses ownership and initialization checks, restricted unsafe boundaries, stack protection, and strict Clippy; these checks aren't identical to MSVC SDL analysis. |
| `/analyze` | The native build does not enable MSVC static analysis. Use Clippy and Miri for the applicable Rust checks. |
| `/ZH:SHA_256` | Rust uses SHA-256 source checksums. The native build does not enable this option. `/ZH:SHA_SHA256` isn't a valid MSVC spelling. |
| `/Zi` | Rust emits full debug information in development and ASan builds. Native C does not receive `/Zi`; release builds disable Rust symbols and linker PDB output. |

See Microsoft's
[`/sdl` reference](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks?view=msvc-170),
[`/analyze` reference](https://learn.microsoft.com/en-us/cpp/build/reference/analyze-code-analysis?view=msvc-170),
and [source-checksum options](https://learn.microsoft.com/en-us/cpp/build/reference/zh?view=msvc-170).

Cargo denies warnings, `unsafe_code`, `unsafe_op_in_unsafe_fn`,
`clippy::undocumented_unsafe_blocks`, and `clippy::unwrap_used`. Packet,
session, and stateless-reflector modules also forbid unsafe code. Windows FFI
modules, including registry, ETW, Winsock, service identity, local RPC, BGP pipe,
COM, and native MI code, explicitly allow the unsafe code required to call
Windows APIs; the UTC-clock function has its own narrow exception.
A crate-wide `unsafe_code = "forbid"` would reject those required FFI calls.
Unsafe operations still need explicit blocks and safety explanations.

Unit and integration test fixtures allow `unwrap()` so invalid setup fails
immediately. Production code retains the denied lint. Development and ASan
PDBs support debugging and source matching. Release builds omit symbols, so
release crash dumps do not have matching PDBs for source-level debugging.
Source checksums aren't a binary signature.

### Run AddressSanitizer checks

AddressSanitizer (ASan) detects memory errors during testing. The repository's
`cargo asan` alias enables `-Z sanitizer=address`, preserves the Windows
hardening flags, rebuilds the standard library, and writes to `target/asan`.
It also passes the sanitizer flag to `rustdoc` for documentation tests.
Its dedicated profile uses unwinding for the test harness.

The sanitizer is enabled only by this alias. Rust documents ASan for testing
and fuzzing because its instrumentation adds runtime overhead. Cargo uses
target `rustflags` before `[build].rustflags`, so placing the sanitizer in the
build table would be ignored while the Windows target flags are configured.
The alias's `--config` arrays append the sanitizer flags to the target settings.
See [Cargo compiler flag precedence](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags).

The `[unstable]` table already sets `build-std = ["std", "panic_unwind"]`.
This enables Cargo's `-Z build-std=std,panic_unwind` for every invocation and
rebuilds the standard library with ASan during sanitized tests. The repository
also sets the explicit Windows target and installs `rust-src` through
`rust-toolchain.toml`. Rebuilding the standard library extends ASan coverage to
its Rust code; ASan can work with an uninstrumented standard library, but that
reduces coverage. See [Cargo's build-std configuration](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).

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
system DLLs, the prebuilt MSVC runtime, or the native RPC C objects. The native
build does not pass MSVC's `/fsanitize=address` option.

## Use the Rust configuration and error APIs

`Options` contains mutable provisioning input. Call `Options::into_validated()`
to produce an immutable `ValidatedOptions` snapshot. On Windows,
`config::load_registry()` returns this snapshot directly. Clones share its
storage, and `ProtocolRole` carries the required nonzero initiator or reflector
discriminator.

Use `Engine::from_config`, `Session::from_config`, `Reflector::from_config`, and
`Transport::from_config` to reuse a snapshot without repeating validation.
The constructors that accept raw `Options` still validate before use.
Live S-BFD timers and maintenance state are separate from startup settings.

`Session::set_timing` rejects overlapping transmitted Poll changes with
`ConfigError::PollInProgress`. Wait for the Final and a subsequent non-Final
response before another wire timer change. An Up TX increase is advertised in
the Poll but takes effect only after its Final. See the
[S-BFD timing reference](docs/seamless.md#change-timing-and-entity-availability).

`Session::packet` and `packet_at` are convenience APIs that reserve a sequence
and register a transmission when they return bytes. Library callers using these
APIs must deliver the returned packets. The Windows runtime prepares packets
without mutation and commits sequence, Poll, and probe tracking only after a
successful socket send; failed sends don't consume meticulous sequences.

The runtime encodes packets into fixed 52-byte storage, reuses its receive
buffer, and verifies keyed authentication without copying the packet or
allocating a digest. The public packet convenience APIs still return owned
vectors. Use `Transport::receive_into` with a retained `Datagram` to reuse
receive storage in library code.

Use `Engine::run_until` with a cloneable `runtime::StopSignal` to wait for socket
events, protocol deadlines, and shutdown. Service control and console handlers
call `StopSignal::signal` to wake the engine immediately. `Engine::run` remains
available for callers with a channel receiver; it checks that channel every
10 milliseconds while idle.

Configuration errors use `error::ConfigError`. Packet and transport rejection
uses `error::PacketError`; authentication uses `error::AuthError`.
`session::ReceiveError` distinguishes packet and authentication failures. Match
these enums rather than comparing their display strings. Error messages omit
keys and packet contents.

`Session::remote_state()` and `remote_diagnostic()` expose the last accepted
peer report, including reserved diagnostic values. They update only after
packet and authentication validation. Peer diagnostics don't replace LocalDiag.
The runtime tracks one peer report per discriminator and communication period
to suppress repeated state and diagnostic events. See the
[Operational event reference](docs/logging.md#operational-events).

`Logger::new` returns `io::Result<Logger>`. Logger clones share one bounded output
worker. `Logger::flush(timeout)` provides explicit completion when a caller needs
to read the output immediately, and `Logger::dropped_records()` reports queue
loss. Do not call `flush` from the protocol timer loop. See
[log destinations and queue limits](docs/logging.md#log-destinations).

## Initialize broker management security

The BFD service sends fixed-target BGP requests through the authenticated local
pipe. See [Security, authentication, and build hardening](docs/security.md)
for caller and server identity checks, and [Monitor service status and BFD
events](docs/monitoring.md) for lifecycle queries and event-log monitoring.

`src/bgp_broker/com.rs` is private to the broker. Its dedicated MTA thread
initializes explicit process security before native MI starts and remains alive
until provider work finishes. Incoming COM access is local-only and grants only
SYSTEM. Normal shutdown, startup errors, and unwinding join
the owner thread, which calls `CoUninitialize`.

The Rust suite isolates process-wide COM security tests in child processes. It
checks duplicate initialization and rejects preexisting security defaults. The
release workflow also runs a read-only native MI schema query under this policy
to check compatibility with Windows management providers. In-process state
observers remain available to library users and UDP integration tests.

## Maintain the private local RPC interface

`src/local_rpc.rs` hosts the private BFD interface. Its `GetSessionStatusV1`
operation copies one published snapshot on an RPC worker. The broker queries it
from one supervised worker inside its existing process; it launches no helper.
Keep this path separate from the BGP control pipe and COM/MI provider worker.

Preserve the conditional server identity policy, exact caller account and
service SID checks, Identify credentials, packet privacy, and management denial.
The provider process keeps its existing token and COM/MI policy. Never vary the
BFD identity policy or treat a unique binding as an authorization-cache reset.

The record uses only fixed-width integers across FFI. Native robust stubs apply
IDL ranges; `src/local_rpc/status.rs` converts into Rust types once. There is no
validation dependency. Invalid data clears the cache and retries with capped
backoff, as do connection failures; only a stuck native worker quarantines
telemetry. These paths do not change BGP state. Keep packet-loop
publication independent of query count and retain pending native storage until
completion. A stuck worker must not block provider work or service shutdown.

See [RPC session-status query](docs/rpc-session-status-design.md),
[RPC authentication](docs/rpc-authentication.md), and
[Service communication](docs/service-communication.md).

Run native RPC tests on a Windows host with a normal token:

```powershell
cargo test-release --lib local_rpc::
cargo test-release --lib native_provider_traffic -- --ignored
```

The second command exercises real read-only CIM schema traffic in the same
process as RPC, including replacement-server rejection and recovery. Fixture
processes isolate test registrations and identities; they are not the production
architecture. `scripts/Test-MsiInstall.ps1` separately checks a successful
authenticated status fetch after installed first start and repair.

## Update the security diagrams

The [draw.io source](docs/service-communication.drawio) has three editable pages:
runtime boundaries, service lifecycle, and RPC authentication. Keep its exports
and [communication guide](docs/service-communication.md) synchronized with the
implementation. The [RPC reference](docs/rpc-authentication.md) supplies the
detailed authentication mechanisms and Microsoft references.

With draw.io Desktop installed in its default Windows location, export from the
repository root:

```powershell
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 1 -b 20 `
    -o docs/images/service-communication-runtime.png `
    docs/service-communication.drawio
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 2 -b 20 `
    -o docs/images/service-communication-lifecycle.png `
    docs/service-communication.drawio
& 'C:\Program Files\draw.io\draw.io.exe' -x -f png -e -p 3 -b 20 `
    -o docs/images/service-communication-authentication.png `
    docs/service-communication.drawio
```

The page numbers are one-based. `-e` embeds editable XML in each PNG; retain the
canonical `.drawio` source as well. Add `--disable-gpu` if export fails during GPU
initialization. If you installed draw.io elsewhere, substitute its actual path.

Open all three images and check text, clipping, arrow direction, process
boundaries, and identity labels. Keep the RPC worker inside the broker
process. Show the snapshot and typed status path, and preserve the
existing BGP pipe and COM/MI provider path. Ensure every diagram has a matching
text explanation and useful alt text in the consuming Markdown page.

## Prepare installation files

Give administrators these files from the same source revision:

- `bfd-winservice.exe`: the release executable.
- `bfd-bgp-broker.exe`: the privileged BGP broker, installed by the MSI.
- `BFD-Service.man`: the Event Log provider manifest.
- `Initialize-Logging.ps1`: the script that provisions logging defaults.

Copy them into a deployment folder:

```powershell
$deploymentDirectory = Join-Path $PWD 'target\deployment'
New-Item -ItemType Directory -Path $deploymentDirectory -Force
Copy-Item `
    -LiteralPath '.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe' `
    -Destination $deploymentDirectory
Copy-Item `
    -LiteralPath '.\target\x86_64-pc-windows-msvc\release\bfd-bgp-broker.exe' `
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
bfd-bgp-broker.exe
bfd-winservice.exe
Initialize-Logging.ps1
```

Deliver the folder's contents with the [setup guide](docs/setup.md).
Administrators don't need Rust, the MSVC toolchain, or the Windows SDK to
follow that guide.

Loose files support console execution. Use the MSI for SCM execution: it
provisions the LocalService BFD process, Automatic (Delayed Start) LocalSystem broker, enabled
service SIDs, service dependency, and scoped registry/file/log ACLs. Native MI
code is confined to `src/bgp_broker/mi.rs`; the BFD worker uses `src/bgp/ipc.rs`.
Broker operations accept only fixed Get/Start/Stop frames and load their target
from protected configuration. Protocol, authorization, reconnect, disconnect
cleanup, and overlapped-I/O cancellation tests use temporary pipes and fake
provider operations, with no service installation or BGP changes.

## Build an MSI

Install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
or a later SDK. WiX 7 requires explicit acceptance of its
[Open Source Maintenance Fee EULA](https://docs.firegiant.com/wix/osmf/).
Review the terms and any applicable maintenance fee before accepting them.
The build script accepts the EULA by default. To build an MSI, run from the
repository root:

```powershell
.\scripts\Build-Msi.ps1
```

The script builds both hardened x64 production executables with Cargo's locked
dependencies, restores WiX and its extensions, compiles the MSI, validates its
tables (including per-machine scope and required administrator privileges), and
writes a SHA-256 checksum. Successful output ends with the MSI path.
For a local build, the package version comes from `Cargo.toml` and must contain
three numeric fields within Windows Installer's `255.255.65535` version limits.
To reproduce a tagged release locally, stamp its version before building:

```powershell
.\scripts\Set-ReleaseVersion.ps1 -Tag 'v1.2.0'
.\scripts\Build-Msi.ps1
```

The stamping script updates only the `bfd-winservice` version in `Cargo.toml`
and `Cargo.lock`; dependency versions remain locked. It rejects malformed tags,
prerelease or build metadata, leading zeros, and versions beyond MSI limits.
Before packaging, the script checks the executable's `--version` output and
Windows file and product versions against the Cargo version. It also checks the
MSI's `ProductVersion` and packaged executable version. `-SkipBuild` rejects an
executable from another version; rebuild it before packaging.

Both executables use the same Cargo version and receive separate filename and
description resources. Tagged Actions builds stamp both from the GitHub tag.

Output files appear in `target\installer`:

| File | Purpose |
| --- | --- |
| `BfdWinService-VERSION-x64.msi` | Installer with embedded payload cabinet |
| `BfdWinService-VERSION-x64.msi.sha256` | SHA-256 checksum of that MSI |

`VERSION` is the build's package version, such as `1.2.0`. Release builds
disable Rust PDBs for both services and WiX symbols with `-pdbtype none`.
Use `-SkipBuild` when changing installer authoring after already building the
matching production executable. The normal command always rebuilds the executable.

The script's `AcceptWixEula` switch defaults to true and passes
`-acceptEula wix7` to extension restore and package build commands. Explicit
`-AcceptWixEula` calls continue to work. Acceptance applies to these commands
without recording per-user acceptance.

The [.NET tool manifest](.config/dotnet-tools.json) pins WiX `7.0.0`; the script
restores `WixToolset.Util.wixext` and `WixToolset.Firewall.wixext` at the same
version into the ignored `.wix` cache and loads those exact versions for the
build. Administrators don't need .NET or WiX
to install the resulting MSI. The package is unsigned; signing isn't configured
in this workflow.

The [package definition](installer/Package.wxs) uses the `v4` XML schema
namespace, which WiX 7 retains, and uses
[ServiceInstall](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[ServiceControl](https://docs.firegiant.com/wix/schema/wxs/servicecontrol/),
[EventManifest](https://docs.firegiant.com/wix/schema/util/eventmanifest/), and
[FirewallException](https://docs.firegiant.com/wix/schema/firewall/firewallexception/).
WiX handles manifest/firewall installation, rollback, and removal through its
native extension actions. Resource paths resolve to the installed executable.
Core [PermissionEx](https://docs.firegiant.com/wix/schema/wxs/permissionex/)
elements apply protected SCM ACLs through `MsiLockPermissionsEx`. SYSTEM and
Administrators receive service full access (`0xf01ff`). Authenticated Users receive
only query config/status, enumerate dependents, interrogate, and read-control
rights (`0x2008d`); Start/Stop and configuration changes require elevation.
See [Windows service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
File-log read permissions and the Event Log channel policy remain unchanged.
Separate registry-value components preserve administrator values during repair.
Fixed-target native SCM custom actions provision accounts, service SID types,
delayed automatic start for both services, and recovery after a nonzero BFD exit.
They snapshot the previous settings in the protected installation directory,
restore them during MSI rollback, and remove the snapshot on commit.
WiX documents limitations in the native MSI service-configuration action; these
settings therefore use explicit SCM calls instead of `MsiServiceConfig` authoring.
See [WiX ServiceConfig](https://docs.firegiant.com/wix/schema/wxs/serviceconfig/).
The installed service is Automatic (Delayed Start) and remains stopped for address configuration
and the documented SEHOP policy. See [MSI installation](docs/setup.md#install-with-an-msi).

### Build with GitHub Actions

The [Build Windows MSI workflow](.github/workflows/build-msi.yml) runs on pushes
of version tags matching `v*` and supports manual dispatch. The build job runs
only when the selected ref is a version tag. It audits `Cargo.lock` against the
RustSec advisory database with `cargo audit`, then checks version stamping, Rust
formatting, Clippy, and optimized tests on an x64 `windows-2025` runner using
`rust-toolchain.toml`. The auditor is built with stable Rust outside the
repository, so the repository's build-std configuration doesn't apply to it.

Only builds of version tags package an MSI. Before compilation, the workflow
removes the leading `v` from a tag such as `v1.2.0` and writes `1.2.0` into the
package entries in `Cargo.toml` and `Cargo.lock` in the runner's checkout.
The executable, MSI, artifact filenames, and installation checks use that
stamped version. The workflow validates production executable hardening before
testing installation. Pushes to `main` or other branches and pull requests do
not trigger this workflow. For a manual MSI build, select a version tag as the
workflow ref; a manual run from a branch skips the build job.

The workflow explicitly passes `-AcceptWixEula` for tagged MSI builds, accepting
the WiX 7 OSMF EULA for extension restore and package compilation.

Linting, tests, and production builds all use the release profile. Linting and
tests enable unwinding for the test harness; the production build uses
`panic = "abort"`. The final hardening check reuses the compiled release test
executable so it doesn't rebuild the packaged service or its matching PDB.

The installation test runs only on a GitHub-hosted runner. It checks fresh
installation, actual service configuration, registry types, firewall rules,
rendered Operational events, disabled/enabled file output, repair without
resetting settings, administrator service start/stop, installed service ACLs,
and uninstall while retaining generated logs.
`scripts/Assert-ServiceAccess.ps1` uses Windows `AccessCheck` with a temporary
Authenticated Users restricted token to verify query rights and reject Start/Stop,
pause, configuration changes, deletion, ACL changes, and custom controls. These
checks run on descriptor fixtures locally and the actual service descriptors in
the installation test. The migration rollback test also checks restoration of the
previous service security descriptor. It provisions
loopback addresses and SEHOP before starting the service. It doesn't run on
developer machines. It also checks the installed executable's versions and the
version shown in Windows installed-app settings. Build-time table validation is
read-only and can run locally.

The tests check both service accounts and SIDs, broker startup authorization
from the actual LocalService token, denial of unrelated pipe clients, both
executable versions, delayed start and recovery settings, SCM recovery after a
broker crash, and log writes through the BFD service SID.
`Test-MsiRollback.ps1` first injects an intentional failure into a temporary MSI
copy to exercise fresh-install and existing LocalSystem-account rollback, including
the delayed-start and non-crash recovery flags. It
runs only on a disposable GitHub-hosted runner.

To inspect the package without installing it, run:

```powershell
.\scripts\Test-Msi.ps1 `
    -Path '.\target\installer\BfdWinService-1.2.0-x64.msi'
```

Adjust the filename for the package version. Confirm that validation reports
the x64 package's elevation requirement, service, payload, registry defaults,
firewall rules, and manifest lifecycle.

After a successful tag build, download the `BfdWinService-x64-COMMIT_SHA`
artifact. It contains the MSI and its checksum.
`COMMIT_SHA` is the source commit. Installer test logs are uploaded separately,
including when a test fails.

### Publish a GitHub release

Pushing a version tag or manually running the workflow on that tag publishes a
[GitHub release](https://github.com/miketheitguy/bfd-winservice/releases) after
the build, hardening, and installation checks pass. The release attaches the MSI,
its SHA-256 checksum, with generated release
notes. The release title includes the version tag, such as
`BFD Windows Service v1.2.0`.

Use the GitHub tag as the release version source. The first stable release is
`v1.0.0`; increase the minor version for each subsequent release, such as
`v1.1.0` and `v1.2.0`, with patch version `0`. The executable's `--version`
output, Windows file and product version strings, MSI `ProductVersion`, and
installed-app `DisplayVersion` use the numeric part of the tag, such as `1.2.0`.
Windows numeric file and product versions
append a fourth field of `0`, such as `1.2.0.0`. You do not need to commit a
matching Cargo version before releasing: the workflow stamps both Cargo files
from the tag before running the build checks. Invalid release tags fail before
compilation.

To release a tested commit:

1. Choose the next version tag, for example `v1.2.0`. Keep the existing tag when
   retrying a release.
2. Commit the tested release changes. Confirm that the commit contains the
   release workflow.
3. Create the version tag from that commit, for example:

   ```powershell
   git tag -a v1.2.0 -m "BFD Windows Service v1.2.0"
   ```

4. Push that tag:

   ```powershell
   git push origin v1.2.0
   ```

5. Wait for **Build Windows MSI** to succeed, then open the repository's
   **Releases** page. Confirm that the version's **Assets** include
   `BfdWinService-1.2.0-x64.msi` and its `.sha256` file.

Replace `1.2.0` with the chosen tag version. Only the release job receives
`contents: write`; the build job retains read-only repository access. Rerunning
the release job completes a draft or adds missing assets to an existing release.
It preserves assets already attached to a published release.

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

Native tests use temporary `HKEY_CURRENT_USER` (HKCU) registry keys, named pipes,
local MI fixtures, and loopback UDP sockets. They do not change installed service
settings or Border Gateway Protocol (BGP) peers. The read-only Common Information
Model (CIM) schema test requires namespace access and is opt-in. Run it separately:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

The default suite leaves both this schema test and the native RPC/MI coexistence
test opt-in. It also contains ignored RPC child fixtures that parent tests launch
automatically; do not run those fixtures directly. Install
[Miri](https://github.com/rust-lang/miri#using-miri) for the repository's pinned
nightly toolchain, then check portable logic:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
rustup component add miri
cargo miri test --locked --lib config:: -- --test-threads=1
cargo miri test --locked --lib packet:: -- --test-threads=1
cargo miri test --locked --lib session:: -- --test-threads=1
```

These filters select portable configuration, packet, and session logic; native
registry fixtures are disabled under Miri. An unfiltered Windows library run also
selects native RPC and service-token tests, which Miri cannot execute. To check
the synthetic ancillary-data parser with strict provenance and tree borrows, run:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance -Zmiri-tree-borrows'
cargo miri test --locked --lib ancillary_metadata
```

To check S-BFD state, reflection, timers, and authentication under Miri, run:

```powershell
cargo miri test --locked --test seamless
```

To check the RFC 5880 boundary regressions under Miri, run:

```powershell
cargo miri test --locked --test rfc5880
```

These tests cover diagnostic retention, AdminDown validity clocks, stale zero-RX
limits, Poll acknowledgement, live TX increases, and multihop backoff. For the
requirements and native shutdown coverage, see the
[RFC 5880 conformance review](docs/rfc5880-conformance.md).
For the expanded RFC 5880, RFC 7419, and RFC 7880 suites and their validation
limits, see [RFC conformance tests](docs/rfc-conformance.md).

Run these commands from the repository root so rustup selects
`rust-toolchain.toml`; `+nightly` would select a separate floating toolchain.
Miri interprets Rust and does not execute the native RPC C bridge. If the pinned
nightly has no Miri component for your host, record that limit rather than
silently changing the toolchain for the check.

Native S-BFD tests additionally check IPv4/IPv6 sockets, source-port reflection,
return-route lookup, concurrent initiators, anycast response sources, and the
maintenance retry minimum. They use loopback endpoints and don't establish
interoperability with external router implementations.

Logging tests compare all Rust event descriptors with the SDK-compiled manifest
and check packed payloads. An injected emitter in the production output loop
captures ETW submissions while the same records are written to a temporary file.
These tests cover the severity mapping, diagnostic 0 suppression, ETW failures,
and disabled file output. UDP and reflector tests cover accepted peer reports,
duplicate suppression, maintenance, shutdown, and retained-diagnostic recovery.
Emitter capture verifies the submission path, not Event Viewer delivery.

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
