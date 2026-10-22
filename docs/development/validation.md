# Validate development changes

Cowabunga, test crew. Bring receipts for the checkout you're changing. Run these
checks from the repository root on the [Windows build host](../../CONTRIBUTING.md#before-you-begin).
Start with the required checks, then choose the additional coverage your change needs.

## Required checks

Turtle power means running the checks on your own changes. Get the validation
receipts before committing Rust changes:

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

## Run opt-in native provider checks

Native tests use temporary `HKEY_CURRENT_USER` (HKCU) registry keys, private local RPC endpoints,
local MI fixtures, and loopback UDP sockets. They do not change installed service
settings or Border Gateway Protocol (BGP) peers. The two
[RPC/MI coexistence tests](#verify-native-rpc-boundaries) read a Common
Information Model (CIM) class schema under the broker's COM security policy.
They require namespace access and are opt-in.

On a server with RRAS BGP configured, check the native status query against an
existing peer. This test reads the peer without starting or stopping it:

```powershell
$env:BFD_TEST_RRAS_PEER = 'EXISTING_PEER_NAME'
cargo test --locked --lib native_mi_reads_configured_rras_peer -- --ignored
Remove-Item Env:BFD_TEST_RRAS_PEER
```

Replace `EXISTING_PEER_NAME` with a configured RRAS peer's name.

The default suite leaves the RRAS query and both coexistence tests opt-in. It
also contains ignored RPC child fixtures that parent tests launch automatically;
do not run those fixtures directly.

## Verify native RPC boundaries

On the supported Windows host with a normal token, run the two native RPC suites:

```powershell
cargo test-release --lib local_rpc::
cargo test-release --lib bgp::ipc::
```

Expect zero failures. To check read-only MI provider traffic alongside RPC,
run these opt-in coexistence tests:

```powershell
cargo test-release --lib native_provider_traffic -- --ignored
cargo test-release --lib native_bgp_rpc_and_provider_security_coexist -- --ignored
```

The fixtures isolate process-wide registrations and identities. They don't
impersonate installed services or mutate a live BGP peer. See the
[RPC verification scope](../security/local-rpc.md#verify-the-implementation)
for rejection coverage and the separate installer checks.

## Check portable Rust with Miri

Install
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
[RFC 5880 conformance review](../rfc5880-conformance.md).
For the expanded RFC 5880, RFC 7419, and RFC 7880 suites and their validation
limits, see [RFC conformance tests](../rfc-conformance.md).

Run these commands from the repository root so rustup selects
`rust-toolchain.toml`; `+nightly` would select a separate floating toolchain.
Miri interprets Rust and does not execute the native RPC C bridge. If the pinned
nightly has no Miri component for your host, record that limit rather than
silently changing the toolchain for the check.

## Interpret test scope

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

Validate SCM lifecycle, Event Viewer delivery, and actual BGP Start/Stop on the target server using the [setup guide](../setup.md) and [BGP guide](../bgp.md). For BGP testing, cover initially stopped and running peers, then disconnect and restore Bidirectional Forwarding Detection (BFD) while watching the logs and BGP state.

See the [validation guide](../../RUST_SKILLS_VALIDATION.md) and
[code review](../../CODE_REVIEW.md) for recorded results and test limits.

## Test with release optimizations

Use the repository alias so the rebuilt standard library and test harness
both use unwinding:

```powershell
cargo test-release
```

This checks optimized code. For the production abort-on-panic executable, follow
[artifact verification](../security/build-hardening.md#verification).

## Run AddressSanitizer checks

Channel Donatello: look for memory errors before the pizza celebration. For the
memory-error vibe check, AddressSanitizer (ASan) detects memory errors during
testing. The repository's `cargo asan` alias enables `-Z sanitizer=address`,
preserves the Windows hardening flags, rebuilds the standard library, and writes
to `target/asan`. It also passes the sanitizer flag to `rustdoc` for
documentation tests. Its dedicated profile uses unwinding for the test harness.
The native build detects the target's `CARGO_CFG_SANITIZE=address` setting and
adds `/fsanitize=address /Zi` to maintained RPC C files and generated MIDL stubs.

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

Install the Visual Studio C++ Build Tools with the AddressSanitizer component.
From the repository root, run the test wrapper:

```powershell
.\scripts\Test-Asan.ps1
```

The wrapper initializes the selected x64 MSVC environment, verifies the runtime
DLL beside that compiler, and builds the sanitized test graph. It checks the
active Cargo build record and emitted ASan hooks in the native RPC client before
running tests. Build records, native instrumentation evidence, and test output
are written under `target/asan`. Confirm that the wrapper reports verified
native instrumentation and that the tests finish without an ASan report.

For a focused check, pass Cargo arguments to the wrapper:

```powershell
.\scripts\Test-Asan.ps1 -CargoArguments @('--lib', 'packet::tests')
```

For direct `cargo asan` use, first run `scripts/Initialize-Asan.ps1` in the same
PowerShell process. It initializes compiler and SDK variables only, without
printing the captured process environment. Set `BFD_VCVARS64_PATH` to select a
custom installation; otherwise it locates the latest x64 C++ toolset with
`vswhere.exe`. A missing ASan runtime fails setup. The installed nightly
must support `address` for `x86_64-pc-windows-msvc`; check target support
again after a toolchain update.

ASan is a [testing tool](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html#addresssanitizer).
Distribute the normal release executable. ASan tests don't instrument Windows
system DLLs or the prebuilt MSVC runtime. The separate `asan` CI job tests the
same source revision and tag version as `build-msi`; it uploads diagnostics
only. Release publication requires `asan`, `fuzz`, and `build-msi` to succeed. The production job
builds its own ordinary release executables, checks that they import no ASan
runtime, and validates the MSI independently. Sanitizer flags and binaries do
not pass between these jobs.
