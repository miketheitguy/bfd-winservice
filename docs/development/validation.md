# Validate development changes

Cowabunga, test crew. Bring receipts for the checkout you're changing. Run these
checks from the repository root on the [Windows build host](../../CONTRIBUTING.md#before-you-begin).
Start with the required checks, then choose the additional coverage your change needs.

## Required checks

Turtle power means running the checks on your own changes. Get the validation
receipts before committing Rust changes. Use PowerShell 7 for the commands here.
Run native tests with a normal Windows process token and access to temporary
HKEY_CURRENT_USER (HKCU) registry keys and local RPC endpoints. A restricted
execution sandbox can prevent these fixtures from running. The default suite
also reads a Common Information Model (CIM) schema in an isolated privilege-policy
fixture; it requires namespace access but does not change BGP peers.

Run the required checks:

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- `
    -D warnings -D clippy::undocumented_unsafe_blocks
cargo fmt --check
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --locked --no-deps
.\scripts\Test-DocumentationLinks.ps1
```

Confirm that the commands complete without errors. The documentation check also rejects undocumented public API elements.

For documentation-only changes, run `scripts/Test-DocumentationLinks.ps1` in
PowerShell 7. It checks repository-relative Markdown links and Markdown anchors
in tracked files, including explicit HTML anchors; it does not query external
URLs. If you change the checker, also run `scripts/Test-DocumentationLinkPolicy.ps1`.

Configuration validation and protocol modules are portable. Registry loading, User Datagram Protocol (UDP) transport, ETW, native Management Infrastructure (MI), and Windows Service Control Manager (SCM) integration require Windows. IPv4 time-to-live (TTL) metadata requires `IP_RECVTTL` support.

## Run opt-in native provider checks

Native tests use temporary HKCU registry keys, private local RPC endpoints,
local MI fixtures, and loopback UDP sockets. They do not change installed service
settings or Border Gateway Protocol (BGP) peers. The two
[RPC/MI coexistence tests](#verify-native-rpc-boundaries) read a CIM class schema
under the broker's COM security policy.
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

Native UDP fixtures choose available source ports in 49152–65535, skipping
address-in-use and access-denied binds. Avoid fixed high source ports: Windows
runners can reserve them or hold exclusive wildcard binds. Keep protocol
destination ports fixed. The explicit `SourcePort` case probes its own loopback
address and releases that socket immediately before opening the engine.

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
[code review checklist](../../CODE_REVIEW.md) for required coverage and test limits.

## Validate installed-service security in a disposable VM

Run `scripts/Test-ServiceTestRecovery.ps1` to check recovery-isolation cleanup
with a state model. The guarded installation tests exercise the helper with
actual SCM policy. Expected privilege/key startup failures suppress non-crash
recovery in a bounded scope and restore the original flag before healthy
startup. This prevents queued restarts from racing with later stop checks.
Crash-recovery configuration and the broker recovery test retain their installed
behavior.

On an installation-test failure, inspect `service-test-diagnostics.json` beside
the tested MSI. CI includes it in the installer-log artifact. It records bounded
service state and event data before uninstall removes the service/provider.

Use a GitHub-hosted runner or the provisioned disposable `BFD-WS2025` Hyper-V
guest for tests that change services, HKLM, Event Log, firewall, or provider
state. The installer scripts reject ordinary developer hosts. Run the complete
fresh-install, rollback, and bundle maintenance
sequence described in [packaging validation](packaging.md#build-with-github-actions).
These tests install and remove the product; preserve the lab configuration and
checkpoint before running them.

`Test-MsiInstall.ps1` invokes `Test-ServicePrivilegePolicy.ps1` with both services
stopped. The policy test broadens each SCM list to include
`SeImpersonatePrivilege`, requires startup rejection and a matching ETW
diagnostic, restores only `SeChangeNotifyPrivilege`, and verifies recovery.
Its `finally` block stops both services and restores the minimum lists.
The install harness then checks independent startup and actual running tokens
after startup and repair. Unit tests separately cover missing, disabled, and
extra privileges, including disabled extras, and confirm queries leave the
token unchanged. See [service isolation](../security/service-isolation.md).

For Windows/Ubuntu interoperability, run the authentication matrix, isolated
Windows- and BIRD-controlled withdrawals and recoveries, BGP-only controls,
service and process interruption cases, adapter and packet faults, logging-disabled
recovery, and final route/stability checks. Native loopback and installer
fixtures alone do not establish these results. Record the tested source,
scenario outcomes, and restoration checks with each run.

During an RRAS restart, SCM can report Running before the BGP provider accepts
queries. A lab sampler can treat the specific `0x800710dd` service-not-running
result as unavailable while retrying within its readiness timeout. Preserve
other query errors as failures; do not infer provider readiness from SCM alone.

## Verify protected authentication keys

On Windows, run the provisioning-script fixtures and native registry tests:

```powershell
.\scripts\Test-BfdAuthenticationKey.ps1
cargo test --locked --lib config::
```

The fixtures use temporary HKCU keys and check DPAPI interoperability, input
validation, read-back verification, and preservation of existing values after
rejected input. They do not establish access under the installed service's
restricted token.
In a disposable installed-service test, configure matching peer authentication,
set the key with the installed administration tool, and require communication
under the actual LocalService service token. Inspect the Secrets ACL, require
missing or malformed encrypted keys to fail startup, and confirm that repair
preserves the encrypted value and ACL. See
[authentication key administration](../configuration.md#authentication-key-administration)
and [installation permissions](../reference/installation.md).

## Test with release optimizations

Use the repository alias so the rebuilt standard library and test harness
both use unwinding:

```powershell
cargo test-release
```

This checks optimized code. For the production abort-on-panic executable, follow
[artifact verification](../security/build-hardening.md#verification).

## Run AddressSanitizer checks

AddressSanitizer (ASan) checks memory errors in the Rust test graph, rebuilt
standard library, maintained RPC C, and generated MIDL stubs. The wrapper uses
an isolated `target/asan` directory and verifies native instrumentation before
running tests. See
[test-profile differences](../security/build-hardening.md#test-profile-differences)
for compiler flags and coverage limits.

Install the Visual Studio C++ Build Tools with the AddressSanitizer component.
Use PowerShell 7 (`pwsh`) for the ASan and fuzz build wrappers. From the
repository root, run the test wrapper:

```powershell
.\scripts\Test-Asan.ps1
```

The wrapper initializes the selected x64 MSVC environment, verifies the runtime
DLL beside that compiler, and builds the sanitized test graph. It checks the
active Cargo build record and emitted ASan hooks in the native RPC client before
running tests. Build records, native instrumentation evidence, and test output
are written under `target/asan`. Confirm that the wrapper reports verified
native instrumentation and that the tests finish without an ASan report.

Run socket test suites one at a time on a given host. Separate Cargo target
directories do not isolate the loopback addresses and ports used by the native
UDP fixtures.

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

ASan is a
[testing tool](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html#addresssanitizer).
Distribute the normal release executable. ASan tests don't instrument Windows
system DLLs or the prebuilt MSVC runtime. The separate `asan` CI job tests the
same source revision and tag version as `build-msi`; it uploads diagnostics
only. The production job builds and validates ordinary release executables;
sanitized binaries never supply the MSI payload. See the
[release gates](packaging.md#build-with-github-actions).
