# Rust skills validation — current guide

Cowabunga, validation crew. Bring the receipts for the checkout you inspect.
Updated 2026-10-16. Rust maintainers, let's get the validation lineup dialed in.
This guide helps you check the implemented API and choose validation commands
using the local [Rust skill](.codex/skills/rust-skills/SKILL.md). The
[correctness review](CODE_REVIEW.md) records fixes, checks, and validation
limits. The
[2026-10-01 audit](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) preserves
the original 265-rule matrix; its defect examples, source hashes, rule counts,
and test counts are historical.

## Choose a validation task

Choose your next test mission, turtle crew. Like, pick your line, buddy: these
links separate checkout guidance from recorded results:

| Task | Section |
| --- | --- |
| Run checks for the checkout | [Check the current checkout](#check-the-current-checkout) |
| Look up API validation guarantees | [Resolved public API findings](#resolved-public-api-findings) |
| Review native ownership and concurrency limits | [Ownership and concurrency boundaries](#ownership-and-concurrency-boundaries) |
| Interpret counts and superseded behavior | [Read the validation receipts](#read-the-validation-receipts) |
| Inspect results for an earlier revision | [Historical validation records](#historical-validation-records) |
| Find installation and operational guides | [Documentation index](docs/README.md) |

## Read the validation receipts

Donatello would check both the revision and the test scope. History vibe check:
each dated section records its own revision. Counts and successful checks are
historical evidence, not a passing result for this checkout. No cap: rerun the
checks before shouting Cowabunga for this checkout. The documentation audit on
2026-10-15 checks descriptions against source and build configuration; it does
not rerun or replace the recorded runtime tests.

Use these implementation details when an older entry describes a superseded
design:

- Production releases omit Rust debug information, symbols, and linker PDBs.
  Development and ASan retain Rust debug information. The RPC stubs and C bridge
  compile with MSVC; Rust ASan does not instrument those native objects. See
  [build security](CONTRIBUTING.md#build-security).
- A classical communicating session announces AdminDown for the longer local
  or peer Detection Time, bounded by `MaxShutdownAnnounceMs` (default 30 seconds,
  range 1–60000 ms). The former five-second limit is historical. See
  [protocol behavior](docs/protocol.md).
- Local or peer AdminDown releases a BGP Stop previously requested by this
  controller by queuing Start. Disconnects and broker shutdown do not issue
  Stop. See [BGP action rules](docs/bgp.md).
- BGP control uses a separate authenticated `ncalrpc` interface. It shares the
  telemetry interface's security helpers, reverses service identities, and retains
  the restricted-caller SID check. The former named-pipe transport is historical.
  See [BGP control RPC](docs/rpc-authentication.md#bgp-control-over-local-rpc).
- One RPC worker runs inside the broker. Rejected records clear telemetry and
  retry with capped backoff; only a stuck native worker quarantines telemetry
  until restart. See [RPC session-status query](docs/rpc-session-status-design.md).
- The pinned toolchain and [tagged MSI workflow](.github/workflows/build-msi.yml)
  provide repeatable build inputs and release checks. The workflow does not run
  on branch pushes or pull requests and does not run ASan or Miri. Run those
  checks locally when applicable; see [development checks](CONTRIBUTING.md#run-development-checks).

## Current API and validation

Keep the active API guidance ready to kick shell. Use these sections for
checkout commands and API contracts. Dated test paragraphs retain the results
and limits of their recorded revisions.

### Check the current checkout

Get the toolchain lined up for a bodacious validation run. Time to lock in. On
x64 Windows with the MSVC toolchain and Windows SDK installed, use the
repository's nightly toolchain and build configuration:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- `
    -D warnings -D clippy::undocumented_unsafe_blocks
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --locked --no-deps
```

The native schema test and the RPC/MI coexistence test are opt-in because they
require native namespace access and a normal Windows token:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
cargo test-release --lib native_provider_traffic -- --ignored
```

Follow the [contributor guide](CONTRIBUTING.md) for release, ASan, filtered Miri,
and production artifact checks, and [Set up a BFD session](docs/setup.md) for
deployment. The native RPC child fixtures are ignored entry points launched by
their parent tests; do not run them directly. Recorded test totals apply to each
review's checks, not automatically to later revisions. Actual BGP Start/Stop and
SCM lifecycle behavior need validation on a provisioned Windows Server; local
fixtures do not establish provider behavior.

Registry configuration checks on 2026-10-07 passed: 69 tests including the doctest, with one opt-in native schema test ignored; formatting; strict Clippy including undocumented unsafe blocks; documentation with warnings denied; and the release build. Seven configuration tests passed under Miri with strict provenance, and the final string decoder was checked again after the parity-check lint correction. Release smoke checks confirmed that help exposes only `--console` plus help/version, removed configuration arguments are rejected, and a missing Parameters key produces exit code 1 with lifecycle/failure messages on STDOUT and empty STDERR. No installed service configuration was modified.

No full 265-rule reassessment or complete Rust skill compliance is claimed. The
string-based configuration errors noted in that registry review have since been
replaced by typed enums. The crate pins its nightly toolchain. Its tagged-release
workflow checks optimized tests, Clippy, production hardening, MSI installation,
and rollback; branch and pull-request CI, ASan CI, and Miri CI are not configured.

### Resolved public API findings

- **F1:** Authentication kind and key are private. `AuthConfig::kind()` exposes the type without mutation; changing authentication requires constructing a new validated configuration. A compile-fail doctest checks that the kind cannot be assigned directly.
- **F2:** `Options::into_validated` checks numeric ranges, endpoint source policy, and option combinations, then creates an immutable `ValidatedOptions` snapshot. Its `ProtocolRole` contains required nonzero S-BFD identifiers. The runtime shares this snapshot between components, while live timers and maintenance state remain separate. Raw constructors, including `Transport::open`, perform full validation. Session state, discriminators, and Poll tracking are read-only outside the crate.

Raw `Options` remain publicly mutable; consume them into a new validated snapshot after changing them. `ControlPacket::encode` serializes public header fields without validating them; decoding and authentication verification provide receive-side checks. Public configuration, packet, authentication, and receive errors use typed enums.

`CommandLine` parses only `--console` plus standard help/version flags. `Options::new` constructs defaults for explicit local/peer addresses; it does not validate them. On Windows, `config::load_registry` reads the service's HKLM Parameters key without creating or modifying it and returns a validated snapshot before sockets open. The loader enforces `REG_SZ`/`REG_DWORD`, checks numeric narrowing, rejects invalid Booleans and malformed UTF-16, and excludes authentication contents from errors. Native loader tests use unique temporary HKCU keys rather than the installed service's configuration.

`Multihop` is the only registry transport selector: absent or DWORD `0` selects single-hop; DWORD `1` selects multihop. Other values and types fail loading. The former `Mode` registry value is ignored. The loader sets the internal transport profile before returning options; library callers can still use the `Mode` enum directly.

The 2026-10-08 selector change passed 72 default tests (61 library, 2 service, 7 UDP, and 2 doctests), with one opt-in CIM schema test ignored. The native regression verifies absent/0/1 selection and ignored legacy `Mode` entries; existing type/range tests reject malformed `Multihop` settings. Formatting, strict Clippy, rustdoc with warnings denied, and the release build passed. Tests used temporary HKCU keys; the installed service's configuration was not modified.

`LogFilePath` is a `REG_SZ` path, defaulting to `C:\ProgramData\BfdWinService\trace.log`. `LogToFile` is a `REG_DWORD` flag, defaulting to `0`. Startup reads both values; disabled logging never opens, creates, or writes the path. With DWORD `1`, the startup logger creates missing parent directories and opens one append file shared by engine, BGP, and service supervisor messages. Folder creation and file-open failures propagate as startup errors; runtime write failures remain best-effort diagnostics.

The administrator-only [logging setup script](scripts/Initialize-Logging.ps1) provisions the default registry values and folder separately from the read-only runtime loader. It disables file output and does not create or write `trace.log`.

The 2026-10-08 file-logging change passed 76 default tests (65 library, 2 service, 7 UDP, and 2 doctests), with the opt-in CIM schema test ignored. The missing-parent regression failed with Windows error 3 before implementation, then passed with directory creation and append behavior. Additional regressions verify that disabled logging leaves existing, missing, and blocked paths untouched; enabled parent-directory errors are returned; registry paths are read independently of the flag; and malformed flag values/types are rejected. Formatting, strict Clippy, rustdoc with warnings denied, and the release build passed. These tests use temporary directories and HKCU keys.

File log entries use `YYYY-MM-DDTHH:mm:ss.sssZ` timestamps sampled immediately before writing. The Windows [GetSystemTime API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime) supplies UTC fields without local timezone conversion. Each line of a multiline message receives the same entry timestamp, including blank lines and CRLF messages. The regression failed against Unix-millisecond output before implementation, then passed. The 2026-10-08 timestamp change passed 77 default tests (66 library, 2 service, 7 UDP, and 2 doctests), with the opt-in schema test ignored, plus formatting, strict Clippy, rustdoc with warnings denied, and the release build.

### Ownership and concurrency boundaries

Ninja discipline starts with clear owners and native lifetimes. Keep ownership
dialed in, dude. Session reception verifies authentication before modifying
state, timers, or sequence tracking. Verification returns a sequence for the
session to commit; verification alone does not update tracking. Transport
peer/path checks happen before session processing in the runtime.

The broker's MI wrappers own their native handles, keep them on the calling
thread, and release children before their session/application. Borrowed MI
result data is consumed before the next result fetch or operation close. Normal
retrieval drains results; error cleanup attempts cancellation and draining and
logs failures. MI's requested timeout does not guarantee completion. A separate
watchdog detects provider requests, including schema lookup and cleanup, active
for 20 seconds and ends the broker process; SCM recovery handles unrequested
failure exits.

BGP IPC runs outside the BFD mailbox mutex, and native provider work runs in the
separate broker. The mailbox holds at most a failure/recovery pair; Down
supersedes queued recovery. Local or peer AdminDown withdraws this controller's
Stop by queuing Start. Start checks for supersession before and after its status
query, but provider mutation is not atomic with packet processing. Closing
publishes cancellation before the worker can dequeue its final action. Each
final IPC call has a 20-second budget; final-action failures propagate.

For SCM execution, BFD's supervisor bounds requested-stop cleanup to 60 seconds
plus the chosen announcement period; the broker has a 60-second stop budget.
These process-level limits can terminate native cleanup. See
[BGP shutdown and recovery](docs/bgp.md) and
[protocol shutdown behavior](docs/protocol.md).

RPC status replies borrow one immutable publication on an RPC worker. Rust
converts the fixed native record into typed values once. Pending call storage
remains owned until native completion; a stuck worker is retained and
quarantined without blocking broker shutdown or spawning replacements. This
telemetry never supplies BGP control decisions.

The unsafe ancillary parser checks buffer bounds before unaligned reads. Its synthetic unit tests run under Miri without using Winsock. Miri cannot verify actual Winsock, registry, ETW, or `mi.dll` execution. Console logging has a subprocess test verifying lifecycle and failure messages reach STDOUT, leave STDERR empty, and run without ETW registration; subprocess tests are excluded under Miri.

## Historical validation records

Turtle power keeps old results tied to their original missions. These are the
flashback receipts: earlier implementation and validation results. Their
behavior descriptions and counts apply to the named revisions; use
[Read the validation receipts](#read-the-validation-receipts) for superseded
details and [Check the current checkout](#check-the-current-checkout) to run
checks.

### Local RPC security validation — 2026-10-15

The [RPC recovery review](CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15)
records implementation checks and limits. The
[RPC authentication reference](docs/rpc-authentication.md) and
[service diagrams](docs/service-communication.md) describe the implemented
status contract, native token checks, restricted BFD privileges, management
denial, in-process broker worker, and completion-before-release ownership.

Native cross-process tests cover both successful calls and rejected account,
group, anonymous, replacement-server, and runtime-management paths. Cancellation
and supervised-worker tests exercise resource lifetime, rejected-data recovery,
capped backoff, stalled-worker quarantine, and bounded shutdown. The fixtures
use real test tokens without granting service SIDs.
SCM-created LocalService and
broker service tokens require the disposable installed MSI check, independently
of fixture results. Existing provider COM/MI compatibility remains covered by
the explicit native schema query.

### State and diagnostic logging validation — 2026-10-08

The [logging review](CODE_REVIEW.md#state-and-diagnostic-logging-review--2026-10-08)
records the defects and corrections. The
[event reference](docs/logging.md#operational-events) documents the 22 Operational
events, including separate local/remote states and diagnostic IDs 201–208.
State and diagnostic records share their ETW descriptor, packed payload, and
file representation. Diagnostic 0 has no standalone event; Up and AdminDown
state events remain Informational independently of the diagnostic level.

Peer state and diagnostic getters update only after acceptance. Tracking uses
one inline report per runtime, and record buffers move through the existing
bounded queue. ETW borrows the packed bytes only during the synchronous call.
No unsafe code or protocol-loop locks were added. Existing authentication tests
verify that rejected packets don't overwrite peer state or diagnostic context.

Emitter capture checks paired submissions and file output through the production
writer, including ETW failure isolation and `LogToFile=0`. UDP tests cover all
assigned peer codes without a local state transition; reflector tests cover
maintenance and shutdown. Console mode continues to use STDOUT and the enabled
file without ETW. Event Viewer delivery and installed service behavior require
deployment validation; these tests don't change service or BGP configuration.

Earlier entries describe the revisions reviewed at those times.

All **133 tests** passed in each debug, optimized, and ASan suite, with one
opt-in CIM schema test ignored. **35 tests** covering sessions, event payloads,
and S-BFD passed under Miri with strict provenance and tree borrows. The SDK
compiled the manifest, and all 22 Rust descriptors match its generated output.
Formatting, strict all-target Clippy, rustdoc, documentation links, and the
rebuilt production release's x64 PE hardening/PDB regression passed.

### RFC 5880 validation — 2026-10-08

The [RFC conformance review](docs/rfc5880-conformance.md) maps the complete
document to implementation and tests, including the RFC 7880 overrides used by
S-BFD. Its [remediation record](CODE_REVIEW.md#rfc-5880-conformance-remediation--2026-10-08)
describes the confirmed findings, Rust skill review, and documentation changes.

Classical recovery retains LocalDiag. Authenticated validity and liveness use
separate clocks, including in AdminDown. Stale peer RX limits expire after one
detection time. Multihop retries back off from the greater of the startup base
and the preceding negotiated rate. Live S-BFD TX increases retain the old
effective rate until a transmitted Poll is acknowledged; another wire change
requires a subsequent non-Final response. Runtime socket failures don't commit
sequence, Poll, or S-BFD probe tracking.

Normal classical shutdown with a communicating peer repeats permitted AdminDown
announcements for the detection period, capped at five seconds. The cap and
unsupported optional features are explicit in the requirement map. Earlier
dated entries describe the revisions reviewed at those times.

All **124 tests** passed in debug, optimized, and ASan builds; **54 configuration
and protocol tests** passed under Miri with strict provenance and tree borrows.
Formatting, strict Clippy, rustdoc, and the rebuilt production release's
x64 PE hardening/PDB check passed. The default suite still ignores one opt-in
CIM schema test. These checks don't replace live service, Event Viewer, real
peer interoperability, or BGP provider validation.

### rust-security fixes — 2026-10-08

The current runtime shares immutable validated startup settings and one bounded
logging worker. S-BFD startup and receive validation use the same source-address
policy. Public configuration, packet, authentication, and receive errors use
typed enums. See the [latest remediation record](CODE_REVIEW.md#rust-security-remediation--2026-10-08)
for the original defects, API changes, regression evidence, and limits.

All 112 tests passed in debug, optimized, and ASan builds; 43 protocol and
configuration tests passed under Miri with strict provenance and tree borrows.
The production release image passed the x64 hardening/PDB regression. Formatting,
strict Clippy, and rustdoc checks passed. One opt-in CIM schema test was ignored.

### Expanded hardening review — 2026-10-08

Heads up, buddy: this entry records the Rust-only build and release PDBs at that
revision. The native RPC bridge and symbol-free release policy described in
[build security](CONTRIBUTING.md#build-security) supersede those details.

Mapped the requested MSVC and Rust settings to the Rust-only build in
[Build security](CONTRIBUTING.md#build-security). Added explicit PIC, release
overflow checks, release panic abortion, full release PDBs, SHA-256 Rust source
checksums, denied warnings and unsafe operations, and denied production
`unwrap()`. Packet, session, and reflection modules forbid unsafe code.
Documented exceptions retain the Windows registry, ETW, Winsock, MI, and UTC
clock FFI boundaries; no FFI operations were added.

MSVC `/sdl` and `/analyze` apply to C/C++ source, which this project doesn't
compile. Rust compiler checks, strict Clippy, Miri, and ASan provide the
applicable checks. The correct MSVC source-checksum spelling is
`/ZH:SHA_256`. Intentional wrapping, checked, and saturating arithmetic retain
their protocol semantics.

The installed nightly's target specification supports AddressSanitizer on
`x86_64-pc-windows-msvc`. The `cargo asan` alias preserves the hardening flags,
instruments the rebuilt standard library, and uses a separate target directory.
All 106 tests passed under ASan without reports. An isolated, deliberately
invalid stack access produced a stack-buffer-overflow report and exit code 1,
confirming the detector was active. The MSVC ASan runtime DLL must be on PATH;
the normal release image has no ASan runtime dependency.

Debug and optimized tests passed all 106 checks, with one opt-in CIM schema
test ignored. The optimized `test-release` alias explicitly uses unwinding
for the test graph: rebuilding the standard library with the aborting release
profile otherwise conflicts with the normal test harness. A separate production
release build uses `panic = "abort"`. The executable regression passed against
that actual image through `BFD_HARDENING_EXE`.

Release LLVM IR contains PIC level 2, `cfguard=2`, `ehcontguard=1`, full
debug information, SHA-256 source checksum metadata, checked-arithmetic
intrinsics, and no Rust unwind `invoke` instructions. The release PDB contains
the exact SHA-256 checksum of `src/main.rs`. The executable retains guard
flags `0x00417500`, CET compatibility, and two EH continuation entries after
panic abortion removed Rust landing pads. An empty enabled EH table is also
valid. Build-script probes reject later static-relocation and MD5-checksum
overrides.

Strict Clippy, formatting, Rust documentation checks, release help, and three
strict-provenance Miri ancillary-parser tests passed. ASan doesn't instrument
Windows system DLLs or the prebuilt MSVC runtime. No installed service,
machine mitigation policy, or BGP provider state was changed.

### Exception handling hardening — 2026-10-08

Enabled `-Z ehcont-guard=yes`, `/GUARD:EHCONT`, and `/CETCOMPAT` for the x64
Windows build. The standard library and Rust dependencies are rebuilt with the
EH continuation compiler setting. The build rejects missing or disabled
metadata generation, including a later overriding option.

The executable regression reproduced missing EH continuation metadata before
the change. Debug and release checks now verify the EH guard flag, a populated
continuation table, sorted unique RVAs mapped to the image, and the CET
compatibility marker. Release `dumpbin` inspection found guard flags
`0x00417500`, 13 EH continuation entries, and CET compatibility. Generated
release LLVM IR contains `ehcontguard=1`; Rust assembly contains a
`.gehcont$y` section.

All 106 default tests passed in debug and release, with one opt-in CIM schema
test ignored. Formatting, strict Clippy, Rust documentation checks, and release
help passed. Runtime CET enforcement depends on Windows, hardware, and policy;
exploit-triggered termination wasn't exercised.

### Control packets and state signaling — 2026-10-08

Reviewed the mandatory header and authentication formats against RFC 5880
section 4, and state/flag handling against sections 6.5 and 6.8. The 24-byte
layout, field widths, network byte order, authentication lengths, and flag
positions matched. The [protocol reference](docs/protocol.md#control-packet-format)
now describes flags, states, and the local diagnostics the service emits.

Regressions reproduced acceptance of simultaneous Poll/Final flags, missing
state notifications when the peer's zero receive interval suppressed periodic
traffic, and replacement of an S-BFD failure diagnostic by a maintenance reply
that left the state unchanged. The shared decoder now rejects conflicting
flags before session mutation. Classical state notifications use a signed
packet with Poll clear, even when periodic traffic is suppressed; passive
sessions still require a known peer discriminator. Pending Polls remain on the
periodic schedule, and Final replies remain independent. S-BFD retains the last
failure diagnostic until its state changes.

All 16 classical local/peer state combinations check the reported transition,
diagnostic, and emitted wire state. Byte fixtures cover every state and five-bit
diagnostic value, flag positions, and all six authentication configurations.
Native UDP checks verify authentication and wire diagnostics `0`, `3`, `1`,
and `7` through establishment, peer maintenance, recovery, timeout, and shutdown
with periodic traffic suppressed. Text logs report each actual transition once.
S-BFD retains its RFC 7880 Demand-bit and reflection behavior.

The debug and release suites passed 106 tests, with one opt-in CIM schema test
ignored. Strict-provenance Miri passed 35 tests: nine packet, 14 session, and
12 portable S-BFD tests. Formatting, strict Clippy, Rust documentation with
warnings and missing public descriptions denied, release build/help, and
documentation links passed. Native protocol checks use loopback sockets;
external router interoperability and live SCM/Event Viewer deployment weren't
exercised.

### Windows build hardening — 2026-10-08

The default target is `x86_64-pc-windows-msvc`. Windows builds reject other
targets, and the build script requires full CFG checks and the
`stack-protector=all` compiler strategy. Explicit linker settings enable ASLR,
high-entropy ASLR, large address awareness, NX/DEP, and CFG. The repository
selects nightly Rust and rebuilds the standard library with the same compiler
protections as the service and its Rust dependencies. See the
[build security instructions](CONTRIBUTING.md#build-security).

Validation used Rust `1.101.0-nightly (21b707e3f 2026-09-30)`. All 99 default
tests passed, with one opt-in CIM schema test ignored. The new
[executable regression](tests/windows_hardening.rs) passed for debug and release
builds, checking PE32+ x64 headers, mitigation bits, relocations, CFG pointers and
function-table metadata, and the security cookie. It reproduced a missing-CFG
failure against the earlier executable. Independent `dumpbin` inspection
confirmed the release image flags and a populated CFG function table.

Generated release LLVM IR contained the full CFG module flag and
`sspreq` attributes on all 214 function definitions. Generated Rust assembly
contained actual security-cookie loads and checks and CFG indirect-call
dispatches. Direct build-script probes rejected 32-bit x86 and ARM64 Windows
targets, missing CFG instrumentation, and later options disabling stack
protection or selecting metadata-only CFG.

Formatting, strict Clippy, Rust documentation with warnings and missing public
descriptions denied, and release help/version checks passed. Miri passed all
11 portable S-BFD tests with strict provenance and all three ancillary parser
tests with strict provenance and tree borrows. These checks don't rebuild
Windows system DLLs or exercise exploit-triggered CFG/stack-cookie termination.

### IP-routed Seamless BFD — 2026-10-08

Added RFC 7880 initiator and stateless reflector roles using RFC 7881 IPv4/IPv6
UDP transport. The [S-BFD guide](docs/seamless.md) maps RFC 7882 use cases to
implemented behavior and identifies the external forwarding-plane requirements.
Classical single-hop remains the default. Registry configuration adds
`SessionType` and `AllowedPeers` strings, plus `RemoteDiscriminator` and
`SbfdAdminDown` DWORD values. Reflectors don't require or read `Peer`.

Initiators send to UDP 7784 and receive replies on their bound source socket.
Reflectors reply from their listener after validating source policy, the
destination, protocol role, discriminator, and authentication. A Windows
`GetBestRoute2` lookup verifies a return route. Typed sockaddr copies and native
output buffers have documented bounds and lifetimes. Reflection retains no peer
state, copies keyed request sequences, and computes new response digests.
Initiators consume outstanding keyed sequences once; their tracking queue is
bounded to 1,024 entries.

S-BFD timing values and reflector maintenance reload once per second without
resetting state. Invalid updates retain the preceding values. Detection includes
a configured round-trip allowance; missing responses double the transmission
interval to reduce traffic. An AdminDown response preserves communication and
enforces at least one second between retries after jitter and rescheduling.
A native regression reproduced a 758 ms retry before that scheduling correction.

Validation passed 98 default tests: 70 library, 2 service, 11 portable S-BFD,
6 Windows S-BFD, 7 classical Windows UDP, and 2 doctests. One opt-in CIM schema
test was ignored. Strict-provenance Miri passed all 11 portable S-BFD tests and
the library sequence-wraparound regression. Formatting, strict Clippy, Rust
documentation with warnings and missing public descriptions denied, and the
release build passed. Native tests cover IPv4/IPv6 replies, multiple concurrent
initiators including one address pair, anycast source changes, filtering,
authentication, timeout events, and maintenance retry timing.

Registry fixtures use temporary HKCU keys; service configuration wasn't changed.
Live registry reading is checked through the same loader against those fixtures.
Real router interoperability, SCM deployment, Event Viewer delivery, and BGP
provider mutations weren't exercised. MPLS label stacks, segment-routing
encapsulation, forwarding-plane TTL-expiry delivery, and S-BFD Echo aren't
implemented.

### Technical documentation improvements — 2026-10-08

Applied the technical-documentation skill's audit recommendations. The README now introduces the service and links to focused setup, registry, logging, BGP, protocol, and development guides. Fresh-installation procedures distinguish startup, Windows service status, BFD readiness, and optional shutdown. Examples use explained placeholders, fit within 80 columns, and describe expected results. The registry reference covers all 22 supported settings; the logging reference covers all nine manifest events. Historical review statements are dated rather than presented as current configuration instructions.

Added descriptions for 33 public enum variants and fields. Rust source comparison after removing API comments confirmed unchanged executable code. Validation passed: 77 tests (66 library, 2 service, 7 Windows UDP integration, and 2 doctests), with one opt-in CIM schema test ignored; formatting; strict Clippy including undocumented unsafe blocks; and Rust documentation with warnings and missing public descriptions denied. Local Markdown links and anchors resolved, all 28 PowerShell samples parsed, and sample lines fit within 80 columns. The examples were parsed without executing installation, registry provisioning, or removal commands. Live service deployment, Event Viewer delivery, and BGP provider mutations were not exercised.

### Code and documentation review — 2026-10-07

The complete service source, tests, build configuration, manifest, and documentation were reviewed against the registry/ETW implementation and relevant Rust skill rules. That review recorded a P2 finding: console STDOUT errors could panic and bypass AdminDown/BGP Stop cleanup or terminate the BGP worker. A standalone Windows closed-pipe probe reproduced the logger panic. The initial review changed documentation only; the finding was subsequently fixed by the rust-check remediation described below and in the [correctness review](CODE_REVIEW.md).

Documentation corrections also cover `LogFile` path handling, lifecycle Mode rendering, generic discard/send logging conditions, and the historical scope of the earlier CLI compatibility and validation results. The default 69 tests and strict Clippy passed again during this review; the opt-in schema test was ignored. Formatting, rustdoc with warnings denied, release help, and all 310 local Markdown file links passed their checks after the edits. A source comparison with API comments removed confirmed unchanged production code. Native service deployment, Event Viewer rendering, and real BGP mutations remain outside these checks.

### rust-check remediation — 2026-10-07

Applied [.codex/skills/rust-check/SKILL.md](.codex/skills/rust-check/SKILL.md). Console output now uses fallible writes and disables the failed destination per logger, preserving file output and engine/BGP cleanup. Logger STDERR diagnostics are best-effort. A subprocess regression reproduced the old failure before implementation and now verifies successful engine shutdown and continued file logging with a closed STDOUT pipe. Normal console output still has a separate subprocess regression.

Internal receive rejections derive `thiserror::Error`, while the existing public error APIs remain compatible. `Received` derives the applicable value traits. Imports, automatic error conversion, and SDK lookup were simplified. File fixtures use `tempfile`; subprocess assertions use `assert_cmd`. These targeted changes follow the skill's minimal-change guidance; the existing Winsock polling loop and MI worker do not require an async-runtime migration.

Required formatting and strict Clippy passed. The default test suite passed 71 tests, including the new regression and logger example, with one opt-in schema test ignored. The closed-pipe regression additionally passed with STDERR closed, confirming unavailable diagnostics do not interrupt cleanup. Rustdoc with warnings denied, the release build, release help, all 311 local documentation links, and `git diff --check` passed. Full Miri, live service deployment, Event Viewer delivery, and BGP provider mutations were not rerun for this remediation.

### Documentation review — 2026-10-05

The README, CLI help, API documentation, source/test comments, and project review records were checked against the implementation. Corrected descriptions cover startup interval clamping, passive transmission, authentication discard, packet-generation sequence advancement, BGP queue supersession, MI timeout/cleanup limits, and SCM status versus protocol readiness. Shutdown attempts one AdminDown packet when the role permits; it does not transmit for a full detection period. The archived matrix is explicitly historical, and instruction-file skill paths now name the actual directories.

Verification at that revision passed: `cargo fmt --check`, `cargo doc --locked --offline --no-deps` with `RUSTDOCFLAGS=-D warnings`, and `cargo test --locked --offline --doc` (one compile-fail doctest). Generated `--help` was checked against the README; all 23 application options at that revision were covered. Local Markdown file links resolved. Comparing source files with comments removed confirmed that the 2026-10-05 Rust edits changed only documentation. The subsequent registry configuration change replaces those application options with registry values, retaining `--console`.
