# Rust skills validation — current guide

Cowabunga, validation crew. Bring the receipts for the checkout you inspect.
Updated 2026-10-21. Rust maintainers, let's get the validation lineup dialed in.
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
checks before shouting Cowabunga for this checkout. The [alignment audit](docs/alignment-audit-2026-10-21.md) records
its baseline, corrections, and validation separately.

Use these implementation details when an older entry describes a superseded
design:

- Production releases omit Rust debug information, symbols, and linker PDBs.
  Development and ASan retain Rust debug information. The RPC stubs and C bridge
  compile with MSVC; the ASan wrapper also instruments maintained C and generated
  stubs and verifies emitted hooks. Windows system DLLs and the prebuilt MSVC
  runtime remain uninstrumented. See
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
  provide repeatable build inputs and release checks. The workflow runs on
  pull requests, main-branch pushes, tags, and manual dispatch, with separate
  native/Rust ASan and four-target fuzz jobs. Miri remains a local opt-in check.
  See [development checks](CONTRIBUTING.md#run-development-checks).

## Current API and validation

Keep the active API guidance ready to kick shell. Use these sections for
checkout commands and API contracts. Earlier test counts and implementation
receipts are preserved in the linked archive.

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

No full 265-rule reassessment or complete Rust skill compliance is claimed. The
string-based configuration errors noted in that registry review have since been
replaced by typed enums. The crate pins its nightly toolchain. The current
workflow checks optimized tests, Clippy, production hardening, native/Rust ASan,
fuzzing, MSI installation, upgrade, and rollback on the supported triggers above.

### Resolved public API findings

- **F1:** Authentication kind and key are private. `AuthConfig::kind()` exposes the type without mutation; changing authentication requires constructing a new validated configuration. A compile-fail doctest checks that the kind cannot be assigned directly.
- **F2:** `Options::into_validated` checks numeric ranges, endpoint source policy, and option combinations, then creates an immutable `ValidatedOptions` snapshot. Its `ProtocolRole` contains required nonzero S-BFD identifiers. The runtime shares this snapshot between components, while live timers and maintenance state remain separate. Raw constructors, including `Transport::open`, perform full validation. Session state, discriminators, and Poll tracking are read-only outside the crate.

Raw `Options` remain publicly mutable; consume them into a new validated snapshot after changing them. `ControlPacket::encode` serializes public header fields without validating them; decoding and authentication verification provide receive-side checks. Public configuration, packet, authentication, and receive errors use typed enums.

`CommandLine` parses only `--console` plus standard help/version flags. `Options::new` constructs defaults for explicit local/peer addresses; it does not validate them. On Windows, `config::load_registry` reads the service's HKLM Parameters key without creating or modifying it and returns a validated snapshot before sockets open. The loader enforces `REG_SZ`/`REG_DWORD`, checks numeric narrowing, rejects invalid Booleans and malformed UTF-16, and excludes authentication contents from errors. Native loader tests use unique temporary HKCU keys rather than the installed service's configuration.

`Multihop` is the only registry transport selector: absent or DWORD `0` selects single-hop; DWORD `1` selects multihop. Other values and types fail loading. The former `Mode` registry value is ignored. The loader sets the internal transport profile before returning options; library callers can still use the `Mode` enum directly.

`LogFilePath` is a `REG_SZ` path, defaulting to `C:\ProgramData\BfdWinService\trace.log`. `LogToFile` is a `REG_DWORD` flag, defaulting to `0`. Startup reads both values; disabled logging never opens, creates, or writes the path. With DWORD `1`, the startup logger creates missing parent directories and opens one append file shared by engine, BGP, and service supervisor messages. Folder creation and file-open failures propagate as startup errors; runtime write failures remain best-effort diagnostics.

The administrator-only [logging setup script](scripts/Initialize-Logging.ps1) provisions the default registry values and folder separately from the read-only runtime loader. It disables file output and does not create or write `trace.log`.

File log entries use `YYYY-MM-DDTHH:mm:ss.sssZ` timestamps sampled immediately before writing. The Windows [GetSystemTime API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime) supplies UTC fields without local timezone conversion. Each line of a multiline message receives the same entry timestamp, including blank lines and CRLF messages.

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

The [2026-10-21 baseline archive](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md)
preserves the dated 2026-10-05 through 2026-10-15 records, including their original
counts and superseded implementation descriptions. The
[2026-10-01 matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) retains the
original 265-rule review. The following anchors preserve existing links.

<a id="local-rpc-security-validation--2026-10-15"></a>

### Local RPC security validation — 2026-10-15

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#local-rpc-security-validation--2026-10-15).

<a id="state-and-diagnostic-logging-validation--2026-10-08"></a>

### State and diagnostic logging validation — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#state-and-diagnostic-logging-validation--2026-10-08).

<a id="rfc-5880-validation--2026-10-08"></a>

### RFC 5880 validation — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rfc-5880-validation--2026-10-08).

<a id="rust-security-fixes--2026-10-08"></a>

### rust-security fixes — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rust-security-fixes--2026-10-08).

<a id="expanded-hardening-review--2026-10-08"></a>

### Expanded hardening review — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#expanded-hardening-review--2026-10-08).

<a id="exception-handling-hardening--2026-10-08"></a>

### Exception handling hardening — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#exception-handling-hardening--2026-10-08).

<a id="control-packets-and-state-signaling--2026-10-08"></a>

### Control packets and state signaling — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#control-packets-and-state-signaling--2026-10-08).

<a id="windows-build-hardening--2026-10-08"></a>

### Windows build hardening — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#windows-build-hardening--2026-10-08).

<a id="ip-routed-seamless-bfd--2026-10-08"></a>

### IP-routed Seamless BFD — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#ip-routed-seamless-bfd--2026-10-08).

<a id="technical-documentation-improvements--2026-10-08"></a>

### Technical documentation improvements — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#technical-documentation-improvements--2026-10-08).

<a id="code-and-documentation-review--2026-10-07"></a>

### Code and documentation review — 2026-10-07

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#code-and-documentation-review--2026-10-07).

<a id="rust-check-remediation--2026-10-07"></a>

### rust-check remediation — 2026-10-07

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rust-check-remediation--2026-10-07).

<a id="documentation-review--2026-10-05"></a>

### Documentation review — 2026-10-05

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#documentation-review--2026-10-05).
