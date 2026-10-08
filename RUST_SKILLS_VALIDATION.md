# Rust skills validation — current guide

Updated 2026-10-08. This guide describes the current API and validation workflow, using the local [Rust skill](.codex/skills/rust-skills/SKILL.md). The [correctness review](CODE_REVIEW.md) records fixes, checks, and validation limits. The [2026-10-01 audit](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) preserves the original 265-rule matrix; its defect examples, source hashes, rule counts, and test counts are historical.

## Technical documentation improvements — 2026-10-08

Applied the technical-documentation skill's audit recommendations. The README now introduces the service and links to focused setup, registry, logging, BGP, protocol, and development guides. Fresh-installation procedures distinguish startup, Windows service status, BFD readiness, and optional shutdown. Examples use explained placeholders, fit within 80 columns, and describe expected results. The registry reference covers all 22 supported settings; the logging reference covers all nine manifest events. Historical review statements are dated rather than presented as current configuration instructions.

Added descriptions for 33 public enum variants and fields. Rust source comparison after removing API comments confirmed unchanged executable code. Validation passed: 77 tests (66 library, 2 service, 7 Windows UDP integration, and 2 doctests), with one opt-in CIM schema test ignored; formatting; strict Clippy including undocumented unsafe blocks; and Rust documentation with warnings and missing public descriptions denied. Local Markdown links and anchors resolved, all 28 PowerShell samples parsed, and sample lines fit within 80 columns. The examples were parsed without executing installation, registry provisioning, or removal commands. Live service deployment, Event Viewer delivery, and BGP provider mutations were not exercised.

## Resolved public API findings

- **F1:** Authentication kind and key are private. `AuthConfig::kind()` exposes the type without mutation; changing authentication requires constructing a new validated configuration. A compile-fail doctest checks that the kind cannot be assigned directly.
- **F2:** `Options::validate` checks numeric ranges and option combinations, normalizes the multihop shortcut, and returns validated authentication. `Session::new` returns a `Result` and requires matching options/authentication. Session state, discriminators, and Poll tracking are read-only outside the crate. `Engine::open` validates configuration before opening sockets. The lower-level `Transport::open` checks numeric ranges only; direct callers must first normalize and fully validate their options.

Options remain publicly mutable, so callers must validate again after changing them. `ControlPacket::encode` serializes public header fields without validating them; decoding and authentication verification provide receive-side checks.

`CommandLine` parses only `--console` plus standard help/version flags. `Options::new` constructs defaults for explicit local/peer addresses; it does not validate them. On Windows, `config::load_registry` reads the service's HKLM Parameters key without creating or modifying it. Startup then calls `Options::validate` before opening sockets. The loader enforces `REG_SZ`/`REG_DWORD`, checks numeric narrowing, rejects invalid Booleans and malformed UTF-16, and excludes authentication contents from errors. Native loader tests use unique temporary HKCU keys rather than the installed service's configuration.

`Multihop` is the only registry transport selector: absent or DWORD `0` selects single-hop; DWORD `1` selects multihop. Other values and types fail loading. The former `Mode` registry value is ignored. The loader sets the internal transport profile before returning options; library callers can still use the `Mode` enum directly.

The 2026-10-08 selector change passed 72 default tests (61 library, 2 service, 7 UDP, and 2 doctests), with one opt-in CIM schema test ignored. The native regression verifies absent/0/1 selection and ignored legacy `Mode` entries; existing type/range tests reject malformed `Multihop` settings. Formatting, strict Clippy, rustdoc with warnings denied, and the release build passed. Tests used temporary HKCU keys; the installed service's configuration was not modified.

`LogFilePath` is a `REG_SZ` path, defaulting to `C:\ProgramData\BfdWinService\trace.log`. `LogToFile` is a `REG_DWORD` flag, defaulting to `0`. Startup reads both values; disabled logging never opens, creates, or writes the path. With DWORD `1`, each logger creates missing parent directories and opens the file for append. This applies to the main logger and the BGP worker. Folder creation and file-open failures propagate as startup errors; runtime write failures remain best-effort diagnostics.

The administrator-only [logging setup script](scripts/Initialize-Logging.ps1) provisions the default registry values and folder separately from the read-only runtime loader. It disables file output and does not create or write `trace.log`.

The 2026-10-08 file-logging change passed 76 default tests (65 library, 2 service, 7 UDP, and 2 doctests), with the opt-in CIM schema test ignored. The missing-parent regression failed with Windows error 3 before implementation, then passed with directory creation and append behavior. Additional regressions verify that disabled logging leaves existing, missing, and blocked paths untouched; enabled parent-directory errors are returned; registry paths are read independently of the flag; and malformed flag values/types are rejected. Formatting, strict Clippy, rustdoc with warnings denied, and the release build passed. These tests use temporary directories and HKCU keys.

File log entries use `YYYY-MM-DDTHH:mm:ss.sssZ` timestamps sampled immediately before writing. The Windows [GetSystemTime API](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime) supplies UTC fields without local timezone conversion. Each line of a multiline message receives the same entry timestamp, including blank lines and CRLF messages. The regression failed against Unix-millisecond output before implementation, then passed. The 2026-10-08 timestamp change passed 77 default tests (66 library, 2 service, 7 UDP, and 2 doctests), with the opt-in schema test ignored, plus formatting, strict Clippy, rustdoc with warnings denied, and the release build.

## Ownership and concurrency boundaries

Session reception verifies authentication before modifying state, timers, or sequence tracking. Verification returns a sequence for the session to commit; verification alone does not update tracking. Transport peer/path checks happen before session processing in the runtime.

The MI wrappers own their native handles, keep them on the calling thread, and release children before their session/application. Borrowed MI result data is consumed before the next result fetch or operation close. Normal retrieval drains results; error cleanup attempts cancellation and draining and logs failures. Native cleanup can block.

BGP provider calls run on a separate worker outside the mailbox mutex. The mailbox holds at most a Stop/Start pair; Down/AdminDown discard queued recovery. Start checks for supersession before and after its status query, but the subsequent call is not atomic with packet processing. An in-flight call finishes before the next action. Shutdown waits for pending Stop attempts and propagates a failed final Stop; the requested MI timeout is not a hard shutdown deadline.

The unsafe ancillary parser checks buffer bounds before unaligned reads. Its synthetic unit tests run under Miri without using Winsock. Miri cannot verify actual Winsock, registry, ETW, or `mi.dll` execution. Console logging has a subprocess test verifying lifecycle and failure messages reach STDOUT, leave STDERR empty, and run without ETW registration; subprocess tests are excluded under Miri.

## Check the current checkout

On Windows with the MSVC toolchain and Windows SDK installed:

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- `
    -D warnings -D clippy::undocumented_unsafe_blocks
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --locked --no-deps
```

The native schema test is opt-in because it requires CIM namespace access:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

Follow the [development guide](docs/development.md) for Miri checks and [Set up a BFD session](docs/setup.md) for deployment. Recorded test totals in the correctness review apply to that review's checks, not automatically to future revisions. Actual BGP Start/Stop and SCM lifecycle behavior need validation on a provisioned Windows Server; local fixtures do not establish provider behavior.

Registry configuration checks on 2026-10-07 passed: 69 tests including the doctest, with one opt-in native schema test ignored; formatting; strict Clippy including undocumented unsafe blocks; documentation with warnings denied; and the release build. Seven configuration tests passed under Miri with strict provenance, and the final string decoder was checked again after the parity-check lint correction. Release smoke checks confirmed that help exposes only `--console` plus help/version, removed configuration arguments are rejected, and a missing Parameters key produces exit code 1 with lifecycle/failure messages on STDOUT and empty STDERR. No installed service configuration was modified.

No full 265-rule reassessment or complete Rust skill compliance is claimed. The crate still uses string-based configuration errors, does not declare an MSRV, and has no checked-in CI workflow. These are guideline gaps rather than confirmed runtime defects.

## Code and documentation review — 2026-10-07

The complete service source, tests, build configuration, manifest, and documentation were reviewed against the registry/ETW implementation and relevant Rust skill rules. That review recorded a P2 finding: console STDOUT errors could panic and bypass AdminDown/BGP Stop cleanup or terminate the BGP worker. A standalone Windows closed-pipe probe reproduced the logger panic. The initial review changed documentation only; the finding was subsequently fixed by the rust-check remediation described below and in the [correctness review](CODE_REVIEW.md).

Documentation corrections also cover `LogFile` path handling, lifecycle Mode rendering, generic discard/send logging conditions, and the historical scope of the earlier CLI compatibility and validation results. The default 69 tests and strict Clippy passed again during this review; the opt-in schema test was ignored. Formatting, rustdoc with warnings denied, release help, and all 310 local Markdown file links passed their checks after the edits. A source comparison with API comments removed confirmed unchanged production code. Native service deployment, Event Viewer rendering, and real BGP mutations remain outside these checks.

## rust-check remediation — 2026-10-07

Applied [.codex/skills/rust-check/SKILL.md](.codex/skills/rust-check/SKILL.md). Console output now uses fallible writes and disables the failed destination per logger, preserving file output and engine/BGP cleanup. Logger STDERR diagnostics are best-effort. A subprocess regression reproduced the old failure before implementation and now verifies successful engine shutdown and continued file logging with a closed STDOUT pipe. Normal console output still has a separate subprocess regression.

Internal receive rejections derive `thiserror::Error`, while the existing public error APIs remain compatible. `Received` derives the applicable value traits. Imports, automatic error conversion, and SDK lookup were simplified. File fixtures use `tempfile`; subprocess assertions use `assert_cmd`. These targeted changes follow the skill's minimal-change guidance; the existing Winsock polling loop and MI worker do not require an async-runtime migration.

Required formatting and strict Clippy passed. The default test suite passed 71 tests, including the new regression and logger example, with one opt-in schema test ignored. The closed-pipe regression additionally passed with STDERR closed, confirming unavailable diagnostics do not interrupt cleanup. Rustdoc with warnings denied, the release build, release help, all 311 local documentation links, and `git diff --check` passed. Full Miri, live service deployment, Event Viewer delivery, and BGP provider mutations were not rerun for this remediation.

## Documentation review — 2026-10-05

The README, CLI help, API documentation, source/test comments, and project review records were checked against the implementation. Corrected descriptions cover startup interval clamping, passive transmission, authentication discard, packet-generation sequence advancement, BGP queue supersession, MI timeout/cleanup limits, and SCM status versus protocol readiness. Shutdown attempts one AdminDown packet when the role permits; it does not transmit for a full detection period. The archived matrix is explicitly historical, and instruction-file skill paths now name the actual directories.

Verification at that revision passed: `cargo fmt --check`, `cargo doc --locked --offline --no-deps` with `RUSTDOCFLAGS=-D warnings`, and `cargo test --locked --offline --doc` (one compile-fail doctest). Generated `--help` was checked against the README; all 23 application options at that revision were covered. Local Markdown file links resolved. Comparing source files with comments removed confirmed that the 2026-10-05 Rust edits changed only documentation. The subsequent registry configuration change replaces those application options with registry values, retaining `--console`.
