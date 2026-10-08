# Rust skills validation — current guide

Updated 2026-10-07. This guide describes the current API and validation workflow, using the local [Rust skill](.codex/skills/rust-skills/SKILL.md). The [correctness review](CODE_REVIEW.md) records fixes, checks, and validation limits. The [2026-10-01 audit](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) preserves the original 265-rule matrix; its defect examples, source hashes, rule counts, and test counts are historical.

## Resolved public API findings

- **F1:** Authentication kind and key are private. `AuthConfig::kind()` exposes the type without mutation; changing authentication requires constructing a new validated configuration. A compile-fail doctest checks that the kind cannot be assigned directly.
- **F2:** `Options::validate` checks numeric ranges and option combinations, normalizes the multihop shortcut, and returns validated authentication. `Session::new` returns a `Result` and requires matching options/authentication. Session state, discriminators, and Poll tracking are read-only outside the crate. `Engine::open` validates configuration before opening sockets. The lower-level `Transport::open` checks numeric ranges only; direct callers must first normalize and fully validate their options.

Options remain publicly mutable, so callers must validate again after changing them. `ControlPacket::encode` serializes public header fields without validating them; decoding and authentication verification provide receive-side checks.

`CommandLine` parses only `--console` plus standard help/version flags. `Options::new` constructs defaults for explicit local/peer addresses; it does not validate them. On Windows, `config::load_registry` reads the service's HKLM Parameters key without creating or modifying it. Startup then calls `Options::validate` before opening sockets. The loader enforces `REG_SZ`/`REG_DWORD`, checks numeric narrowing, rejects invalid Booleans and malformed UTF-16, and excludes authentication contents from errors. Native loader tests use unique temporary HKCU keys rather than the installed service's configuration.

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
cargo clippy --locked --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks
$env:RUSTDOCFLAGS = '-D warnings'
cargo doc --locked --no-deps
```

The native schema test is opt-in because it requires CIM namespace access:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

Follow the [README](README.md) for Miri and deployment instructions. Recorded test totals in the correctness review apply to that review's checks, not automatically to future revisions. Actual BGP Start/Stop and SCM lifecycle behavior need validation on a provisioned Windows Server; local fixtures do not establish provider behavior.

Registry configuration checks on 2026-10-07 passed: 69 tests including the doctest, with one opt-in native schema test ignored; formatting; strict Clippy including undocumented unsafe blocks; documentation with warnings denied; and the release build. Seven configuration tests passed under Miri with strict provenance, and the final string decoder was checked again after the parity-check lint correction. Release smoke checks confirmed that help exposes only `--console` plus help/version, removed configuration arguments are rejected, and a missing Parameters key produces exit code 1 with lifecycle/failure messages on STDOUT and empty STDERR. No installed service configuration was modified.

No full 265-rule reassessment or complete Rust skill compliance is claimed. The crate still uses string-based configuration errors, does not declare an MSRV, and has no checked-in CI workflow. These are guideline gaps rather than confirmed runtime defects.

## Documentation review — 2026-10-05

The README, CLI help, API documentation, source/test comments, and project review records were checked against the implementation. Corrected descriptions cover startup interval clamping, passive transmission, authentication discard, packet-generation sequence advancement, BGP queue supersession, MI timeout/cleanup limits, and SCM status versus protocol readiness. Shutdown attempts one AdminDown packet when the role permits; it does not transmit for a full detection period. The archived matrix is explicitly historical, and instruction-file skill paths now name the actual directories.

Verification at that revision passed: `cargo fmt --check`, `cargo doc --locked --offline --no-deps` with `RUSTDOCFLAGS=-D warnings`, and `cargo test --locked --offline --doc` (one compile-fail doctest). Generated `--help` was checked against the README; all 23 application options at that revision were covered. Local Markdown file links resolved. Comparing source files with comments removed confirmed that the 2026-10-05 Rust edits changed only documentation. The subsequent registry configuration change replaces those application options with registry values, retaining `--console`.
