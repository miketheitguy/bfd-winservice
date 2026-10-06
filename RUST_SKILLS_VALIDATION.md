# Rust skills validation — current guide

Updated 2026-10-05. This guide describes the current API and validation workflow, using the local [Rust skill](.codex/skills/rust-skills/SKILL.md). The [correctness review](CODE_REVIEW.md) records fixes, checks, and validation limits. The [2026-10-01 audit](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) preserves the original 265-rule matrix; its defect examples, source hashes, rule counts, and test counts are historical.

## Resolved public API findings

- **F1:** Authentication kind and key are private. `AuthConfig::kind()` exposes the type without mutation; changing authentication requires constructing a new validated configuration. A compile-fail doctest checks that the kind cannot be assigned directly.
- **F2:** `Options::validate` checks numeric ranges and option combinations, normalizes the multihop shortcut, and returns validated authentication. `Session::new` returns a `Result` and requires matching options/authentication. Session state, discriminators, and Poll tracking are read-only outside the crate. `Engine::open` validates configuration before opening sockets. The lower-level `Transport::open` checks numeric ranges only; direct callers must first normalize and fully validate their options.

Options remain publicly mutable, so callers must validate again after changing them. `ControlPacket::encode` serializes public header fields without validating them; decoding and authentication verification provide receive-side checks.

## Ownership and concurrency boundaries

Session reception verifies authentication before modifying state, timers, or sequence tracking. Verification returns a sequence for the session to commit; verification alone does not update tracking. Transport peer/path checks happen before session processing in the runtime.

The MI wrappers own their native handles, keep them on the calling thread, and release children before their session/application. Borrowed MI result data is consumed before the next result fetch or operation close. Normal retrieval drains results; error cleanup attempts cancellation and draining and logs failures. Native cleanup can block.

BGP provider calls run on a separate worker outside the mailbox mutex. The mailbox holds at most a Stop/Start pair; Down/AdminDown discard queued recovery. Start checks for supersession before and after its status query, but the subsequent call is not atomic with packet processing. An in-flight call finishes before the next action. Shutdown waits for pending Stop attempts and propagates a failed final Stop; the requested MI timeout is not a hard shutdown deadline.

The unsafe ancillary parser checks buffer bounds before unaligned reads. Its synthetic unit tests run under Miri without using Winsock. Miri cannot verify actual Winsock or `mi.dll` execution.

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

No full 265-rule reassessment or complete Rust skill compliance is claimed. The crate still uses string-based configuration errors, does not declare an MSRV, and has no checked-in CI workflow. These are guideline gaps rather than confirmed runtime defects.

## Documentation review — 2026-10-05

The README, CLI help, API documentation, source/test comments, and project review records were checked against the implementation. Corrected descriptions cover startup interval clamping, passive transmission, authentication discard, packet-generation sequence advancement, BGP queue supersession, MI timeout/cleanup limits, and SCM status versus protocol readiness. Shutdown attempts one AdminDown packet when the role permits; it does not transmit for a full detection period. The archived matrix is explicitly historical, and instruction-file skill paths now name the actual directories.

Verification passed: `cargo fmt --check`, `cargo doc --locked --offline --no-deps` with `RUSTDOCFLAGS=-D warnings`, and `cargo test --locked --offline --doc` (one compile-fail doctest). Generated `--help` was checked against the README; all 23 application options are covered. Local Markdown file links resolve. Comparing source files with comments removed confirmed that Rust edits change only documentation; CLI help text is updated through those comments.
