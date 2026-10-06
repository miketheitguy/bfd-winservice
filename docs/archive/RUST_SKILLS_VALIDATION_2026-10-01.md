# Rust skills validation — historical snapshot (2026-10-01)

**Archived audit, not an assessment of the current code.** The findings, examples, source hashes, rule statuses, and test counts below describe the 2026-09-30/2026-10-01 implementation. F1 and F2 were subsequently fixed; use [the current correctness review](../../CODE_REVIEW.md) and [validation guide](../../RUST_SKILLS_VALIDATION.md) for the current state. Source links resolve to current files, so historical line anchors may no longer identify the original code. This 265-rule matrix has not been reassessed.

Initial audit: 2026-09-30. Miri revalidation: 2026-10-01. Scope: the entire service crate, its tests, Cargo manifest/lockfile, and README. The revalidation adds three ancillary-parser unit tests and Miri instructions; production behavior is unchanged.

## Result

All 265 rules referenced by the local [rust-skills catalog](../../.codex/skills/rust-skills/SKILL.md) were assessed across all 26 categories. No `SKILLS.md` exists in this workspace; the active `SKILL.md` is the actual catalog. All referenced rule files exist. The vendored skill's illustrative code and its separate checks crate are reference material, not service targets.

The standard checks pass. Miri now passes all 21 library tests with strict provenance, including the unsafe ancillary parser; its three focused tests also pass with Tree Borrows. Native testing passes all 26 tests. Two public-library validation defects from the initial audit remain open. No P0/P1 ownership, borrowing, or memory-safety defect was identified in the tested paths. Native Winsock operations remain outside Miri's supported execution paths. The codebase does not yet fully satisfy the applicable guidelines.

The matrix records 80 Pass, 115 N/A, 36 Recommendation, 34 Gap, and 0 Unverified assessments. The previous Unverified Miri rule is now a Gap because local tests pass but CI automation is absent. Multiple rules refer to the same underlying issue; 34 Gap rows do not mean 34 independent defects. The zero Unverified rows do not imply that every native FFI path was interpreted by Miri; see the validation limits.

| Status | Meaning | Rules |
|---|---|---:|
| Pass | Applicable guidance satisfied by inspection and/or the recorded check. | 80 |
| N/A | The relevant construct or deployment requirement is absent. | 115 |
| Recommendation | Conditional improvement; measurement or API goals should justify it. | 36 |
| Gap | Applicable guideline is not fully met; this is not automatically a runtime bug. | 34 |
| Unverified | Applicable check could not be attempted or assessed. | 0 |

## Confirmed defects

### F1 — P2: changing authentication type invalidates key bounds and can panic

Locations: [public authentication type](../../src/packet.rs#L54), [constructor validation](../../src/packet.rs#L60), and [verification key copy](../../src/packet.rs#L126).

`AuthConfig::new` accepts a 20-byte SHA-1 key. Its public `kind` field can subsequently be changed to keyed MD5, whose hash field is only 16 bytes. Encoding produces a 48-byte MD5 packet, then `verify` copies the unchanged 20-byte key into `signed[32..52]`, indexing beyond the packet. The API returns `Result`, but this legal sequence of safe public calls panics.

Reproduction, after importing the packet types:

```rust
let mut auth = AuthConfig::new(AuthType::KeyedSha1, 0, vec![1; 20]).unwrap();
auth.kind = AuthType::KeyedMd5;
let packet = ControlPacket {
    diagnostic: 0, state: State::Down, poll: false, final_bit: false,
    control_plane_independent: false, demand: false, detect_mult: 3,
    my_discriminator: 7, your_discriminator: 0,
    desired_min_tx_us: 1_000_000, required_min_rx_us: 300_000,
    required_min_echo_rx_us: 0,
};
let wire = packet.encode(&auth, 0);
let _ = auth.verify(&wire, None); // panics
```

The probe observed `Mutating validated SHA1 config to MD5 causes verify panic: true`. Current CLI/service startup does not mutate `kind`, so the reproduced failure is in the exported library API. It was not demonstrated as a remotely triggered service crash.

Recommended correction: make `kind` private with a read-only accessor, and construct or change an authentication configuration only through a fallible operation that validates the type/key combination. Retain a regression test for the invariant.

### F2 — P2: public session options bypass numeric validation

Locations: [CLI-only range checks](../../src/config.rs#L51), [Options::validate](../../src/config.rs#L99), [Session::new](../../src/session.rs#L34), and [packet generation](../../src/session.rs#L202).

The numeric constraints are declared in Clap's argument parsers. `Options` exposes these values publicly, but `validate` does not repeat their checks, and `Session::new` accepts raw `Options` without validation. A library caller can parse otherwise valid options, set `detect_mult = 0` and `discriminator = Some(0)`, pass `validate`, and emit an invalid BFD packet.

```rust
let mut options = Options::try_parse_from([
    "bfd", "--local", "127.0.0.1", "--peer", "127.0.0.2",
    "--mode", "multihop",
]).unwrap();
options.detect_mult = 0;
options.discriminator = Some(0);
let auth = options.validate().unwrap();
let mut session = Session::new(options, auth);
let wire = session.packet(false);
assert_eq!(wire[2], 0);
assert_eq!(u32::from_be_bytes(wire[4..8].try_into().unwrap()), 0);
assert!(ControlPacket::decode(&wire).is_err());
```

The compiled probe emitted multiplier 0 and discriminator 0; decoding returned `Err("zero detection multiplier")`. CLI parsing rejects these settings, so this is another exported-library boundary defect.

Recommended correction: separate raw CLI options from an opaque validated session configuration, enforce every range at the conversion boundary, and require that type in session/engine construction. Keep invariant-bearing session fields private with accessors; `local_discriminator` is also currently publicly writable.

## Guideline gaps and recommendations

### G1 — domain error types and operational context

[Configuration](../../src/config.rs#L99), [packet/authentication](../../src/packet.rs#L84), and [session](../../src/session.rs#L108) APIs identify errors with `String` or `&'static str`. They do not expose typed variants implementing `std::error::Error`. [Transport startup](../../src/transport.rs#L121) and [log-file opening](../../src/runtime.rs#L15) propagate raw I/O errors without identifying the failed operation, address, interface, or path.

Introduce typed library errors, using `thiserror` or manual `Error` implementations, preserve underlying causes, and attach useful context at the application boundary. `Box<dyn Error>` itself is reasonable for heterogeneous application failures; the problem is insufficient context and domain error identity.

### G2 — incomplete public API documentation

The expanded production audit reports 87 `missing_docs`, 13 `missing_errors_doc`, and 1 `missing_panics_doc` warnings. [lib.rs](../../src/lib.rs) has no crate documentation, and many public types, variants, fields, and methods are undocumented. No executable API examples exist: the test command ran zero doctests.

Complete crate/module/public API documentation with examples and appropriate Errors sections. Fix F1 rather than documenting an avoidable public panic. Describe any intentional invariant-related panic where applicable. Add intra-doc links as useful cross-references; do not expose authentication secrets in examples or Debug implementations.

### G3 — strict unsafe comments, unwrap, and narrowing conversions

The IPv4 and IPv6 union accesses at [transport.rs:333](../../src/transport.rs#L333) and [transport.rs:339](../../src/transport.rs#L339) lack adjacent comments for their individual unsafe blocks. Nearby comments explain the enclosing `read_unaligned` operations and union validity, so this is a documentation gap rather than demonstrated undefined behavior.

The ancillary TTL parser has one [production unwrap](../../src/transport.rs#L326). Its preceding four-byte guard establishes the conversion length, so the current operation is safe; an invariant-describing expect or explicit conversion would meet the stricter guideline.

Sixteen possible-truncation lint warnings concern packet/auth lengths, jitter nanoseconds, native socket handles/sizes, bounded polling time, and source-port selection. Manual review found these bounded or intentional for the current platform; the warnings were not treated as 16 truncation bugs. Prefer checked conversion for narrowing values and document platform-width conversions.

Manual memory/numeric review covered:

- Synchronous Winsock calls do not retain pointers beyond initialized stack buffers; no project-written unsafe Send/Sync exists.
- Ancillary buffers use native alignment, checked record lengths, and unaligned reads; returned byte/control lengths are checked before slicing.
- Valid immutable authentication configs produce packets of at most 52 bytes. F1 is a safe-Rust invariant failure, not an unsafe memory access.
- Maximum detection-time multiplication is `u32::MAX * 255 = 1,095,216,660,225` microseconds, within u64; doubling remains within range.
- Jitter multiplication is performed in u128, source-port selection remains within 49152..65535, and poll milliseconds are capped before conversion.

### G4 — logging differs from the observability guidelines

[Logger](../../src/runtime.rs#L9) writes interpolated text directly to stderr/files from the exported library. It provides neither a standard logging facade nor structured fields/severity filtering. Service failures may be reported at multiple boundaries.

For reusable library behavior, emit through a logging/tracing facade and configure sinks in the binary. Record peer/state/discriminator/timers as fields and choose a single owner for reporting terminal errors. Preserve the current deliberate exclusion of key material; any Debug or automatic instrumentation must redact secrets.

### G5 — persistent safety checks, MSRV, and test cleanup

The service has no CI configuration, persistent guideline lint selection, declared `rust-version`, or Miri job. Local Miri validation now passes; the remaining `unsafe-miri-ci` gap is automation. The local checks validate this toolchain, not a supported-version/platform matrix. No retained property-testing suite covers arbitrary packet input.

[RunningEngine](../../tests/windows_udp.rs#L60) correctly stops/joins in Drop for two tests, but the [older handshake test](../../tests/windows_udp.rs#L173) manually joins only on its successful path. On assertion panic the stop sender closes, which should eventually stop the engine, but the dropped JoinHandle does not guarantee worker completion before test teardown.

Recommended follow-up: adopt the RAII fixture throughout engine tests, retain bounded parser properties/regressions, declare and test an MSRV, and automate Windows tests, formatting, selected Clippy checks, and suitable Miri unit tests.

### Conditional performance/API improvements

Packet encode/receive and keyed authentication allocate small buffers repeatedly. Options is cloned into both Engine and Session, including authentication strings retained after key parsing. Reserve complete packet capacity, separate operational settings from CLI secrets, and consider reusable or bounded inline buffers only after measuring a representative workload. No allocation or latency benchmark was run, and no improvement magnitude is claimed.

Public API ergonomics could benefit from intentional visibility, redacted Debug, selected must_use annotations, root re-exports, and distinct ID types. No Tokio, Rayon, Serde, builder framework, arena, or extra abstraction is required merely because its rules are in the catalog.

## Checks and evidence

Environment: `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`, target `x86_64-pc-windows-msvc`, edition 2021. The locally staged Windows CRT/SDK libraries and Rust's `rust-lld` were used as linker inputs; Cargo.toml/toolchain configuration was not changed.

Formatting, native tests, and default Clippy were rerun on 2026-10-01. Documentation, optimized build, expanded lint counts, and the bounded packet/authentication probes below are results from 2026-09-30; production code is unchanged.

| Check | Outcome |
|---|---|
| `cargo fmt --all -- --check` | Pass |
| `cargo test --locked --offline` | Pass: 21 unit + 5 Windows UDP integration tests; 0 doctests |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Pass for default lint groups |
| `cargo doc --locked --offline --no-deps` with `RUSTDOCFLAGS=-D warnings` | Pass; does not enable missing-docs checking |
| `cargo build --release --locked --offline --all-targets` | Pass, optimized build |
| Selected additional production documentation/safety/numeric lints | 120 warnings, detailed below |
| Public authentication mutation probe | F1 reproduced |
| Public options mutation probe | F2 reproduced |
| Bounded packet/authentication parser exercise | 98,496 cases completed without panic for valid immutable configs |
| `cargo +nightly miri --version` | Available: Miri 0.1.0, commit 21b707e3f9 (2026-09-30) |
| `cargo +nightly miri test --locked --offline --lib -- --test-threads=1` with strict provenance | Pass: all 21 library tests; no undefined behavior reported |
| Ancillary parser under strict provenance and Tree Borrows | Pass: all 3 focused tests; no undefined behavior reported |
| Windows UDP integration suite under Miri | Unsupported: interpreter stops at `WSAStartup`; all 5 tests pass natively |

Additional lint counts:

| Diagnostic | Count |
|---|---:|
| `missing_docs` | 87 |
| `clippy::missing_errors_doc` | 13 |
| `clippy::missing_panics_doc` | 1 |
| `clippy::undocumented_unsafe_blocks` | 2 |
| `clippy::unwrap_used` | 1 |
| `clippy::cast_possible_truncation` | 16 |
| Total | 120 |

The additional audit selected these warning-level checks for production library/binary targets (test unwraps are intentionally excluded):

```powershell
cargo clippy --locked --offline --lib --bins --no-deps --message-format=json -- `
  -W missing-docs -W clippy::missing-errors-doc -W clippy::missing-panics-doc `
  -W clippy::undocumented-unsafe-blocks -W clippy::unwrap-used `
  -W clippy::cast-possible-truncation -W clippy::cast-sign-loss `
  -W clippy::redundant-clone -W clippy::use-self `
  -W clippy::match-wildcard-for-single-variants -W clippy::unused-self `
  -W clippy::used-underscore-binding -W unsafe-op-in-unsafe-fn
```

Raw JSON diagnostics and temporary probes are under ignored `target/validation/` in this workspace. These files are supplementary local artifacts; the complete findings, reproduction snippets, and coverage matrix are retained in this report.

The parser exercise covered six valid authentication configurations, input lengths 0..512, and 32 deterministic cases per length/configuration (`6 * 513 * 32 = 98,496`). Cases included random bytes and mutated valid wire packets. It checked both decoding and authentication verification for panic freedom and checked valid round trips. It is bounded probing, not an exhaustive proof or a replacement for retained property tests.

Validation limits: no external router interoperability test, installed SCM lifecycle test, benchmark/profile, dependency vulnerability audit, Windows x86 build, or non-Windows build was performed during this audit. Windows loopback UDP tests exercised IPv4/IPv6 metadata and real engine traffic natively. Miri's interpreter rejects the UDP suite's `WSAStartup` call, so socket creation, native `WSARecvMsg`, and polling were not interpreted. Pure ancillary parsing is now tested directly under Miri. Interpreter results cover the exercised inputs and executions, not every possible safe API call ([official Miri documentation](https://github.com/rust-lang/miri)).

### Miri revalidation details — 2026-10-01

The installed nightly is `rustc 1.101.0-nightly (21b707e3f 2026-09-30)`. Miri required `rust-src` and a prepared sysroot; both are now available. The workspace's existing Rust linker and staged SDK libraries were used for setup, with the generated Miri sysroot under ignored `target/validation/miri-sysroot-windows`. The project's default toolchain remains stable.

Three new [ancillary-parser tests](../../src/transport.rs#L380) cover byte-offset alignment, IPv4/IPv6 address and interface unions, TTL/hop-limit fields, unknown record skipping, invalid/oversized native lengths, short metadata payloads, incomplete header/payload buffers, and an out-of-range TTL. Fixtures serialize native fields using checked slices and `offset_of!`, without adding unsafe test code. These tests invoke the production `read_control` function directly without opening sockets.

Commands for this workspace after setup:

```powershell
$nightlyRoot = rustc +nightly --print sysroot
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = Join-Path $nightlyRoot 'lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe'
$sdkRoot = Join-Path $PWD 'target/build-tools/sysroot'
$env:LIB = (@('crt/lib/x86_64', 'sdk/lib/ucrt/x86_64', 'sdk/lib/um/x86_64') | ForEach-Object { Join-Path $sdkRoot $_ }) -join ';'
$env:MIRI_SYSROOT = Join-Path $PWD 'target/validation/miri-sysroot-windows'
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
cargo +nightly miri test --locked --offline --lib -- --test-threads=1
$env:MIRIFLAGS = '-Zmiri-strict-provenance -Zmiri-tree-borrows'
cargo +nightly miri test --locked --offline --lib ancillary_metadata -- --test-threads=1
```

Logs: `target/validation/miri-windows-strict.log` (21 passed), `miri-windows-tree.log` (3 passed), and `miri-windows-ffi.log` (unsupported `WSAStartup`, not a detected service bug). The report's two API defects were not fixed by adding parser coverage.

A repeat run requested on 2026-10-01 confirmed the same results: 21 strict-provenance library tests, 3 Tree Borrows parser tests, and 26 native tests pass; default Clippy and formatting also pass. All nine Rust source hashes match this report's snapshot. The repeated UDP Miri attempt again stopped at unsupported `WSAStartup`. Additional logs are `target/validation/miri-windows-strict-rerun.log`, `miri-windows-tree-rerun.log`, and `miri-windows-ffi-rerun.log`.

## Source snapshot

All nine service/test Rust files were inspected. SHA-256 identifies the source state after the Miri revalidation; only transport.rs changed, by adding tests. A service Git worktree was not available at the workspace root.

| File | Lines | SHA-256 |
|---|---:|---|
| [tests/windows_udp.rs](../../tests/windows_udp.rs) | 407 | `739b664a7b9ea0c027fce053d8e35b0d5b9c9d0b98e14b0779d1fe5d793b6d05` |
| [src/transport.rs](../../src/transport.rs) | 632 | `06fa4414c1a8a308626709a32b778206458a2384f95d46e1b361f4252c62fdec` |
| [src/session.rs](../../src/session.rs) | 375 | `58ed7799e51c07bcd374950caa185a9d20af5e6b4597cbe6b9891c28caa6f0c2` |
| [src/service.rs](../../src/service.rs) | 102 | `30dc6a208feee924206fb1554d661bbba0ecb1304580dae29b0120ba7b2a9adc` |
| [src/runtime.rs](../../src/runtime.rs) | 188 | `098ad3d92d1f066ced4d57601353807d0f196dcd2b67108b4408de36a9afeae5` |
| [src/packet.rs](../../src/packet.rs) | 379 | `45ce6a45ad1bb44a4ec3e03ecd7855fd9adf52a99fa59d800839ea4c51b94427` |
| [src/main.rs](../../src/main.rs) | 49 | `f5d251ffc1a94ebdebbd035c6da6ecddcd129bea3f9ca859baec13df0bb32a67` |
| [src/lib.rs](../../src/lib.rs) | 8 | `914c6c03a77267cf422b19289ef53fbd58e52698e0ee744cdbffcb57f5e534e4` |
| [src/config.rs](../../src/config.rs) | 264 | `e9ee01bb62acff5909ec8dd4d8c1c5ce0dd6bafce1d58ee2d6172c44b01d3d72` |

## Category coverage

| Category | Rules | Pass | N/A | Recommendation | Gap | Unverified |
|---|---:|---:|---:|---:|---:|---:|
| Ownership & Borrowing | 12 | 4 | 6 | 2 | 0 | 0 |
| Error Handling | 12 | 3 | 0 | 3 | 6 | 0 |
| Memory Optimization | 17 | 3 | 5 | 9 | 0 | 0 |
| Unsafe Code | 7 | 2 | 3 | 0 | 2 | 0 |
| API Design | 17 | 3 | 8 | 4 | 2 | 0 |
| Async/Await | 18 | 0 | 18 | 0 | 0 | 0 |
| Concurrency | 4 | 1 | 3 | 0 | 0 | 0 |
| Compiler Optimization | 12 | 3 | 6 | 3 | 0 | 0 |
| Numeric & Arithmetic Safety | 5 | 2 | 1 | 0 | 2 | 0 |
| Type Safety | 13 | 5 | 4 | 1 | 3 | 0 |
| Trait & Generics Design | 6 | 2 | 4 | 0 | 0 | 0 |
| Conversions | 3 | 1 | 1 | 1 | 0 | 0 |
| Const & Compile-Time | 4 | 1 | 2 | 1 | 0 | 0 |
| Serde | 8 | 0 | 8 | 0 | 0 | 0 |
| Pattern Matching | 5 | 2 | 2 | 1 | 0 | 0 |
| Macros | 8 | 1 | 7 | 0 | 0 | 0 |
| Closures | 5 | 4 | 1 | 0 | 0 | 0 |
| Collections | 4 | 1 | 3 | 0 | 0 | 0 |
| Naming Conventions | 16 | 10 | 5 | 1 | 0 | 0 |
| Testing | 15 | 5 | 7 | 0 | 3 | 0 |
| Documentation | 12 | 1 | 4 | 2 | 5 | 0 |
| Observability | 7 | 1 | 1 | 0 | 5 | 0 |
| Performance Patterns | 13 | 6 | 5 | 2 | 0 | 0 |
| Project Structure | 14 | 3 | 8 | 2 | 1 | 0 |
| Clippy & Linting | 13 | 7 | 2 | 2 | 2 | 0 |
| Anti-patterns | 15 | 9 | 1 | 2 | 3 | 0 |
| Total | 265 | 80 | 115 | 36 | 34 | 0 |

## Complete rule matrix

Every catalog rule appears once below, in catalog order. Pass is an evidence-based assessment within this service's scope, not a universal proof. Recommendations are conditional; N/A rows describe why a rule is irrelevant. Rule links point to the exact local guidance used.

### Ownership & Borrowing

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [own-borrow-over-clone](../../.codex/skills/rust-skills/rules/own-borrow-over-clone.md) | Recommendation | Engine and Session both own cloned Options, including key strings; split operational settings to reduce duplication without adding shared ownership. |
| [own-slice-over-vec](../../.codex/skills/rust-skills/rules/own-slice-over-vec.md) | Pass | Packet and transport APIs accept byte slices; no borrowed Vec or String parameters. |
| [own-cow-conditional](../../.codex/skills/rust-skills/rules/own-cow-conditional.md) | N/A | No conditionally owned string/slice result; Cow would add no current benefit. |
| [own-arc-shared](../../.codex/skills/rust-skills/rules/own-arc-shared.md) | N/A | No shared mutable session ownership; configuration uses OnceLock and stop notifications use channels. |
| [own-rc-single-thread](../../.codex/skills/rust-skills/rules/own-rc-single-thread.md) | N/A | No shared mutable session ownership; configuration uses OnceLock and stop notifications use channels. |
| [own-refcell-interior](../../.codex/skills/rust-skills/rules/own-refcell-interior.md) | N/A | No shared mutable session ownership; configuration uses OnceLock and stop notifications use channels. |
| [own-mutex-interior](../../.codex/skills/rust-skills/rules/own-mutex-interior.md) | N/A | No shared mutable session ownership; configuration uses OnceLock and stop notifications use channels. |
| [own-rwlock-readers](../../.codex/skills/rust-skills/rules/own-rwlock-readers.md) | N/A | No shared mutable session ownership; configuration uses OnceLock and stop notifications use channels. |
| [own-copy-small](../../.codex/skills/rust-skills/rules/own-copy-small.md) | Pass | Mode, State, Diagnostic, and AuthType are small Copy enums; resource owners remain non-Copy. |
| [own-clone-explicit](../../.codex/skills/rust-skills/rules/own-clone-explicit.md) | Pass | Owned configuration/key duplication uses explicit Clone; socket/file owners are not implicitly copied. |
| [own-move-large](../../.codex/skills/rust-skills/rules/own-move-large.md) | Recommendation | Engine and Session both own cloned Options, including key strings; split operational settings to reduce duplication without adding shared ownership. |
| [own-lifetime-elision](../../.codex/skills/rust-skills/rules/own-lifetime-elision.md) | Pass | Borrowed signatures use elided lifetimes; no unnecessary lifetime parameters. |

### Error Handling

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [err-thiserror-lib](../../.codex/skills/rust-skills/rules/err-thiserror-lib.md) | Gap | Domain APIs return String or static string errors rather than typed std::error::Error enums; see G1. |
| [err-anyhow-app](../../.codex/skills/rust-skills/rules/err-anyhow-app.md) | Recommendation | Application boundaries use Box<dyn Error>; anyhow with operation context would improve diagnostics, but boxing itself is valid. |
| [err-result-over-panic](../../.codex/skills/rust-skills/rules/err-result-over-panic.md) | Gap | AuthConfig::verify can panic after a legal public-field mutation; see F1. |
| [err-context-chain](../../.codex/skills/rust-skills/rules/err-context-chain.md) | Gap | Socket/log startup propagates raw I/O errors without operation, endpoint, interface, or path context; see G1. |
| [err-no-unwrap-prod](../../.codex/skills/rust-skills/rules/err-no-unwrap-prod.md) | Gap | read_control uses one production unwrap after a four-byte length guard; safe invariant, but violates the strict no-unwrap rule; see G3. |
| [err-expect-bugs-only](../../.codex/skills/rust-skills/rules/err-expect-bugs-only.md) | Pass | Explicit expect calls describe internal packet bounds and the privately initialized WSARecvMsg pointer, not routine I/O failures. |
| [err-question-mark](../../.codex/skills/rust-skills/rules/err-question-mark.md) | Pass | Fallible parsing and I/O propagate with ?; explicit matches implement handling, conversion, or best-effort behavior. |
| [err-from-impl](../../.codex/skills/rust-skills/rules/err-from-impl.md) | Recommendation | Typed domain errors could implement From and Error::source; current String/static-string errors cannot form causal error chains; see G1. |
| [err-source-chain](../../.codex/skills/rust-skills/rules/err-source-chain.md) | Recommendation | Typed domain errors could implement From and Error::source; current String/static-string errors cannot form causal error chains; see G1. |
| [err-lowercase-msg](../../.codex/skills/rust-skills/rules/err-lowercase-msg.md) | Pass | Domain error messages begin lowercase without trailing punctuation; capitalized CLI/log prefixes are surrounding presentation. |
| [err-doc-errors](../../.codex/skills/rust-skills/rules/err-doc-errors.md) | Gap | Thirteen public fallible functions lack Errors documentation; see G2. |
| [err-custom-type](../../.codex/skills/rust-skills/rules/err-custom-type.md) | Gap | Domain APIs return String or static string errors rather than typed std::error::Error enums; see G1. |

### Memory Optimization

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [mem-with-capacity](../../.codex/skills/rust-skills/rules/mem-with-capacity.md) | Recommendation | Packet encoding starts a 24-byte Vec then appends authentication up to 52 bytes; reserve its complete bounded length. |
| [mem-smallvec](../../.codex/skills/rust-skills/rules/mem-smallvec.md) | Recommendation | Packets and keys are short and bounded; inline storage may help after measurement, but requires an API/storage tradeoff. |
| [mem-arrayvec](../../.codex/skills/rust-skills/rules/mem-arrayvec.md) | Recommendation | Packets and keys are short and bounded; inline storage may help after measurement, but requires an API/storage tradeoff. |
| [mem-box-large-variant](../../.codex/skills/rust-skills/rules/mem-box-large-variant.md) | N/A | Project enums contain no large payload variants. |
| [mem-boxed-slice](../../.codex/skills/rust-skills/rules/mem-boxed-slice.md) | Recommendation | AuthConfig's private key is fixed after construction; boxed slice or bounded inline storage could express that constraint. |
| [mem-thinvec](../../.codex/skills/rust-skills/rules/mem-thinvec.md) | N/A | No arrays of many mostly empty Vec headers; ThinVec has no demonstrated use. |
| [mem-clone-from](../../.codex/skills/rust-skills/rules/mem-clone-from.md) | N/A | No repeated clone assignment into an existing allocation. |
| [mem-reuse-collections](../../.codex/skills/rust-skills/rules/mem-reuse-collections.md) | Recommendation | Receive allocates a packet Vec; keyed authentication copies a packet and allocates a digest; reuse bounded buffers after profiling. |
| [mem-avoid-format](../../.codex/skills/rust-skills/rules/mem-avoid-format.md) | Recommendation | Logger callers allocate formatted messages and Logger allocates the final line; borrowed format_args/write! can reduce these allocations. |
| [mem-write-over-format](../../.codex/skills/rust-skills/rules/mem-write-over-format.md) | Recommendation | Logger callers allocate formatted messages and Logger allocates the final line; borrowed format_args/write! can reduce these allocations. |
| [mem-arena-allocator](../../.codex/skills/rust-skills/rules/mem-arena-allocator.md) | N/A | No bulk object graph with shared lifetime; arena allocation is unwarranted. |
| [mem-zero-copy](../../.codex/skills/rust-skills/rules/mem-zero-copy.md) | Recommendation | Receive allocates a packet Vec; keyed authentication copies a packet and allocates a digest; reuse bounded buffers after profiling. |
| [mem-compact-string](../../.codex/skills/rust-skills/rules/mem-compact-string.md) | N/A | No large collection of short Strings; compact string storage is not justified. |
| [mem-smaller-integers](../../.codex/skills/rust-skills/rules/mem-smaller-integers.md) | Pass | Wire fields use u8/u16/u32 as required; time products widen to u64 and jitter arithmetic to u128. |
| [mem-assert-type-size](../../.codex/skills/rust-skills/rules/mem-assert-type-size.md) | Recommendation | Native struct sizes/alignment are queried, but no compile-time layout assertions or size regression checks are retained. |
| [mem-take-replace](../../.codex/skills/rust-skills/rules/mem-take-replace.md) | Pass | RunningEngine takes its optional join handle before joining; no clone is needed to move it out. |
| [mem-drop-order](../../.codex/skills/rust-skills/rules/mem-drop-order.md) | Pass | Owned sockets/files use RAII; RunningEngine signals and joins its worker before releasing the test fixture. |

### Unsafe Code

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [unsafe-safety-comment](../../.codex/skills/rust-skills/rules/unsafe-safety-comment.md) | Gap | Two nested union access unsafe blocks lack their own adjacent SAFETY comments; outer reads are documented; see G3. |
| [unsafe-minimize-scope](../../.codex/skills/rust-skills/rules/unsafe-minimize-scope.md) | Pass | Unsafe is localized to Winsock calls, bounded raw reads, union accesses, and one checked raw slice. |
| [unsafe-miri-ci](../../.codex/skills/rust-skills/rules/unsafe-miri-ci.md) | Gap | Local strict-provenance Miri passes 21 library tests; the unsafe parser also passes 3 Tree Borrows tests. CI automation is still absent; native Winsock is unsupported. |
| [unsafe-maybeuninit](../../.codex/skills/rust-skills/rules/unsafe-maybeuninit.md) | Pass | Buffers are initialized arrays and SockAddr::try_init encapsulates native address initialization; no user MaybeUninit assume_init. |
| [unsafe-extern-block](../../.codex/skills/rust-skills/rules/unsafe-extern-block.md) | N/A | Project declares no custom extern block; native declarations come from windows-sys. |
| [unsafe-send-sync-manual](../../.codex/skills/rust-skills/rules/unsafe-send-sync-manual.md) | N/A | No project-written unsafe Send/Sync implementations; Send requirements are compiler-checked. |
| [unsafe-no-mangle-unsafe](../../.codex/skills/rust-skills/rules/unsafe-no-mangle-unsafe.md) | N/A | No project-written no_mangle/export_name attribute; service trampoline is provided by windows-service. |

### API Design

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [api-builder-pattern](../../.codex/skills/rust-skills/rules/api-builder-pattern.md) | Pass | Options is a named configuration parameter object, avoiding long positional constructors; a builder is not necessary for CLI construction. |
| [api-builder-must-use](../../.codex/skills/rust-skills/rules/api-builder-must-use.md) | N/A | No builder or consuming builder setters. |
| [api-newtype-safety](../../.codex/skills/rust-skills/rules/api-newtype-safety.md) | Gap | Public AuthConfig.kind and raw numeric Options fields allow validated invariants to be invalidated; see F1/F2. |
| [api-typestate](../../.codex/skills/rust-skills/rules/api-typestate.md) | N/A | BFD states are runtime peer input and are represented by State; compile-time typestate would not enforce peer transitions. |
| [api-sealed-trait](../../.codex/skills/rust-skills/rules/api-sealed-trait.md) | N/A | No project-defined public traits requiring sealing or extension traits. |
| [api-extension-trait](../../.codex/skills/rust-skills/rules/api-extension-trait.md) | N/A | No project-defined public traits requiring sealing or extension traits. |
| [api-parse-dont-validate](../../.codex/skills/rust-skills/rules/api-parse-dont-validate.md) | Gap | Public AuthConfig.kind and raw numeric Options fields allow validated invariants to be invalidated; see F1/F2. |
| [api-impl-into](../../.codex/skills/rust-skills/rules/api-impl-into.md) | Recommendation | AuthConfig::new requires an owned Vec; consider Into<Vec<u8>> only if library caller ergonomics warrant it. |
| [api-impl-asref](../../.codex/skills/rust-skills/rules/api-impl-asref.md) | Pass | Packet APIs take slices and Logger takes a Display value; no public read-only API forces callers to construct a String/PathBuf. |
| [api-must-use](../../.codex/skills/rust-skills/rules/api-must-use.md) | Recommendation | Result/Option already enforce use, but pure getters and constructors lack explicit must_use annotations. |
| [api-non-exhaustive](../../.codex/skills/rust-skills/rules/api-non-exhaustive.md) | Recommendation | Public structs/enums are extensible protocol/API surfaces; decide which need non_exhaustive before supporting external consumers. |
| [api-from-not-into](../../.codex/skills/rust-skills/rules/api-from-not-into.md) | N/A | No custom Into or From conversion implementations to assess. |
| [api-default-impl](../../.codex/skills/rust-skills/rules/api-default-impl.md) | Pass | Mode has a meaningful Default; keys, endpoints, sockets, and active sessions appropriately require explicit construction. |
| [api-common-traits](../../.codex/skills/rust-skills/rules/api-common-traits.md) | Recommendation | Packet/enums derive useful common traits; several public runtime types lack Debug. Use redacted Debug for Options/AuthConfig, never derive secret output. |
| [api-serde-optional](../../.codex/skills/rust-skills/rules/api-serde-optional.md) | N/A | No Serde integration or optional serialization feature. |
| [api-impl-fromiterator](../../.codex/skills/rust-skills/rules/api-impl-fromiterator.md) | N/A | No custom collection or algebraic operator type. |
| [api-operator-overload](../../.codex/skills/rust-skills/rules/api-operator-overload.md) | N/A | No custom collection or algebraic operator type. |

### Async/Await

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [async-tokio-runtime](../../.codex/skills/rust-skills/rules/async-tokio-runtime.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-no-lock-await](../../.codex/skills/rust-skills/rules/async-no-lock-await.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-spawn-blocking](../../.codex/skills/rust-skills/rules/async-spawn-blocking.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-tokio-fs](../../.codex/skills/rust-skills/rules/async-tokio-fs.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-cancellation-token](../../.codex/skills/rust-skills/rules/async-cancellation-token.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-join-parallel](../../.codex/skills/rust-skills/rules/async-join-parallel.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-try-join](../../.codex/skills/rust-skills/rules/async-try-join.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-select-racing](../../.codex/skills/rust-skills/rules/async-select-racing.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-bounded-channel](../../.codex/skills/rust-skills/rules/async-bounded-channel.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-mpsc-queue](../../.codex/skills/rust-skills/rules/async-mpsc-queue.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-broadcast-pubsub](../../.codex/skills/rust-skills/rules/async-broadcast-pubsub.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-watch-latest](../../.codex/skills/rust-skills/rules/async-watch-latest.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-oneshot-response](../../.codex/skills/rust-skills/rules/async-oneshot-response.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-joinset-structured](../../.codex/skills/rust-skills/rules/async-joinset-structured.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-clone-before-await](../../.codex/skills/rust-skills/rules/async-clone-before-await.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-fn-in-trait](../../.codex/skills/rust-skills/rules/async-fn-in-trait.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-async-fn-bounds](../../.codex/skills/rust-skills/rules/async-async-fn-bounds.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |
| [async-cancel-safety](../../.codex/skills/rust-skills/rules/async-cancel-safety.md) | N/A | Service uses a synchronous event loop and std channels, not Rust async/futures/Tokio; BFD asynchronous mode is a protocol term. |

### Concurrency

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [conc-rayon-par-iter](../../.codex/skills/rust-skills/rules/conc-rayon-par-iter.md) | N/A | No CPU-bound batch workload suited to Rayon; packet processing is one session at a time. |
| [conc-scoped-threads](../../.codex/skills/rust-skills/rules/conc-scoped-threads.md) | Pass | Integration workers require independent owned fixtures and are joined by RAII; no borrowed thread inputs call for scoped threads. |
| [conc-atomic-ordering](../../.codex/skills/rust-skills/rules/conc-atomic-ordering.md) | N/A | No project atomics or thread-local caches; OnceLock supplies synchronization. |
| [conc-thread-local](../../.codex/skills/rust-skills/rules/conc-thread-local.md) | N/A | No project atomics or thread-local caches; OnceLock supplies synchronization. |

### Compiler Optimization

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [opt-inline-small](../../.codex/skills/rust-skills/rules/opt-inline-small.md) | Recommendation | Small pure wire/enum helpers could be inline candidates if cross-crate profiling shows call overhead; no speed claim is established. |
| [opt-inline-always-rare](../../.codex/skills/rust-skills/rules/opt-inline-always-rare.md) | Pass | No inline(always), architecture-specific hints, or speculative forced inlining. |
| [opt-inline-never-cold](../../.codex/skills/rust-skills/rules/opt-inline-never-cold.md) | N/A | No profiled cold-code or branch-prediction bottleneck; attributes and hints would be speculative. |
| [opt-cold-unlikely](../../.codex/skills/rust-skills/rules/opt-cold-unlikely.md) | N/A | No profiled cold-code or branch-prediction bottleneck; attributes and hints would be speculative. |
| [opt-likely-hint](../../.codex/skills/rust-skills/rules/opt-likely-hint.md) | N/A | No profiled cold-code or branch-prediction bottleneck; attributes and hints would be speculative. |
| [opt-lto-release](../../.codex/skills/rust-skills/rules/opt-lto-release.md) | Recommendation | Release uses Cargo defaults; benchmark LTO and reduced codegen-units before adopting their build-time tradeoff. |
| [opt-codegen-units](../../.codex/skills/rust-skills/rules/opt-codegen-units.md) | Recommendation | Release uses Cargo defaults; benchmark LTO and reduced codegen-units before adopting their build-time tradeoff. |
| [opt-pgo-profile](../../.codex/skills/rust-skills/rules/opt-pgo-profile.md) | N/A | No profile data, CPU-specific deployment contract, or demonstrated vectorizable batch kernel. |
| [opt-target-cpu](../../.codex/skills/rust-skills/rules/opt-target-cpu.md) | N/A | No profile data, CPU-specific deployment contract, or demonstrated vectorizable batch kernel. |
| [opt-bounds-check](../../.codex/skills/rust-skills/rules/opt-bounds-check.md) | Pass | Packet and ancillary accesses have preceding length guards; fixed-field iteration avoids arbitrary indexing loops. |
| [opt-simd-portable](../../.codex/skills/rust-skills/rules/opt-simd-portable.md) | N/A | No profile data, CPU-specific deployment contract, or demonstrated vectorizable batch kernel. |
| [opt-cache-friendly](../../.codex/skills/rust-skills/rules/opt-cache-friendly.md) | Pass | Tiny contiguous packet buffers and session fields; no pointer-heavy collection or large cache-sensitive traversal. |

### Numeric & Arithmetic Safety

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [num-overflow-explicit](../../.codex/skills/rust-skills/rules/num-overflow-explicit.md) | Pass | Authentication sequence explicitly wraps; duration multiplication widens before arithmetic; bounded native buffer sizes cannot overflow locally. |
| [num-cast-try-from](../../.codex/skills/rust-skills/rules/num-cast-try-from.md) | Gap | Expanded Clippy flags 16 possible truncation casts. Current wire/native sizes are bounded, but checked conversions or explicit width rationale are missing; see G3. |
| [num-float-compare](../../.codex/skills/rust-skills/rules/num-float-compare.md) | N/A | No floating-point arithmetic or comparisons. |
| [num-saturating-clamp](../../.codex/skills/rust-skills/rules/num-saturating-clamp.md) | Pass | Timeout handling uses saturating_duration_since, bounded poll milliseconds, and saturating ancillary remaining lengths. |
| [num-nonzero](../../.codex/skills/rust-skills/rules/num-nonzero.md) | Gap | Nonzero multiplier/discriminator constraints live in CLI parsing rather than an invariant-preserving session type; see F2. |

### Type Safety

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [type-newtype-ids](../../.codex/skills/rust-skills/rules/type-newtype-ids.md) | Recommendation | Discriminators and interface indexes share raw u32 types; distinct newtypes would prevent accidental mixing in the library API. |
| [type-newtype-validated](../../.codex/skills/rust-skills/rules/type-newtype-validated.md) | Gap | Public AuthConfig.kind and raw numeric Options fields allow validated invariants to be invalidated; see F1/F2. |
| [type-enum-states](../../.codex/skills/rust-skills/rules/type-enum-states.md) | Pass | BFD states, diagnostics, mode, and authentication mechanisms use enums rather than textual state values. |
| [type-option-nullable](../../.codex/skills/rust-skills/rules/type-option-nullable.md) | Pass | Missing metadata, deadlines, configured values, keys, and sequence tracking use Option rather than sentinel pointers. |
| [type-result-fallible](../../.codex/skills/rust-skills/rules/type-result-fallible.md) | Gap | Most fallible APIs return Result, but verify can panic for publicly mutated valid-at-construction config; see F1. |
| [type-phantom-marker](../../.codex/skills/rust-skills/rules/type-phantom-marker.md) | N/A | No marker-only generic types, transparent newtypes, or custom Deref implementations. |
| [type-never-diverge](../../.codex/skills/rust-skills/rules/type-never-diverge.md) | N/A | No project-defined function whose public contract requires the never return type. |
| [type-generic-bounds](../../.codex/skills/rust-skills/rules/type-generic-bounds.md) | Pass | Logger requires Display for formatted values; no unnecessary public generic trait bounds. |
| [type-no-stringly](../../.codex/skills/rust-skills/rules/type-no-stringly.md) | Gap | Mode/State/AuthType are typed, but library error identities are Strings/static strings; callers cannot match variants; see G1. |
| [type-repr-transparent](../../.codex/skills/rust-skills/rules/type-repr-transparent.md) | N/A | No marker-only generic types, transparent newtypes, or custom Deref implementations. |
| [type-deref-coercion](../../.codex/skills/rust-skills/rules/type-deref-coercion.md) | N/A | No marker-only generic types, transparent newtypes, or custom Deref implementations. |
| [type-display-vs-debug](../../.codex/skills/rust-skills/rules/type-display-vs-debug.md) | Pass | User-facing endpoints/errors use Display and protocol state diagnostics use Debug; authentication keys are never formatted. |
| [type-numeric-fmt](../../.codex/skills/rust-skills/rules/type-numeric-fmt.md) | Pass | Wire integers use explicit endian conversion; log durations and IDs use ordinary numeric Display. |

### Trait & Generics Design

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [trait-associated-type-vs-generic](../../.codex/skills/rust-skills/rules/trait-associated-type-vs-generic.md) | N/A | No custom traits, blanket implementations, orphan-rule adaptations, or default trait methods. |
| [trait-blanket-impl](../../.codex/skills/rust-skills/rules/trait-blanket-impl.md) | N/A | No custom traits, blanket implementations, orphan-rule adaptations, or default trait methods. |
| [trait-coherence-newtype](../../.codex/skills/rust-skills/rules/trait-coherence-newtype.md) | N/A | No custom traits, blanket implementations, orphan-rule adaptations, or default trait methods. |
| [trait-default-methods](../../.codex/skills/rust-skills/rules/trait-default-methods.md) | N/A | No custom traits, blanket implementations, orphan-rule adaptations, or default trait methods. |
| [trait-dyn-vs-generic](../../.codex/skills/rust-skills/rules/trait-dyn-vs-generic.md) | Pass | Dynamic dispatch is limited to heterogeneous errors at application boundaries; packet logic and closures remain statically dispatched. |
| [trait-object-safety](../../.codex/skills/rust-skills/rules/trait-object-safety.md) | Pass | Box<dyn std::error::Error> uses an object-safe standard trait; no project trait-object incompatibility. |

### Conversions

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [conv-tryfrom-fallible](../../.codex/skills/rust-skills/rules/conv-tryfrom-fallible.md) | Recommendation | A TryFrom<Options> validated configuration boundary would improve reuse and enforce numeric constraints; see F2. |
| [conv-fromstr-parsing](../../.codex/skills/rust-skills/rules/conv-fromstr-parsing.md) | Pass | Clap uses standard IP/integer parsers and ValueEnum; custom hex parsing returns a fallible result. |
| [conv-asmut-mutable](../../.codex/skills/rust-skills/rules/conv-asmut-mutable.md) | N/A | No polymorphic mutable buffer consumer requiring AsMut. |

### Const & Compile-Time

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [const-block](../../.codex/skills/rust-skills/rules/const-block.md) | N/A | No const-generic container or expensive compile-time computation needing an inline const block. |
| [const-fn](../../.codex/skills/rust-skills/rules/const-fn.md) | Recommendation | Pure enum helpers such as Mode::port and AuthType::hash_len could be const fn if compile-time callers need them. |
| [const-generics](../../.codex/skills/rust-skills/rules/const-generics.md) | N/A | No const-generic container or expensive compile-time computation needing an inline const block. |
| [const-vs-static](../../.codex/skills/rust-skills/rules/const-vs-static.md) | Pass | Protocol/service values use const; process-wide initialized configuration uses static OnceLock. |

### Serde

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [serde-rename-all](../../.codex/skills/rust-skills/rules/serde-rename-all.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-default-compat](../../.codex/skills/rust-skills/rules/serde-default-compat.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-skip-empty](../../.codex/skills/rust-skills/rules/serde-skip-empty.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-flatten](../../.codex/skills/rust-skills/rules/serde-flatten.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-enum-representation](../../.codex/skills/rust-skills/rules/serde-enum-representation.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-deny-unknown-fields](../../.codex/skills/rust-skills/rules/serde-deny-unknown-fields.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-custom-with](../../.codex/skills/rust-skills/rules/serde-custom-with.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |
| [serde-try-from-validate](../../.codex/skills/rust-skills/rules/serde-try-from-validate.md) | N/A | No Serde derives/config files: BFD binary wire encoding and decoding are implemented directly. |

### Pattern Matching

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [pat-let-else](../../.codex/skills/rust-skills/rules/pat-let-else.md) | Pass | Session::expire uses let-else for an absent timestamp; subsequent logic stays flat. |
| [pat-matches-macro](../../.codex/skills/rust-skills/rules/pat-matches-macro.md) | Pass | State membership, error kinds, and authentication kinds use matches!. |
| [pat-if-let-chains](../../.codex/skills/rust-skills/rules/pat-if-let-chains.md) | N/A | No compelling chained let condition; project edition is 2021, where proposed let-chain syntax is not generally available. |
| [pat-exhaustive-enum](../../.codex/skills/rust-skills/rules/pat-exhaustive-enum.md) | Recommendation | AuthType helper and state-pair matches use catch-all arms; explicit variant groups would force review if enums grow. |
| [pat-at-bindings](../../.codex/skills/rust-skills/rules/pat-at-bindings.md) | N/A | No nested pattern needing simultaneous whole-value binding and destructuring. |

### Macros

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [macro-prefer-functions](../../.codex/skills/rust-skills/rules/macro-prefer-functions.md) | Pass | Project logic uses functions; macros are limited to dependency-provided derives and Windows service registration. |
| [macro-rules-hygiene](../../.codex/skills/rust-skills/rules/macro-rules-hygiene.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-fragment-specifiers](../../.codex/skills/rust-skills/rules/macro-fragment-specifiers.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-export-crate-path](../../.codex/skills/rust-skills/rules/macro-export-crate-path.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-private-helpers](../../.codex/skills/rust-skills/rules/macro-private-helpers.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-proc-two-crate](../../.codex/skills/rust-skills/rules/macro-proc-two-crate.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-proc-syn-quote](../../.codex/skills/rust-skills/rules/macro-proc-syn-quote.md) | N/A | No project-authored declarative or procedural macro implementation. |
| [macro-proc-error-spans](../../.codex/skills/rust-skills/rules/macro-proc-error-spans.md) | N/A | No project-authored declarative or procedural macro implementation. |

### Closures

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [closure-fn-trait-bounds](../../.codex/skills/rust-skills/rules/closure-fn-trait-bounds.md) | Pass | Closure-taking operations come from typed standard/library APIs; no custom Fn bound is unnecessarily restrictive. |
| [closure-impl-fn-return](../../.codex/skills/rust-skills/rules/closure-impl-fn-return.md) | N/A | No function returns a closure. |
| [closure-move-capture](../../.codex/skills/rust-skills/rules/closure-move-capture.md) | Pass | Ctrl+C, SCM, and integration worker closures use move to own captured stop senders/configuration. |
| [closure-static-vs-dyn](../../.codex/skills/rust-skills/rules/closure-static-vs-dyn.md) | Pass | Closures are statically dispatched; no boxed dynamic closure allocation. |
| [closure-disjoint-capture](../../.codex/skills/rust-skills/rules/closure-disjoint-capture.md) | Pass | Stop callbacks capture only their sender; worker-owned Engine/configuration is intentionally moved into the worker. |

### Collections

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [coll-binaryheap](../../.codex/skills/rust-skills/rules/coll-binaryheap.md) | N/A | Single session timers need no heap priority queue; no production map or set workload. |
| [coll-map-choice](../../.codex/skills/rust-skills/rules/coll-map-choice.md) | N/A | Single session timers need no heap priority queue; no production map or set workload. |
| [coll-seq-choice](../../.codex/skills/rust-skills/rules/coll-seq-choice.md) | Pass | Byte sequences use arrays for native scratch space, slices for reads, and Vec for owned variable-length packets/keys. |
| [coll-set-membership](../../.codex/skills/rust-skills/rules/coll-set-membership.md) | N/A | Single session timers need no heap priority queue; no production map or set workload. |

### Naming Conventions

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [name-types-camel](../../.codex/skills/rust-skills/rules/name-types-camel.md) | Pass | Rust types and enum variants use UpperCamelCase; BFD acronym spelling follows word casing. |
| [name-variants-camel](../../.codex/skills/rust-skills/rules/name-variants-camel.md) | Pass | Rust types and enum variants use UpperCamelCase; BFD acronym spelling follows word casing. |
| [name-funcs-snake](../../.codex/skills/rust-skills/rules/name-funcs-snake.md) | Pass | Functions/fields use snake_case and project constants/statics use SCREAMING_SNAKE_CASE. |
| [name-consts-screaming](../../.codex/skills/rust-skills/rules/name-consts-screaming.md) | Pass | Functions/fields use snake_case and project constants/statics use SCREAMING_SNAKE_CASE. |
| [name-lifetime-short](../../.codex/skills/rust-skills/rules/name-lifetime-short.md) | N/A | No explicit lifetime or generic type parameter names are introduced. |
| [name-type-param-single](../../.codex/skills/rust-skills/rules/name-type-param-single.md) | N/A | No explicit lifetime or generic type parameter names are introduced. |
| [name-as-free](../../.codex/skills/rust-skills/rules/name-as-free.md) | Pass | No project conversion method misuses as_, to_, or into_ cost/ownership conventions. |
| [name-to-expensive](../../.codex/skills/rust-skills/rules/name-to-expensive.md) | Pass | No project conversion method misuses as_, to_, or into_ cost/ownership conventions. |
| [name-into-ownership](../../.codex/skills/rust-skills/rules/name-into-ownership.md) | Pass | No project conversion method misuses as_, to_, or into_ cost/ownership conventions. |
| [name-no-get-prefix](../../.codex/skills/rust-skills/rules/name-no-get-prefix.md) | Pass | Getters such as detection_time and desired_min_tx_us omit get_ prefixes. |
| [name-is-has-bool](../../.codex/skills/rust-skills/rules/name-is-has-bool.md) | Recommendation | Boolean predicates periodic_enabled and meticulous could use is_ names; side-effecting expire/receive should retain action names. |
| [name-iter-convention](../../.codex/skills/rust-skills/rules/name-iter-convention.md) | N/A | No custom iterator method or iterator type to name. |
| [name-iter-method](../../.codex/skills/rust-skills/rules/name-iter-method.md) | N/A | No custom iterator method or iterator type to name. |
| [name-iter-type-match](../../.codex/skills/rust-skills/rules/name-iter-type-match.md) | N/A | No custom iterator method or iterator type to name. |
| [name-acronym-word](../../.codex/skills/rust-skills/rules/name-acronym-word.md) | Pass | Rust types and enum variants use UpperCamelCase; BFD acronym spelling follows word casing. |
| [name-crate-no-rs](../../.codex/skills/rust-skills/rules/name-crate-no-rs.md) | Pass | Crate is bfd-winservice; no redundant rust/rs suffix. |

### Testing

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [test-cfg-test-module](../../.codex/skills/rust-skills/rules/test-cfg-test-module.md) | Pass | Unit tests are private cfg(test) modules using super::*; Windows integration tests live under tests/. |
| [test-use-super](../../.codex/skills/rust-skills/rules/test-use-super.md) | Pass | Unit tests are private cfg(test) modules using super::*; Windows integration tests live under tests/. |
| [test-integration-dir](../../.codex/skills/rust-skills/rules/test-integration-dir.md) | Pass | Unit tests are private cfg(test) modules using super::*; Windows integration tests live under tests/. |
| [test-descriptive-names](../../.codex/skills/rust-skills/rules/test-descriptive-names.md) | Pass | Tests describe state transitions, authentication windows, malformed metadata, Poll scheduling, and point-to-point source changes. |
| [test-arrange-act-assert](../../.codex/skills/rust-skills/rules/test-arrange-act-assert.md) | Pass | Test setup and actions precede behavior assertions; multi-step protocol tests intentionally alternate actions/assertions. |
| [test-proptest-properties](../../.codex/skills/rust-skills/rules/test-proptest-properties.md) | Gap | No retained proptest/property suite; the audit's 98,496 bounded parser cases are supplementary and do not provide persisted regression coverage. |
| [test-mockall-mocking](../../.codex/skills/rust-skills/rules/test-mockall-mocking.md) | N/A | No mock framework or custom mocking traits; real UDP integration and pure state-machine tests cover current boundaries. |
| [test-mock-traits](../../.codex/skills/rust-skills/rules/test-mock-traits.md) | N/A | No mock framework or custom mocking traits; real UDP integration and pure state-machine tests cover current boundaries. |
| [test-fixture-raii](../../.codex/skills/rust-skills/rules/test-fixture-raii.md) | Gap | Two newer engine tests use RunningEngine RAII; the older handshake test manually joins only on success, leaving cleanup unjoined on panic; see G5. |
| [test-tokio-async](../../.codex/skills/rust-skills/rules/test-tokio-async.md) | N/A | No async tests, intentional panic API, lock-free algorithm, or stable large output suitable for snapshots. |
| [test-should-panic](../../.codex/skills/rust-skills/rules/test-should-panic.md) | N/A | No async tests, intentional panic API, lock-free algorithm, or stable large output suitable for snapshots. |
| [test-criterion-bench](../../.codex/skills/rust-skills/rules/test-criterion-bench.md) | N/A | No benchmark target or performance change to validate; establish a workload before adding Criterion benchmarks. |
| [test-doctest-examples](../../.codex/skills/rust-skills/rules/test-doctest-examples.md) | Gap | No executable API doc examples; cargo test executes zero doctests; see G2. |
| [test-loom-concurrency](../../.codex/skills/rust-skills/rules/test-loom-concurrency.md) | N/A | No async tests, intentional panic API, lock-free algorithm, or stable large output suitable for snapshots. |
| [test-snapshot-testing](../../.codex/skills/rust-skills/rules/test-snapshot-testing.md) | N/A | No async tests, intentional panic API, lock-free algorithm, or stable large output suitable for snapshots. |

### Documentation

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [doc-all-public](../../.codex/skills/rust-skills/rules/doc-all-public.md) | Gap | Expanded production lint audit reports 87 missing public documentation warnings; see G2. |
| [doc-module-inner](../../.codex/skills/rust-skills/rules/doc-module-inner.md) | Gap | packet/session/transport have module docs, but lib.rs lacks crate docs and config/runtime lack module docs; see G2. |
| [doc-examples-section](../../.codex/skills/rust-skills/rules/doc-examples-section.md) | Gap | No executable API doc examples; cargo test executes zero doctests; see G2. |
| [doc-errors-section](../../.codex/skills/rust-skills/rules/doc-errors-section.md) | Gap | Thirteen public fallible functions lack Errors documentation; see G2. |
| [doc-panics-section](../../.codex/skills/rust-skills/rules/doc-panics-section.md) | Gap | Transport::receive has an undocumented expect invariant; AuthConfig::verify also has F1's externally reachable panic; see G2/F1. |
| [doc-safety-section](../../.codex/skills/rust-skills/rules/doc-safety-section.md) | N/A | No public unsafe function or unsafe trait contract needing a rustdoc Safety section; block comments are assessed separately. |
| [doc-question-mark](../../.codex/skills/rust-skills/rules/doc-question-mark.md) | N/A | No doctest examples currently exist; when added, use ? and hide only necessary setup. |
| [doc-hidden-setup](../../.codex/skills/rust-skills/rules/doc-hidden-setup.md) | N/A | No doctest examples currently exist; when added, use ? and hide only necessary setup. |
| [doc-intra-links](../../.codex/skills/rust-skills/rules/doc-intra-links.md) | Recommendation | Current API prose has no intra-doc cross-references; link related types and functions when completing documentation. |
| [doc-link-types](../../.codex/skills/rust-skills/rules/doc-link-types.md) | Recommendation | Current API prose has no intra-doc cross-references; link related types and functions when completing documentation. |
| [doc-cargo-metadata](../../.codex/skills/rust-skills/rules/doc-cargo-metadata.md) | N/A | No crate-publication objective is declared. Publishing would first require description/license/repository metadata; service manifest is minimal. |
| [doc-crate-readme](../../.codex/skills/rust-skills/rules/doc-crate-readme.md) | Pass | README exists with build commands, CLI options, deployment, protocol scope, and limitations. |

### Observability

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [obs-tracing-over-log](../../.codex/skills/rust-skills/rules/obs-tracing-over-log.md) | Gap | Custom Logger emits unstructured text rather than tracing events; library Logger writes directly to process stderr/files; see G4. |
| [obs-library-facade](../../.codex/skills/rust-skills/rules/obs-library-facade.md) | Gap | Custom Logger emits unstructured text rather than tracing events; library Logger writes directly to process stderr/files; see G4. |
| [obs-structured-fields](../../.codex/skills/rust-skills/rules/obs-structured-fields.md) | Gap | Peer, state, discriminator, intervals, and failure reasons are interpolated into text rather than typed structured fields; see G4. |
| [obs-instrument-spans](../../.codex/skills/rust-skills/rules/obs-instrument-spans.md) | N/A | No async tasks or concurrent request processing needing tracing span attachment; one session per Engine. |
| [obs-levels-filter](../../.codex/skills/rust-skills/rules/obs-levels-filter.md) | Gap | Logger lacks severity levels and standard filtering; verbose controls discarded packets only; see G4. |
| [obs-error-chain](../../.codex/skills/rust-skills/rules/obs-error-chain.md) | Gap | Startup errors lack contextual source chains and service failures can be logged again at the entry point; see G1/G4. |
| [obs-no-sensitive-data](../../.codex/skills/rust-skills/rules/obs-no-sensitive-data.md) | Pass | AuthConfig deliberately omits Debug and logs avoid Options/key material; no secret bytes are emitted. |

### Performance Patterns

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [perf-iter-over-index](../../.codex/skills/rust-skills/rules/perf-iter-over-index.md) | Pass | Production loops iterate values/fields, hex pairs, source ports, or validated ancillary records; no needless index traversal. |
| [perf-iter-lazy](../../.codex/skills/rust-skills/rules/perf-iter-lazy.md) | Pass | Hex decoding collects once into its final Result<Vec<_>>; no collect-then-iterate temporary chain. |
| [perf-collect-once](../../.codex/skills/rust-skills/rules/perf-collect-once.md) | Pass | Hex decoding collects once into its final Result<Vec<_>>; no collect-then-iterate temporary chain. |
| [perf-entry-api](../../.codex/skills/rust-skills/rules/perf-entry-api.md) | N/A | No mutable map insertion, chained bulk collection, or collecting into a preexisting repeated iterator destination. |
| [perf-drain-reuse](../../.codex/skills/rust-skills/rules/perf-drain-reuse.md) | Recommendation | Receive allocates a packet Vec; keyed authentication copies a packet and allocates a digest; reuse bounded buffers after profiling. |
| [perf-extend-batch](../../.codex/skills/rust-skills/rules/perf-extend-batch.md) | Pass | Encoding copies header words and appends key/sequence slices in batches with copy_from_slice/extend_from_slice. |
| [perf-chain-avoid](../../.codex/skills/rust-skills/rules/perf-chain-avoid.md) | N/A | No mutable map insertion, chained bulk collection, or collecting into a preexisting repeated iterator destination. |
| [perf-collect-into](../../.codex/skills/rust-skills/rules/perf-collect-into.md) | N/A | No mutable map insertion, chained bulk collection, or collecting into a preexisting repeated iterator destination. |
| [perf-black-box-bench](../../.codex/skills/rust-skills/rules/perf-black-box-bench.md) | N/A | No benchmark harness or string-keyed map workload. |
| [perf-release-profile](../../.codex/skills/rust-skills/rules/perf-release-profile.md) | Pass | Optimized release build succeeds; correctness checks run in debug where overflow checking remains active. |
| [perf-profile-first](../../.codex/skills/rust-skills/rules/perf-profile-first.md) | Pass | No speculative tuning was applied during this audit; memory/optimization suggestions require profiling before implementation. |
| [perf-ahash](../../.codex/skills/rust-skills/rules/perf-ahash.md) | N/A | No benchmark harness or string-keyed map workload. |
| [perf-io-buffering](../../.codex/skills/rust-skills/rules/perf-io-buffering.md) | Recommendation | Logger performs one file write per event; buffering could help high-volume logs but must preserve explicit flush/error handling and timely service diagnostics. |

### Project Structure

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [proj-lib-main-split](../../.codex/skills/rust-skills/rules/proj-lib-main-split.md) | Pass | main.rs parses/dispatches; reusable config, packet, session, runtime, and transport logic is in the library. |
| [proj-mod-by-feature](../../.codex/skills/rust-skills/rules/proj-mod-by-feature.md) | Pass | Eight source files group coherent concerns in a flat layout suitable for this small crate. |
| [proj-flat-small](../../.codex/skills/rust-skills/rules/proj-flat-small.md) | Pass | Eight source files group coherent concerns in a flat layout suitable for this small crate. |
| [proj-mod-rs-dir](../../.codex/skills/rust-skills/rules/proj-mod-rs-dir.md) | N/A | No nested multi-file module directory. |
| [proj-pub-crate-internal](../../.codex/skills/rust-skills/rules/proj-pub-crate-internal.md) | Recommendation | Nearly all library modules and many session fields are public; narrow implementation visibility or provide accessors before promising a reusable API. |
| [proj-pub-super-parent](../../.codex/skills/rust-skills/rules/proj-pub-super-parent.md) | N/A | No nested module tree with parent-only helpers. |
| [proj-pub-use-reexport](../../.codex/skills/rust-skills/rules/proj-pub-use-reexport.md) | Recommendation | Public users import module paths directly; a small intentional root re-export API could stabilize imports if library reuse is intended. |
| [proj-prelude-module](../../.codex/skills/rust-skills/rules/proj-prelude-module.md) | N/A | Small service crate has no broad common trait import set requiring a prelude. |
| [proj-bin-dir](../../.codex/skills/rust-skills/rules/proj-bin-dir.md) | N/A | One binary, one library, no multi-crate workspace. |
| [proj-workspace-large](../../.codex/skills/rust-skills/rules/proj-workspace-large.md) | N/A | One binary, one library, no multi-crate workspace. |
| [proj-workspace-deps](../../.codex/skills/rust-skills/rules/proj-workspace-deps.md) | N/A | One binary, one library, no multi-crate workspace. |
| [proj-feature-additive](../../.codex/skills/rust-skills/rules/proj-feature-additive.md) | N/A | No custom Cargo feature switches. |
| [proj-msrv-declare](../../.codex/skills/rust-skills/rules/proj-msrv-declare.md) | Gap | Cargo.toml omits rust-version and no service CI tests a minimum supported Rust version; see G5. |
| [proj-build-rs-minimal](../../.codex/skills/rust-skills/rules/proj-build-rs-minimal.md) | N/A | Project has no build.rs. |

### Clippy & Linting

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [lint-deny-correctness](../../.codex/skills/rust-skills/rules/lint-deny-correctness.md) | Pass | Default Clippy groups plus -D warnings are clean for all project targets; correctness violations would fail this check. |
| [lint-warn-suspicious](../../.codex/skills/rust-skills/rules/lint-warn-suspicious.md) | Pass | Default Clippy groups plus -D warnings are clean for all project targets; correctness violations would fail this check. |
| [lint-warn-style](../../.codex/skills/rust-skills/rules/lint-warn-style.md) | Pass | Default Clippy groups plus -D warnings are clean for all project targets; correctness violations would fail this check. |
| [lint-warn-complexity](../../.codex/skills/rust-skills/rules/lint-warn-complexity.md) | Pass | Default Clippy groups plus -D warnings are clean for all project targets; correctness violations would fail this check. |
| [lint-warn-perf](../../.codex/skills/rust-skills/rules/lint-warn-perf.md) | Pass | Default Clippy groups plus -D warnings are clean for all project targets; correctness violations would fail this check. |
| [lint-pedantic-selective](../../.codex/skills/rust-skills/rules/lint-pedantic-selective.md) | Recommendation | Expanded audit selects relevant pedantic lints, but the repository has no persistent lint configuration/CI for them; see G5. |
| [lint-missing-docs](../../.codex/skills/rust-skills/rules/lint-missing-docs.md) | Gap | Expanded production lint audit reports 87 missing public documentation warnings; see G2. |
| [lint-unsafe-doc](../../.codex/skills/rust-skills/rules/lint-unsafe-doc.md) | Gap | Expanded undocumented_unsafe_blocks audit reports two union accesses; no persistent strict unsafe documentation lint; see G3. |
| [lint-cargo-metadata](../../.codex/skills/rust-skills/rules/lint-cargo-metadata.md) | N/A | Publishing is not requested; cargo metadata linting should be enabled if the crate becomes a distributed library. |
| [lint-rustfmt-check](../../.codex/skills/rust-skills/rules/lint-rustfmt-check.md) | Pass | cargo fmt --all -- --check passes for service source and tests. |
| [lint-workspace-lints](../../.codex/skills/rust-skills/rules/lint-workspace-lints.md) | N/A | No Cargo workspace/member lint inheritance. |
| [lint-cfg-check](../../.codex/skills/rust-skills/rules/lint-cfg-check.md) | Pass | Only standard windows/test cfgs are used; Cargo's unexpected_cfgs checking emits no warnings. |
| [lint-clippy-nursery-selected](../../.codex/skills/rust-skills/rules/lint-clippy-nursery-selected.md) | Recommendation | Expanded audit selects relevant pedantic lints, but the repository has no persistent lint configuration/CI for them; see G5. |

### Anti-patterns

| Rule | Assessment | Rationale/evidence |
|---|---|---|
| [anti-unwrap-abuse](../../.codex/skills/rust-skills/rules/anti-unwrap-abuse.md) | Gap | read_control uses one production unwrap after a four-byte length guard; safe invariant, but violates the strict no-unwrap rule; see G3. |
| [anti-expect-lazy](../../.codex/skills/rust-skills/rules/anti-expect-lazy.md) | Pass | Explicit expect calls describe internal packet bounds and the privately initialized WSARecvMsg pointer, not routine I/O failures. |
| [anti-clone-excessive](../../.codex/skills/rust-skills/rules/anti-clone-excessive.md) | Recommendation | Configuration clones are explicit and needed by the current ownership design; splitting runtime settings can avoid copying secret-bearing strings. |
| [anti-lock-across-await](../../.codex/skills/rust-skills/rules/anti-lock-across-await.md) | N/A | No await points or async locks. |
| [anti-string-for-str](../../.codex/skills/rust-skills/rules/anti-string-for-str.md) | Pass | Packet APIs accept slices; no &String or &Vec parameter signatures. |
| [anti-vec-for-slice](../../.codex/skills/rust-skills/rules/anti-vec-for-slice.md) | Pass | Packet APIs accept slices; no &String or &Vec parameter signatures. |
| [anti-index-over-iter](../../.codex/skills/rust-skills/rules/anti-index-over-iter.md) | Pass | Production loops iterate values/fields, hex pairs, source ports, or validated ancillary records; no needless index traversal. |
| [anti-panic-expected](../../.codex/skills/rust-skills/rules/anti-panic-expected.md) | Gap | AuthConfig::verify can panic after a legal public-field mutation; see F1. |
| [anti-empty-catch](../../.codex/skills/rust-skills/rules/anti-empty-catch.md) | Pass | Ignored errors represent deliberate best-effort stop notifications, teardown joins, or rejected datagrams; operational I/O errors are reported/propagated. |
| [anti-over-abstraction](../../.codex/skills/rust-skills/rules/anti-over-abstraction.md) | Pass | Small direct modules and concrete packet/session types; no unnecessary trait framework or protocol type erasure. |
| [anti-premature-optimize](../../.codex/skills/rust-skills/rules/anti-premature-optimize.md) | Pass | No speculative tuning was applied during this audit; memory/optimization suggestions require profiling before implementation. |
| [anti-type-erasure](../../.codex/skills/rust-skills/rules/anti-type-erasure.md) | Pass | Small direct modules and concrete packet/session types; no unnecessary trait framework or protocol type erasure. |
| [anti-format-hot-path](../../.codex/skills/rust-skills/rules/anti-format-hot-path.md) | Recommendation | Formatting allocations occur on logged state/discard/send events; discarded traffic is rate limited. Use format_args if measurements show logging overhead. |
| [anti-collect-intermediate](../../.codex/skills/rust-skills/rules/anti-collect-intermediate.md) | Pass | Hex decoding collects once into its final Result<Vec<_>>; no collect-then-iterate temporary chain. |
| [anti-stringly-typed](../../.codex/skills/rust-skills/rules/anti-stringly-typed.md) | Gap | Mode/State/AuthType are typed, but library error identities are Strings/static strings; callers cannot match variants; see G1. |
