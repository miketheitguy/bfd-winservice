# Correctness reviews

This record is for Rust maintainers reviewing dated findings and validation limits. For fresh installation instructions and settings, see [Set up a BFD session](docs/setup.md) and the [configuration reference](docs/configuration.md).

## rust-check remediation — 2026-10-07

Applied the explicitly requested [rust-check skill](.codex/skills/rust-check/SKILL.md) to the service code, using its minimal-change guidance. **The P2 console-output finding below is resolved.** `Logger` now uses fallible `Write` calls, reports console failure once per logger on a best-effort basis, and suppresses subsequent STDOUT writes while preserving console mode, file logging, and engine/BGP execution. Failed STDERR diagnostics cannot panic in the logger. The closed-pipe regression first failed on the old implementation with OS error 232, then passed after the fix, reaching AdminDown and recording subsequent lifecycle messages in the file log. No BGP provider mutation is needed for this regression.

Other targeted changes use `thiserror` for the internal receive-rejection enum, derive the applicable value traits for the small `Received` result, simplify entry-point imports and automatic error conversion, and express SDK PATH lookup with iterators. Native UDP log fixtures now use `tempfile` for ownership and cleanup; the existing console subprocess assertion uses `assert_cmd`. Public logger docs include a compiled example and describe output-error handling.

The synchronous Winsock timer loop and dedicated MI worker remain appropriate for the current runtime; adding an async executor would require a separate architectural change. Key-bearing configuration types continue to omit `Debug`. Existing public string error APIs remain compatible; the skill's preferences do not justify rewriting those interfaces in this fix. The skill's note-taking CLI examples and undefined “Constitution II” reference do not describe this project; its test-first instruction was applied to the stdout regression. No complete Rust-skill compliance claim is made.

The required `cargo fmt` and strict `cargo clippy --all-targets` checks passed. The default test suite passed 71 tests: 60 library tests, 2 service tests, 7 native UDP integration tests, and 2 doctests; the opt-in CIM schema test was ignored. The closed-pipe regression also passed with both STDOUT and STDERR unavailable, checking the diagnostic failure path. Rustdoc with warnings denied, the release build, release help, all 311 local documentation links, and `git diff --check` passed. Live SCM deployment, Event Viewer delivery, and actual BGP Start/Stop remain untested here.

## Review before remediation — 2026-10-07

Reviewed all service Rust modules, unit/integration tests, `build.rs`, Cargo configuration and lockfile, the ETW manifest, README, API comments, instruction files, and validation/review records at commit `66eeaf6`. Applied the local [Rust skill](.codex/skills/rust-skills/SKILL.md), concentrating on ownership/borrowing, native handle lifetimes and drop order, memory layout/alignment, unsafe pointer bounds, error handling, numeric conversion, and concurrency. Vendored skill examples and their checks crates are reference material rather than service code. This is a defect review, not a new 265-rule compliance matrix.

### Finding subsequently resolved

**P2 — Handle failed console writes without bypassing shutdown.** At that revision, [Logger::log](src/runtime.rs) used `print!` for STDOUT. Rust's [print documentation](https://doc.rust-lang.org/std/macro.print.html#panics) confirms that write failures panic. A standalone Windows probe connected STDOUT to an anonymous pipe, closed its reader, and called `Logger::new(true).service_started()`: `catch_unwind` observed a panic with OS error 232 (“The pipe is being closed”). The probe used no service configuration or BGP provider calls.

In that revision, a downstream reader closing the console pipe could unwind out of `run_session` before `Engine::run` reached AdminDown and its shutdown packet. A panic in the state-change log could also occur before the BGP Stop was queued. `Controller::drop` joined the worker and preserved already queued Stops but did not create a new Stop, so a previously started BGP peer could be left running. A log failure in the BGP worker could terminate that worker and prevent subsequent queued actions. The recommendation was to replace the panicking write with fallible `Write` handling and add a closed-pipe regression. This finding was open at the end of the documentation-only review and was subsequently resolved as described above.

No P0/P1 ownership, borrowing, or memory-safety defect was identified. Authentication rejection remains before session mutation; registry data has bounded initialized buffers and checked narrowing; ETW field order/widths and descriptors match the compiled manifest. Winsock ancillary parsing checks lengths before unaligned reads. MI results are copied while their operations remain live, child objects are released before parents, and provider calls stay outside the mailbox mutex. The existing BGP supersession and SCM lifecycle regressions cover the previously corrected races. This does not establish the absence of other defects.

### Documentation corrections

At the 2026-10-07 revision, the README distinguished permitted relative `LogFile` paths from the recommendation to use absolute paths under SCM. It also described numeric lifecycle Mode `0` and its `Windows service` rendering, and documented verbose gating and rate limits for generic discards/send errors. Documentation covered console output failure and its cleanup implications in the README and public runtime API comments. The 2026-10-05 review's CLI compatibility and test counts applied to its own revision. The registry configuration at the 2026-10-07 revision used `CommandLine` for `--console` and `Options::new`/`config::load_registry` for settings.

### Validation and limits

`cargo test --locked --offline` passed: 59 library tests, 2 service tests, 7 native UDP integration tests, and 1 compile-fail doctest (69 total); one namespace-dependent schema test was ignored. Strict Clippy, including `clippy::undocumented_unsafe_blocks`, passed. The closed-pipe probe reproduced the open finding above. After the documentation edits, `cargo fmt --check`, rustdoc with warnings denied, and `git diff --check` passed; release help matched the documented `--console`/help/version interface. All 310 local Markdown file links resolved. Comparing `src/runtime.rs` with its committed contents after removing API comments confirmed that production code was unchanged.

No full Miri rerun, live SCM installation/start/stop, manifest installation/Event Viewer rendering, or actual BGP Start/Stop was performed in this review. Native ETW registration/writes do not prove delivery to a registered Operational channel. The earlier validation records retain their own dates and limits.

## Historical review — 2026-10-05

The following findings, compatibility notes, and checks describe the revision before ETW and registry configuration were added. They are retained as a record of that review.

Reviewed all service source modules and tests, Cargo configuration, and operational documentation. Applied the relevant ownership, borrowing, memory layout, FFI, concurrency, error handling, and numeric rules from the local Rust skill. The earlier 265-rule assessment is preserved as a [historical guideline matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md); this review concentrates on defects and their fixes. [The current validation guide](RUST_SKILLS_VALIDATION.md) describes the API guarantees and links to that snapshot.

### Findings fixed

| Priority | Finding | Correction and evidence |
|---|---|---|
| P1 | A queued BGP Start could run after a newer Down/AdminDown, including during shutdown. A Down arriving during the preceding status query also failed to prevent Start. | Stop supersedes queued recovery actions; closing removes Starts; Start checks for supersession before and after querying. Mailbox, blocked-worker shutdown, and Down-during-query regressions pass. |
| P2 | SCM StopPending was reported only after `Engine::run` had already finished BGP cleanup. Concurrent startup could also overwrite a StopPending update if reporting were moved into the handler without synchronization. | The control handler reports StopPending immediately. One mutex serializes lifecycle reporting. A supervisor advances checkpoints while the engine thread finishes. Tests cover stop/start ordering, terminal state protection, and checkpoint fields. This follows Microsoft's [service control handler guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function). |
| P2 | A failed final BGP Stop was logged but service/console shutdown could still report success. | The worker returns its final error; explicit controller shutdown joins and propagates it through `Engine::run`. A mocked provider rejection regression verifies error propagation. Ordinary background failures still retry. |
| P2 | Public mutation of `AuthConfig.kind` could invalidate a previously validated key length and panic in verification. | The kind field is private with a read-only accessor. Authentication changes require a validated new configuration. A compile-fail doctest prevents the original mutation. This closes F1 in the earlier audit. |
| P2 | Programmatic options bypassed Clap numeric/conflict checks; raw session construction and writable session identifiers could emit invalid BFD packets. | `Options::validate` now checks all numeric ranges and key conflicts. Session construction validates and rejects mismatched authentication. Runtime construction validates and normalizes options before opening sockets; transport also checks numeric ranges. Session fields are read-only outside the crate. Constructor and options mutation regressions pass. This closes F2 in the earlier audit. |
| P2 | Only ICMP port-unreachable error reporting was disabled; Windows can also surface TTL-expired feedback as a UDP receive error, which the runtime treats as fatal. | Both `SIO_UDP_CONNRESET` and `SIO_UDP_NETRESET` are disabled. Native IPv4/IPv6 UDP tests exercise socket creation with both IOCTLs. ICMP packet injection was not performed. Microsoft's [Winsock IOCTL documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls) describes the two independent controls. |
| P3 | The older UDP handshake fixture did not join its engine on an assertion failure. | It now uses the same RAII shutdown/join fixture as the other engine tests. |

Also corrected unsafe union-access comments, replaced the ancillary parser's invariant-based `unwrap` with an explanatory `expect`, and updated README statements about BGP queueing, shutdown failure, and implemented routing integration.

### Protocol and FFI review

- Authentication is verified before peer state, timers, sequence tracking, or Poll/Final processing changes. Invalid authentication causes silent discard as required by [RFC 5880 section 6.8.6](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.6).
- BFD state transitions, detection expiry, passive transmission, remote Demand/zero receive-interval suppression, jitter, discriminator expiry, and keyed authentication sequence wrap/resynchronization were checked against RFC 5880. Local timer settings remain startup-only.
- MI function-pointer signatures were checked against the installed Windows SDK `mi.h`. Borrowed result pointers are consumed before fetching the next result or closing an operation. Normal result retrieval drains operations before closing; error cleanup attempts cancellation and draining, logging cleanup failures. Child native objects are released before their session/application.
- Provider calls execute on one BGP worker and never under the mailbox mutex. Queue growth is bounded. Already issued MI calls finish before the next state action; a later Stop follows an in-flight Start. There is no claim that an in-flight provider mutation can be atomically canceled when a UDP packet arrives.
- Ancillary data uses bounds-checked unaligned reads; real Winsock output lengths are checked before slicing. No new raw-pointer ownership or manual Send/Sync implementation was introduced.

### Compatibility at that revision

The 2026-10-05 changes retained the command-line interface then in use. Library callers had to handle `Session::new(...) -> Result<Session, String>`, use `AuthConfig::kind()`, and use the session's state/diagnostic/discriminator/polling accessors instead of public fields. Supplied session authentication must match its options. These API guarantees remain; the subsequent registry configuration change removes the former command-line settings.

### Validation at that revision

| Check | Result |
|---|---|
| `cargo test --locked --offline` | 44 library tests, 2 service tests, 6 Windows UDP integration tests, and 1 compile-fail doctest pass. One namespace-dependent schema test is opt-in. |
| Explicit read-only CIM schema test outside the restricted sandbox | Pass; verifies qualifier metadata on `MSFT_NetAdapter`, without changing BGP. Total native/default plus explicit tests: 54. |
| `cargo clippy --locked --offline --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks` | Pass. |
| `cargo fmt --check` | Pass. |
| `cargo build --release --locked --offline` | Pass. |
| Miri with `-Zmiri-strict-provenance` | Full 39-test library suite passed before the final query-race regression was added. All 13 BGP tests then passed on the final code, including that regression; both pure service status tests also passed. |

Native Winsock and `mi.dll` execution are outside Miri's supported paths. They were checked through native UDP tests, native local MI fixtures, and the read-only schema test. SCM installation/start/stop and actual `PS_BgpPeer.Start/Stop` require a provisioned Windows Server and were not exercised against a live BGP peer. Provider timeout settings request five seconds per operation; they are not a guarantee that every provider call or teardown finishes within five seconds ([MI timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). No additional confirmed defect remains from this review; testing cannot establish the absence of all bugs.
