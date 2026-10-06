# Correctness review — 2026-10-05

Reviewed all service source modules and tests, Cargo configuration, and operational documentation. Applied the relevant ownership, borrowing, memory layout, FFI, concurrency, error handling, and numeric rules from the local Rust skill. The earlier 265-rule assessment is preserved as a [historical guideline matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md); this review concentrates on defects and their fixes. [The current validation guide](RUST_SKILLS_VALIDATION.md) describes the API guarantees and links to that snapshot.

## Findings fixed

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

## Protocol and FFI review

- Authentication is verified before peer state, timers, sequence tracking, or Poll/Final processing changes. Invalid authentication causes silent discard as required by [RFC 5880 section 6.8.6](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.6).
- BFD state transitions, detection expiry, passive transmission, remote Demand/zero receive-interval suppression, jitter, discriminator expiry, and keyed authentication sequence wrap/resynchronization were checked against RFC 5880. Local timer settings remain startup-only.
- MI function-pointer signatures were checked against the installed Windows SDK `mi.h`. Borrowed result pointers are consumed before fetching the next result or closing an operation. Normal result retrieval drains operations before closing; error cleanup attempts cancellation and draining, logging cleanup failures. Child native objects are released before their session/application.
- Provider calls execute on one BGP worker and never under the mailbox mutex. Queue growth is bounded. Already issued MI calls finish before the next state action; a later Stop follows an in-flight Start. There is no claim that an in-flight provider mutation can be atomically canceled when a UDP packet arrives.
- Ancillary data uses bounds-checked unaligned reads; real Winsock output lengths are checked before slicing. No new raw-pointer ownership or manual Send/Sync implementation was introduced.

## Compatibility

The command-line interface is unchanged. Library callers must now handle `Session::new(...) -> Result<Session, String>`, use `AuthConfig::kind()`, and use the session's state/diagnostic/discriminator/polling accessors instead of public fields. Supplied session authentication must match its options. These API changes intentionally prevent invalid safe-Rust configurations.

## Validation

| Check | Result |
|---|---|
| `cargo test --locked --offline` | 44 library tests, 2 service tests, 6 Windows UDP integration tests, and 1 compile-fail doctest pass. One namespace-dependent schema test is opt-in. |
| Explicit read-only CIM schema test outside the restricted sandbox | Pass; verifies qualifier metadata on `MSFT_NetAdapter`, without changing BGP. Total native/default plus explicit tests: 54. |
| `cargo clippy --locked --offline --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks` | Pass. |
| `cargo fmt --check` | Pass. |
| `cargo build --release --locked --offline` | Pass. |
| Miri with `-Zmiri-strict-provenance` | Full 39-test library suite passed before the final query-race regression was added. All 13 BGP tests then passed on the final code, including that regression; both pure service status tests also passed. |

Native Winsock and `mi.dll` execution are outside Miri's supported paths. They were checked through native UDP tests, native local MI fixtures, and the read-only schema test. SCM installation/start/stop and actual `PS_BgpPeer.Start/Stop` require a provisioned Windows Server and were not exercised against a live BGP peer. Provider timeout settings request five seconds per operation; they are not a guarantee that every provider call or teardown finishes within five seconds ([MI timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). No additional confirmed defect remains from this review; testing cannot establish the absence of all bugs.
