# Documentation Audit: repository guides and diagrams

For maintainers, this record explains the documentation corrections checked
against the source, tests, installer, and build configuration on 2026-10-15.
These are documentation receipts; the older runtime test results keep their
original dates and validation limits.

**Score:** 9/10 — ships as is. **Shippable:** yes.

**Diagnostic:** 9/10 — failed rows: 2 (the current validation guide also retains
dated review history rather than giving that history its own document).

**Doc type / reader:** audit record for Windows administrators and Rust
maintainers. **Language:** en.

**Local style guide:** contributor instructions and established Markdown
conventions; the requested Gen-Z wording takes precedence over the general
preference against slang. Commands, identifiers, and protocol terminology retain
their exact meanings.

**Blocking:** none remaining in the reviewed documentation. This is a source and
documentation review, not a fresh claim of router interoperability or installed
service validation.

## Findings

The following findings are corrected in the linked sections:

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Build security](../CONTRIBUTING.md#build-security), [native RPC compiler options](security.md#native-rpc-compiler-options) | P11 verified behavior | Described a Rust-only build with no C compilation. | Describe generated MIDL stubs, the three C bridge files, actual MSVC flags, and the Rust-only scope of ASan instrumentation. | Blocking |
| 2 | [Development checks](../CONTRIBUTING.md#run-development-checks) | P11 verified behavior | Used floating `+nightly` and an unfiltered Miri library run that includes native-only modules. | Use the pinned toolchain and explicit portable filters and integration targets. | Blocking |
| 3 | [Verify the session](../README.md#verify-the-session) | P11 verified behavior | Applied per-peer Up verification to every role. | Distinguish classical/initiator Up events from stateless reflector response checks. | Blocking |
| 4 | [Session configuration](setup.md#2-configure-the-session), [Operational log](setup.md#3-verify-the-operational-log) | P11 verified behavior | Repeated MSI-provisioned setup and reset existing file-log settings. | Verify MSI registration; reserve logging initialization for loose files or a deliberate reset. | Blocking |
| 5 | [BGP actions](bgp.md#verify-state-changes-and-actions), [protocol limits](protocol.md#supported-modes-and-limits) | P11 verified behavior | Said shutdown always leaves BGP unchanged and grouped handled fatal transport errors with crashes. | Explain AdminDown release of BFD's own Stop, final Start/cleanup, and the separate abrupt-termination case. | Blocking |
| 6 | [S-BFD authentication](seamless.md#authentication-and-loop-prevention) | P11 verified behavior | Ambiguous opposite-role Demand-bit wording. | State explicitly that reflectors accept D=1 and initiators accept D=0. | Blocking |
| 7 | [Configuration reference](configuration.md), [S-BFD roles](seamless.md) | P11 verified behavior | Omitted role restrictions, ignored legacy `Mode`, limiter bounds, and permitted RTT-only updates. | Document `Multihop`, validation constraints, 4,096 tracked sources per limiter window, and `MinRxUs`-only updates. | Blocking |
| 8 | [Log destinations](logging.md#log-destinations), [event limits](logging.md#lifecycle-communication-and-state-events) | P11 verified behavior | Implied a hard disk cap and guaranteed delivery for rate-budget-exempt events. | Explain failed-rotation growth, queue/delivery limits, and service flush timing. | Blocking |
| 9 | [Monitoring permissions](monitoring.md#monitor-lifecycle-and-state-transitions) | P11 verified behavior | Implied every non-administrator can run all log queries. | Separate service-query rights from host-specific Event Log read permissions. | Blocking |
| 10 | [Service lifecycle](service-communication.md#service-lifecycle), [snapshot publication](rpc-session-status-design.md#snapshot-coherence-and-packet-isolation) | P11 verified behavior | Omitted early observer closure and blurred nominal publication timing with deadlines. | Close observation before announcement/BGP cleanup; distinguish minimum spacing, refresh targets, freshness, and separate timeout budgets. | Blocking |
| 11 | [RPC resource ownership](rpc-authentication.md#deadlines-cancellation-and-resource-ownership) | P11 verified behavior | Broadly said native exceptions stay inside C. | Distinguish recoverable RPC errors from fatal native faults left outside the handler. | Blocking |
| 12 | [Validation guide](../RUST_SKILLS_VALIDATION.md#read-the-validation-receipts), [correctness reviews](../CODE_REVIEW.md) | V7 timeless documentation | Older build, shutdown, CI, and RPC designs could be mistaken for active guidance. | Add explicit supersession maps while preserving dated evidence and test counts. | Medium |
| 13 | [BGP configuration](bgp.md#configure-the-peer) | P1 complete procedures | Omitted a runnable routing-domain example and separate provider verification. | Add target configuration, coordinated restart, and BGP verification steps. | High |
| 14 | [Service diagrams](service-communication.md) | S10 accessible diagrams | Visuals omitted optional-authentication defaults and important shutdown/freshness details. | Update all three editable pages and embedded-XML PNG exports, with matching prose and alt text. | Blocking |

## Coverage

The review covers all 20 existing project Markdown files and the three diagram
pages. Bundled `.codex/skills` documentation is tooling guidance, not service
documentation; its Rust and documentation rules inform this review.

The file-level outcomes are:

| Files | Outcome |
| --- | --- |
| [README](../README.md), [CONTRIBUTING](../CONTRIBUTING.md) | Correct readiness, deployment, compiler, sanitizer, and validation instructions. |
| [Setup](setup.md), [configuration](configuration.md), [BGP](bgp.md), [logging](logging.md) | Correct operator procedures and fill configuration, verification, and failure-limit gaps. |
| [Protocol](protocol.md), [S-BFD](seamless.md), [RFC 5880](rfc5880-conformance.md), [RFC conformance](rfc-conformance.md) | Correct role behavior, scope, shutdown, and test-coverage descriptions. |
| [Monitoring](monitoring.md), [security](security.md), [communication](service-communication.md), [RPC authentication](rpc-authentication.md), [RPC status](rpc-session-status-design.md) | Align identities, permissions, native build details, telemetry ownership, freshness, and failure handling. |
| [Correctness reviews](../CODE_REVIEW.md), [validation guide](../RUST_SKILLS_VALIDATION.md) | Mark superseded designs and preserve dated results. |
| [Archived audit](archive/RUST_SKILLS_VALIDATION_2026-10-01.md) | Reviewed; retain the existing historical warning and original evidence. |
| [AGENTS](../AGENTS.md), [CLAUDE](../CLAUDE.md) | Reviewed; retain applicable agent instructions. |
| [Editable diagram](service-communication.drawio) and its three PNGs | Update runtime boundaries, service lifecycle, and RPC authentication; inspect rendered output. |
| Rust source documentation | Correct stale BGP shutdown comments in `src/bgp.rs`, `src/runtime.rs`, and `src/service.rs`, and publication guarantees in `src/runtime/status.rs`; executable code is unchanged. |

## Validation and limits

The following checks pass for this documentation update:

- Build Rust API documentation with `RUSTDOCFLAGS='-D warnings -D missing-docs'`
  and `cargo doc --locked --no-deps`.
- Check Rust formatting with `cargo fmt --check`.
- Resolve 642 local Markdown references, including three images and 113
  heading/HTML-ID anchors; check 83 closed fenced blocks and parse 67 PowerShell
  examples without executing them.
- Check XML structure and regenerate and visually inspect all three PNGs with
  editable diagram data embedded. The successful retry exports each page with
  exit code zero and no error output; embedded labels match the canonical source.
- Check changed-file whitespace with `git diff --check` and confirm Rust edits
  contain comments only.

External RFC and Microsoft references were checked for the corrected protocol
and native API claims; this was not a crawl of every external URL. Historical
source-line links remain archival references. Service installation, registry
configuration, BGP changes, router interoperability, ASan, Miri, and runtime
tests were not executed for this documentation-only update.

**Rewrite plan:** factual, procedure, accessibility, and diagram corrections are
complete. To reach 10/10 on document-type separation, move dated entries from the
current validation guide into linked historical records while preserving their
anchors and evidence. That editorial split is separate from the correctness
fixes recorded here.

## Change log

The changes follow these audit rules:

| Change | Rule ID + name | Why |
| --- | --- | --- |
| Verify behavior against implementation and build scripts | P11 verified behavior | Readers need commands and explanations that match the checkout. |
| Add configuration and verification steps | P1 complete procedures; R5 verification | Operators can finish setup and confirm the intended outcome. |
| Align diagrams, alt text, and prose | S10 accessible diagrams | The same boundaries and lifecycle are available visually and in text. |
| Label historical results | V7 timeless documentation | Prior successful checks do not validate a later revision. |
