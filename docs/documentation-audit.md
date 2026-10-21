# Documentation Audit: repository guides and diagrams

Maintainers, here's the documentation audit with the receipts attached, dude.
This record explains the corrections checked against the source, tests,
installer, and build configuration on 2026-10-15. These are documentation
receipts; the older runtime test results keep their original dates and
validation limits. A style glow-up doesn't rerun a test, for sure. Even turtle
power needs fresh receipts.

The [source, correctness, and diagram review](#source-correctness-and-diagram-review--2026-10-15)
records the earlier corrections. The
[structure and navigation review](#structure-and-navigation-review--2026-10-15)
records the subsequent organization pass, including its separate validation scope.

## Source, correctness, and diagram review — 2026-10-15

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

### Findings

Cowabunga, audit crew. Follow each correction to its evidence. Here's the
corrected-finding lineup; follow the links for the details:

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Build security](../CONTRIBUTING.md#build-security), [native RPC compiler options](security/build-hardening.md#native-rpc-compiler-options) | P11 verified behavior | Described a Rust-only build with no C compilation. | Describe generated MIDL stubs, the three C bridge files, actual MSVC flags, and the Rust-only scope of ASan instrumentation. | Blocking |
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

### Coverage

Keep the reviewed scope clear, turtle crew. The review covers all 20 existing
project Markdown files and the three diagram pages. Bundled `.codex/skills`
documentation is tooling guidance, not service documentation; its Rust and
documentation rules inform this review.

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

### Validation and limits

Donatello would separate recorded checks from work not exercised. These are the
recorded checks for the source, correctness, and diagram review, buddy:

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

### Change log

The changes follow this audit-rule lineup:

| Change | Rule ID + name | Why |
| --- | --- | --- |
| Verify behavior against implementation and build scripts | P11 verified behavior | Readers need commands and explanations that match the checkout. |
| Add configuration and verification steps | P1 complete procedures; R5 verification | Operators can finish setup and confirm the intended outcome. |
| Align diagrams, alt text, and prose | S10 accessible diagrams | The same boundaries and lifecycle are available visually and in text. |
| Label historical results | V7 timeless documentation | Prior successful checks do not validate a later revision. |

## Structure and navigation review — 2026-10-15

For admins finding their operational groove and maintainers finding an
implementation reference, this pass reviews the complete project Markdown set
for structure, clarity, and organization. Existing Gen-Z and surfer slang stays
in place. Technical contracts, examples, dated evidence, and diagrams retain
their meanings and content.

**Score:** 9/10 → 9/10 — ships as is. **Shippable:** yes for this editorial scope.

**Diagnostic:** 9/10 — failed rows: 2 (the validation guide retains current
reference material and dated validation records in one document, now separated
and ordered explicitly).

**Doc type / reader:** documentation-set audit for Windows administrators and
Rust maintainers. **Language:** en.

**Local style guide:** repository contributor instructions and existing Markdown
conventions. The explicit request to preserve slang takes precedence over voice
rules that would remove idioms or conversational phrasing. Historical titles and
evidence remain recognizable.

**Blocking:** none found in the requested structure and organization scope.
This pass does not repeat the earlier behavioral audit, external-reference
verification, or runtime validation.

### Organization findings

Here's the corrected-finding lineup; follow the links for the details:

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Documentation index (line 1)](README.md), [project documentation links (line 119)](../README.md#documentation) | R6 key points first | Operator tasks, implementation references, and review evidence shared one long README table. | Add a complete index grouped by operational tasks, architecture, development, and evidence; keep common starting points in the project README. | Medium |
| 2 | [Setup routes (line 1)](setup.md), [BGP configuration (line 30)](bgp.md#configure-the-peer) | R6 key points first | Resource/security detail preceded installation or configuration; related tasks were spread across broad sections. | Put the operational route first and separate configuration, verification, shutdown, and supporting internals. | Medium |
| 3 | [Configuration (line 1)](configuration.md), [logs (line 1)](logging.md), [monitoring (line 1)](monitoring.md) | S2 descriptive task and concept headings | Validation, reload, queue behavior, permissions, and diagnosis were harder to locate within broad sections. | Give those topics explicit headings and keep prerequisites with their procedures. | Medium |
| 4 | [Security topics (line 23)](security.md#find-a-security-topic), [RPC topics (line 20)](rpc-authentication.md#find-an-rpc-topic) | R6 key points first | Long security references required scrolling to locate one boundary or API responsibility. | Add section navigation and a boundary-to-section map while retaining all function-call diagrams and slang. | Medium |
| 5 | [RPC startup sequence (line 105)](rpc-authentication.md#startup-and-query-sequence) | A7 descriptive reference text | A description of service startup mixed descriptive steps with commands to the reader. | Name the broker, BFD, client, or monitor as the actor throughout the sequence. | Low |
| 6 | [Protocol (line 1)](protocol.md), [S-BFD (line 1)](seamless.md), [RPC status contract (line 1)](rpc-session-status-design.md) | S2 descriptive task and concept headings | Transport, timing, live updates, status freshness, retries, and cleanup shared long sections. | Add focused subsections, role entry points, and links to operator procedures. | Medium |
| 7 | [RFC validation (line 124)](rfc-conformance.md#run-and-interpret-validation) | R3 prerequisites before steps (convention) | The ASan runtime prerequisite appeared after the commands. | Put prerequisites before execution and separate coverage from deployment limits. | High |
| 8 | [RFC 5880 requirement mapping (line 28)](rfc5880-conformance.md#requirement-mapping) | S8 explicit cross-references | A requirement row referred to limits "below." | Link directly to the named deployment-limits section and categorize limits and evidence. | Medium |
| 9 | [Contributor tasks (line 11)](../CONTRIBUTING.md#choose-a-development-task), [current validation (line 53)](../RUST_SKILLS_VALIDATION.md#current-api-and-validation) | R6 key points first | Development tasks lacked a short route map; current commands followed hundreds of lines of review history. | Add task navigation and move current commands, API guidance, and ownership boundaries before the grouped historical records. | Medium |
| 10 | [Review topics (line 10)](../CODE_REVIEW.md#find-a-review), [archived audit navigation (line 7)](archive/RUST_SKILLS_VALIDATION_2026-10-01.md#navigate-this-snapshot) | R6 key points first | Readers had to scan dated entries or a long rule matrix to locate evidence. | Add topic links while preserving historical bodies, counts, dates, and existing anchors. | Medium |

### Organization coverage

Track the complete documentation lineup before the pizza break. The review
covers the 21 existing project Markdown files and the new
[documentation index](README.md), for 22 repository documents. The ignored local
`bird-anycast-lab/README.md` was also read and left unchanged. Bundled skill
documentation remains tooling guidance outside this project-documentation scope.

All operator, protocol, security, RPC, contributor, validation, and historical
pages were read. [Service communication](service-communication.md) already has a
clear overview-to-detail flow and accessible diagram descriptions; it needs no
editorial change. [AGENTS](../AGENTS.md) and [CLAUDE](../CLAUDE.md) retain their
applicable repository instructions. The earlier audit remains a separate record
with its original validation claims.

### Organization validation and limits

Turtle power needs explicit editorial checks and validation limits. The recorded
editorial vibe check passes across all 22 repository documents:

- Resolve 813 local references, including 252 heading/HTML-anchor references.
- Check heading hierarchy and retain every original heading/HTML anchor.
- Check all 85 closed fenced examples against the pre-edit snapshot; their
  contents are unchanged.
- Preserve all 40 original slang-bearing prose paragraphs, apart from whitespace.
- Confirm that changes affect Markdown only; the ASCII diagrams, editable draw.io
  source, PNG exports, and executable source are unchanged.
- Check changed-file whitespace with `git diff --check`.

Historical source-line fragments remain archival references; this check confirms
that the target files exist without asserting the old line locations.

This pass changes Markdown only. It does not execute setup commands, install
services, change registry settings or BGP state, or rerun runtime tests. Earlier
test counts and diagram-export results belong to the preceding review.

**Rewrite plan:** the requested navigation, section-order, and clarity changes
are complete. A separate split of dated validation entries into historical
documents would address the remaining document-type issue; retain the evidence
and provide compatibility links if that split is made.

### Organization change log

The changes follow this audit-rule lineup:

| Change | Rule ID + name | Why |
| --- | --- | --- |
| Group the documentation map by reader task | R2 document type matches the task (inferred taxonomy) | Operators and maintainers can choose a guide without scanning unrelated material. |
| Put procedures and current references before supporting detail/history | R6 key points first | Readers reach the action or contract they need sooner. |
| Add focused section headings and prerequisite placement | S2 descriptive headings; R3 prerequisites before steps (convention) | Readers can scan long pages and prepare before executing examples. |
| Preserve old anchors and add descriptive links | S9 descriptive navigation links | Existing references remain valid while related topics become easier to find. |
| Preserve slang, examples, diagrams, and historical evidence | P11 verified behavior | An editorial pass must preserve technical meaning and the requested voice. |
