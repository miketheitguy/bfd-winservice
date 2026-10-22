# Archived documentation audit — v2.0.2 baseline

This record describes the documentation review based on `b6248aa`. Its counts,
unchanged-diagram hashes, commands, and validation results belong to that
revision. See the [current documentation audit](../documentation-audit.md)
for the service-only design and current navigation checks.

# Documentation audit: guides, references, and diagrams

Cowabunga, documentation crew. This 2026-10-22 review covers clarity, repeated
information, source alignment, navigation, and both diagram formats. Baseline:
`b6248aa` (v2.0.2). The [previous review](../archive/documentation-audit-2026-10-15.md)
keeps its original dated findings and validation scope.

**Score:** 8/10 before → 10/10 after — ready for the reviewed documentation scope.
**Shippable:** yes. **Diagnostic:** 10/10 — failed rows: none remaining in the
current guides. The baseline failed rows 2 (mixed document jobs) and 3
(incorrect facts/procedure).

**Doc type / reader:** guide-set audit for Windows operators and Rust maintainers.
**Language:** en. **Local style guide:** AGENTS.md, CONTRIBUTING.md, and the
user's explicit instruction to retain slang and both image formats. **Blocking:**
none remaining among the findings below. This editorial score does not certify
every deployment or replace runtime validation.

## Findings

The findings are resolved in the linked canonical guides:

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Production artifact check](../security/build-hardening.md#check-the-production-executable) | P11 verified commands and behavior | A debug hardening harness inspected a release image and required incompatible debug output. | Compile the release harness first, rebuild production images, invoke that harness directly, and restore the image-selection variable. | Blocking |
| 2 | [Packet security](../security/packet-authentication.md) | P11 verified commands and behavior | The text counted four installed firewall rules. | Link to the canonical five-rule installation inventory. | Blocking |
| 3 | [RFC test coverage](../rfc-conformance.md) | P11 verified commands and behavior | The reflector row claimed four keyed authentication types. | Describe the two supported keyed SHA-1 modes, matching `tests/rfc7880.rs`. | Blocking |
| 4 | [Fuzz wrapper](../../fuzz/README.md) | P11 verified commands and behavior | The wrapper description said three targets. | Describe all four targets; keep assertion and mutation details in the security reference. | Blocking |
| 5 | [RFC validation](../rfc-conformance.md#run-and-interpret-validation) | R3 prerequisites before steps (convention) | A direct ASan command omitted initialization in the same shell. | Use the wrapper that initializes and verifies the selected MSVC runtime. | High |
| 6 | [Contributor guide](../../CONTRIBUTING.md) and [setup](../setup.md) | R2 document type matches task | Build, installer internals, console execution, inventory, and operator steps competed on the same pages. | Link focused development, console, installation, and legacy-removal documents. | High |
| 7 | [RPC overview](../rpc-authentication.md), [security map](../security.md), and [monitoring](../monitoring.md) | R6 key points first | API arguments, timing policies, source maps, and identity explanations repeated across guides. | Keep native API details in local RPC security, exact telemetry policy in the status contract, and operator responses in monitoring. | Medium |
| 8 | [Runtime/lifecycle views](../service-communication.md) and [authentication view](../rpc-authentication.md#rpc-authentication-flow) | R6 key points first | Tall stacked Mermaid groups and dense labels differed from the Draw.io views. | Use process columns, rounded white boundaries/cards, matching colors, shorter labels, and accessible titles/descriptions; retain PNGs and Draw.io bytes. | Medium |

**Rewrite plan:** completed in order: correct factual/procedural gaps, separate
reader tasks, establish canonical references, shorten repeated prose, restyle
and inspect Mermaid, then check navigation and samples. Slang remains part of
the house style, dude.

## Information ownership

Keep future edits in the page that owns the detail:

| Detail | Canonical home |
| --- | --- |
| Registry names, defaults, types, and combinations | [Configuration](../configuration.md) |
| Network ports, path checks, and protocol shutdown | [Protocol behavior](../protocol.md) |
| BGP state-to-action policy | [BGP operations](../bgp.md) |
| Native provider methods, queues, watchdogs, and cleanup budgets | [BGP provider reference](../reference/bgp-provider.md) |
| Event IDs, meanings, destinations, and file configuration | [Logs and events](../logging.md) |
| Output-worker sizes, buffering, flushes, and logger APIs | [Logging internals](../reference/logging-internals.md) |
| RPC account/service-SID matrix and visual overview | [RPC authentication](../rpc-authentication.md) |
| Native RPC settings, Authz parsing, and call flows | [Local RPC security](../security/local-rpc.md) |
| Status schema, cadence, freshness, retry, and quarantine | [Session-status contract](../rpc-session-status-design.md) |
| Build protections and production artifact verification | [Build hardening](../security/build-hardening.md) |
| Checkout checks, packaging, library work, and diagram maintenance | [Development guide map](../../CONTRIBUTING.md#choose-a-development-task) |

## Coverage and validation

The review inventoried all 34 original project Markdown files: root guides,
operator and architecture documents, security and RFC references, the fuzz
guide, release notes, runtime provenance, and historical records. Bundled skill
manuals are external guidance, not product documentation. Repository agent
instructions and published release notes retain their content. Dated review
records retain their evidence; navigation links follow moved references.

The resulting set has 46 Markdown files, including focused references and the
archived prior documentation audit. Verification includes local file/heading
links, heading levels, closed code fences, PowerShell syntax, and whitespace.
All three Mermaid diagrams render successfully and were inspected for readable
labels, process ownership, call directions, and preserved authentication gates.
SHA-256 checks confirm that the three PNGs and editable Draw.io source are unchanged.

The corrected production hardening procedure was executed successfully: both
production images passed the release harness. These documentation changes do
not change Rust, native code, installer behavior, or protocol defaults. The
strict API documentation build also passed. A check for repeated prose found
no identical long paragraphs across the current guides, excluding historical
records and intentional diagram/code repetition. The
full Rust, ASan, fuzz, installer, and failure-injection suites were not rerun
for this prose/layout change. Historical runtime results keep their original
revisions and timers; the [lab record](../windows-bgp-interop-2026-10-22.md) separately
records the requested running-lab timer change.
