# Documentation Audit: service-only guides and references

Cowabunga, documentation crew. This 2026-10-22 audit checks the repository's
operator, developer, security, API, release, and historical documentation against
the service-only working tree based on v3.0.2 (`2a95110`). Use the
[migration guide](console.md#revision-scope) to distinguish these sources from
the published v3.0.2 assets. The
[earlier v2.0.2 audit](archive/documentation-audit-2026-10-22-baseline.md)
retains its original findings, diagram checks, and validation scope.

**Score:** 8/10 before → 10/10 after — shippable for the reviewed documentation
scope. **Shippable:** yes. **Diagnostic:** 10/10 — failed rows: none remaining
in the maintained guidance. The baseline failed rows 3 (verified commands and
behavior) and 8 (navigation and cross-references).

**Doc type / reader:** documentation-set audit for Windows operators, Rust
maintainers, and release reviewers. **Language:** en. **Local style guide:**
AGENTS.md and CONTRIBUTING.md; the established conversational house style is
preserved. **Blocking:** none remaining among the findings below. This score
is an editorial assessment, not a security certification or a fresh runtime test.

## Findings

The audit resolves these documentation gaps:

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Configuration](configuration.md#apply-changes-and-access-settings) | P11 verified commands and behavior | Two passages still describe console execution and its BGP guard. | Describe elevated registry administration and installed-service configuration. | Blocking |
| 2 | [Migration scope](console.md#revision-scope), [README](../README.md), and [index](README.md) | P11 verified commands and behavior | Service-only guidance can be mistaken for the published v3.0.2 contract. | Identify the unreleased working tree, private package version, removed interfaces, and major-release requirement. | Blocking |
| 3 | [Service isolation](security/service-isolation.md#diagnose-a-startup-token-policy-failure) and [library development](development/library.md#service-entry-and-token-policy) | R5 verification and next steps | Startup rejection has no focused policy inspection procedure; library migration omits logger construction details. | Document read-only SCM queries, expected policy, repair/restart, exact token checks, and replacement APIs. | High |
| 4 | [Packaging](development/packaging.md#build-with-github-actions) and [validation](development/validation.md#validate-installed-service-security-in-a-disposable-vm) | P11 verified commands and behavior | Installer descriptions say hosted runners only and omit excessive-privilege rejection coverage. | Include the guarded disposable-VM path, actual token checks, policy rejection/recovery, and PE-only version checks. | Blocking |
| 5 | [Packet format](protocol.md#control-packet-format) and [RPC verification](security/local-rpc.md#verify-the-implementation) | P11 verified commands and behavior | Packet lengths omit meticulous MD5; authorization coverage counts four broker operations. | Include the 48-byte MD5 packet and the three functional Get/Start/Stop operations in the IDL. | Blocking |
| 6 | [BGP administration](bgp.md#administrative-disablement-and-failures), [monitoring](monitoring.md), and [logging](logging.md) | P11 verified commands and behavior | Local AdminDown is described as stop-only; the event span omits 113; file-log setup still tells readers to copy the installed script. | Include fatal-error cleanup, events 100–113, bundle-installed script provisioning, and service restart wording. | Medium |
| 7 | [Logging internals](reference/logging-internals.md#library-api), [source map](reference/source-map.md), and logger API comments | A1 document public API behavior | Logger constructor/mode details and read-only privilege ownership are incomplete; a flush comment contradicts service cleanup. | Describe both mode-free constructors, ETW/file destinations, read-only validation, test-only reduction, and cleanup flushes. | Medium |
| 8 | [Logging anchors](logging.md#packet-text) and historical records | S8 descriptive, durable cross-references | A dated audit links to a removed logging heading. | Retain the legacy HTML anchors without restoring foreground guidance. | High |
| 9 | [Validation record](service-only-validation-2026-10-22.md), [validation index](../RUST_SKILLS_VALIDATION.md), and [review history](../CODE_REVIEW.md) | R6 key points first | The complete service-only VM receipts are local-only and absent from the maintained evidence map. | Add a dated, scoped summary of existing results and local receipt locations, including harness failures and coverage limits. | Medium |
| 10 | [Documentation index](README.md#review-evidence-and-repository-instructions) and [release procedure](development/packaging.md#tag-and-publish-the-release) | S9 descriptive links; N4 breaking-change migration | The index omits v3 release notes; the release procedure does not mention retiring the working-tree notices. | Link all five release-note files and require matching notes, migration, and scope updates when preparing the major release. | Medium |

**Rewrite plan:** completed: verify the service entry points and SCM/token
policy; correct stale operator and implementation guidance; expand migration
and disposable-host validation references; preserve dated evidence; then check
navigation, samples, and API documentation. Historical claims were not rewritten
as current test results.

## Information ownership

Keep each contract in its canonical reference:

| Detail | Canonical home |
| --- | --- |
| Release boundary, removed flags, and library migration | [Service migration](console.md) |
| Registry names, defaults, types, and combinations | [Configuration](configuration.md) |
| Network ports, packet formats, path checks, and shutdown | [Protocol behavior](protocol.md) |
| BGP state-to-action policy | [BGP operations](bgp.md) |
| Native provider methods, queues, watchdogs, and cleanup budgets | [BGP provider reference](reference/bgp-provider.md) |
| Event IDs, meanings, destinations, and file configuration | [Logs and events](logging.md) |
| Output-worker ownership, buffering, flushes, and logger APIs | [Logging internals](reference/logging-internals.md) |
| Service accounts, restricted SIDs, privilege validation, and repair | [Service isolation](security/service-isolation.md) |
| RPC identity matrix and visual overview | [RPC authentication](rpc-authentication.md) |
| Native RPC settings, Authz parsing, and call flows | [Local RPC security](security/local-rpc.md) |
| Status schema, cadence, freshness, retry, and quarantine | [Session-status contract](rpc-session-status-design.md) |
| Compiler protections and production artifact verification | [Build hardening](security/build-hardening.md) |
| Checkout checks, packaging, library work, and diagrams | [Development guide map](../CONTRIBUTING.md#choose-a-development-task) |

## Change log

These edits improve source alignment without changing daemon behavior:

| Area | Change |
| --- | --- |
| Operators | Complete foreground-to-service migration, protected log-path guidance, version inspection, and token-policy diagnosis. |
| Maintainers | Document mode-free APIs, service entry checks, test-only token reduction, disposable-host validation, and release handoff. |
| Evidence | Preserve the preceding audit and published notes; link the completed service-only VM results with their original revision and limits. |
| Navigation | Restore legacy logging anchors, list v3 release notes, and connect the current validation and source maps. |

## Coverage and validation

The inventory covers 52 product/repository Markdown files, including root
guides and agent instructions, operator and architecture guides, security and
RFC references, development and installation references, fuzz documentation,
runtime provenance, all five release-note files, and dated records. Bundled
skill manuals are external guidance and were not rewritten. Historical records
were checked for scope, supersession, and navigation; their old API examples,
counts, hashes, and runtime claims remain historical evidence.

Source checks cover the service entry points, token validator and fixture,
logger constructors and cleanup, RPC IDL and rejection fixtures, installer
script guards, version checker, workflow, packet codec, and conformance tests.
The audit also checks the three existing Mermaid/Draw.io/PNG views for the
service identities, read-only startup checks, RPC direction, and ownership
contract established by the implementation change. This documentation pass does
not regenerate or claim a new rendering of the diagrams.
The 25 runtime, 28 lifecycle, and 28 authentication labels in the PNGs'
embedded editable XML match their corresponding Draw.io source pages.

Microsoft's [required service privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow),
[service SID types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info),
and [service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
were checked against the token and operational guidance. Other external URLs
were inventoried, not exhaustively network-tested.

Validation checks local file and Markdown-heading destinations, legacy aliases,
image alt text, heading levels, closed code fences, and PowerShell syntax using
the Windows PowerShell 5.1 parser. All 1,088 local link occurrences, including
324 Markdown-heading targets, resolve, and all 70 PowerShell samples parse.
Strict rustdoc with warnings and missing public
API documentation denied, formatting, all three doctests, and whitespace checks
passed. The local check receipts are under
`target/documentation-service-only-audit/`; they are ignored output, not bundled
repository files. No full native, ASan, fuzz campaign, installer, or VM scenario
suite was rerun for this documentation pass. The
[service-only validation record](service-only-validation-2026-10-22.md) preserves
the already completed runtime checks and their limits.

## Release preparation follow-up

After this audit, [v4.0.0 release notes](releases/4.0.0.md) were added and the
README, documentation index, and migration scope were updated to identify that
release. The counts above describe the preceding documentation pass. Release
preparation checks include the additional notes and version-stamped sources;
their local receipts are under `target/release-v4.0.0-prep/`. The VM results
remain the pre-stamping observations in the dated validation record.
