# Documentation audit: operator and developer guides

This audit helps Windows administrators and Rust maintainers assess the
documentation against the implementation in this checkout.

**Score:** 8/10 before → 10/10 after — ready for the reviewed structure, clarity, and implementation-contract scope.
**Shippable:** yes.
**Diagnostic:** 10/10 — failed rows: none remaining in the reviewed scope.
**Doc type / reader:** documentation-set audit for Windows administrators and Rust maintainers. **Language:** en.
**Local style guide:** [CONTRIBUTING.md](../CONTRIBUTING.md#write-and-maintain-documentation) and [AGENTS.md](../AGENTS.md); repository tone preserved.
**Blocking:** none remaining among the findings below.
**Findings:**

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| 1 | [Configuration: Authentication](configuration.md#authentication), [S-BFD](seamless.md#authentication-and-loop-prevention) | P11 verified commands and behavior | Key-storage descriptions and examples disagree with the registry loader. | Document DPAPI ciphertext, mode-specific key limits, protected Secrets ACL, and the installed administration tool. | Blocking |
| 2 | [Documentation index](README.md) and [setup](setup.md) | R2 doc type matches the reader's task | Retired deployment procedures and superseded records obscure supported operations. | Keep installation and operation guidance for the supported service. Remove obsolete documents and transition procedures. | High |
| 3 | [Authentication key administration](configuration.md#authentication-key-administration) | R5 verification and next steps | Key administration lacks a complete set/replace and peer-verification procedure. | Include stopped-service provisioning, hidden input, read-back verification, and communication checks. | Medium |
| 4 | [RPC contracts](rpc-session-status-design.md#native-interface-contract), [packaging](development/packaging.md), and [logging](logging.md) | V7 timeless | Implementation explanations mix supported contracts with change history. | Describe the active interfaces, installer transactions, and event payloads directly. | Medium |
| 5 | [Validation guide](../RUST_SKILLS_VALIDATION.md) and [code review checklist](../CODE_REVIEW.md) | R2 doc type matches the reader's task | Review indexes primarily summarize superseded revisions. | Provide reusable checks tied to implementation boundaries and explicit evidence limits. | High |
| 6 | [Registry loading](../src/config/registry.rs) and [Options validation](../src/config.rs) | P11 verified commands and behavior | API comments disagree about registry validation and key provisioning. | State that registry loading returns a validated snapshot and uses DPAPI as its key source. | Blocking |
| 7 | [Documentation index](README.md) and related guides | S9 descriptive links | Cross-references depend on removed material and obsolete heading aliases. | Link supported procedures, canonical references, and current checklists. | High |
| 8 | [Service communication](service-communication.md#runtime-behavior) and [provider reference](reference/bgp-provider.md#worker-retries-and-broker-recovery) | P11 verified commands and behavior | Idle dispatcher ownership and telemetry wake eligibility are not explicit. | Describe request/stop event waits, bounded admission, routine counter coalescing, and priority changes. | High |
| 9 | [Library development](development/library.md#raw-options-encoding-and-registry-loading) and [packet authentication](security/packet-authentication.md) | P11 verified commands and behavior | Secret ownership and programmatic field types describe the preceding implementation. | Document SecretString inputs, shared SecretSlice ownership, startup-only decryption, zeroization limits, and caller-owned encoded output. | High |
| 10 | [Dispatcher measurements](performance.md) and [telemetry measurements](performance-telemetry-coalescing.md) | R5 verification and next steps | Capture provenance could be mistaken for measurements of the combined release. | Preserve exact development-build identities and state that secrecy and the combined 6.0.0 build are outside those recordings. | High |
| 11 | [6.0.0 release notes](releases/6.0.0.md#version-and-compatibility) | R5 verification and next steps | The source migration and required major increment are undocumented. | Explain the public Rust API break, migration, compatible installed contracts, and separately scoped validation. | High |
| 12 | [Setup](setup.md#configure-and-verify-the-windows-service) | R2 doc type matches the reader's task | A second configuration checklist repeats the main procedure, and removal interrupts the installation path. | Keep one numbered setup path, move removal after operation, and retain the previous section anchor for existing links. | High |
| 13 | [Documentation index](README.md#review-performance-and-release-evidence) | R2 doc type matches the reader's task | Performance and release records are mixed into build tasks, and historical release notes have no index link. | Give measurements and release evidence their own section, with explicit build scope and a historical release link. | High |
| 14 | [BGP guide](bgp.md) | R6 key points first | The introduction summarizes the queued Start action without explaining the status check described later in the guide. | Lead with the status check and conditional mutation so the summary distinguishes BFD Up from BGP readiness. | Medium |
| 15 | [Configuration access](configuration.md#apply-changes-and-access-settings) and [log access](logging.md#read-logs-without-service-control-privileges) | P11 verified commands and behavior | Non-administrator log access reads as unconditional. | Separate service-query rights from channel and filesystem permissions. | Blocking |
| 16 | [Log destinations](logging.md#log-destinations) and [logging internals](reference/logging-internals.md#output-queue-and-loss) | R6 key points first | File mirroring can be read to include broker records; queue wording obscures the distinction between avoiding writer I/O and guaranteeing timer latency. | Limit file output to BFD service records and describe nonblocking enqueue behavior precisely. | Medium |
| 17 | [Packaging](development/packaging.md) | S2 task headings | CI validation and publication are nested under the local bundle-build task. | Promote CI and publication to top-level tasks while preserving anchor names. | Medium |
| 18 | [Dispatcher measurements](performance.md) and [telemetry measurements](performance-telemetry-coalescing.md) | R6 key points first | The earlier capture has a generic title, and readers must scan long pages to find metric tables. | Name the dispatcher capture and add direct links to CPU, context-switch, memory, ready-time, scope, and provenance sections. | Medium |

**Rewrite plan:** completed: organize by supported operator and developer tasks;
verify behavior against source; replace stale descriptions; remove retired
material; then check references, examples, and API documentation.

Rows 12–18 record the structure, clarity, and accuracy pass against commit
`fc857ae`. The initial diagnostic failed row 2 (duplicated and misplaced tasks)
and row 3 (ambiguous summaries of verified behavior). Rows 1–11 retain the
earlier implementation-alignment findings. The completed pass changes prose
and navigation; it does not change application code, measured data, release
versions, or the scope of earlier runtime results.

## Coverage

The inventory includes 42 retained Markdown files: root guides and repository
instructions; operator, protocol, architecture, security, development, and
installation references; release notes; measured performance references; fuzz
guides; and runtime provenance. Bundled skill manuals supply editing instructions
and are outside the product documentation
set. Rust configuration API comments are included where they describe the
operator-facing contract.

The three PNG diagrams, their editable Draw.io pages, and Mermaid views were
checked for service identities, privilege policy, RPC direction, status
freshness, and shutdown ownership. Their content remains aligned with the
implementation; no diagram regeneration is needed.

## Source verification

Use these canonical references to maintain the contracts:

| Contract | Documentation | Implementation |
| --- | --- | --- |
| Registry settings, defaults, and key administration | [Configuration](configuration.md) | [Registry loader](../src/config/registry.rs), [DPAPI owner](../src/config/dpapi.rs), and [administration script](../scripts/Set-BfdAuthenticationKey.ps1) |
| Accounts, privileges, ACLs, and firewall rules | [Service isolation](security/service-isolation.md) and [installed resources](reference/installation.md) | [Package](../installer/Package.wxs), [service identity](../src/service_identity.rs), and [privilege validator](../src/runtime/privileges.rs) |
| Packet formats, authentication, timers, and protocol limits | [Protocol behavior](protocol.md) and [conformance](rfc-conformance.md) | [Packet codec](../src/packet.rs), [classical session](../src/session.rs), and [S-BFD implementation](../src/seamless.rs) |
| Event IDs, severity, queues, and rotation | [Logs and events](logging.md) and [logging internals](reference/logging-internals.md) | [Manifest](../events/BFD-Service.man) and [output worker](../src/runtime/logging.rs) |
| RPC schema, identity gates, and timeout budgets | [RPC security](security/local-rpc.md) and [status contract](rpc-session-status-design.md) | [Telemetry IDL](../rpc/bfd_local.idl), [control IDL](../rpc/bgp_control.idl), [telemetry](../src/local_rpc.rs), and [BGP IPC](../src/bgp/ipc.rs) |
| Build, test, and release commands | [Development validation](development/validation.md) and [packaging](development/packaging.md) | [Cargo configuration](../.cargo/config.toml), [workflow](../.github/workflows/build-msi.yml), and [scripts](../scripts) |

Microsoft's [DPAPI contract](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
supports the machine-scope and optional-entropy description. The RFC Editor's
[verified-errata rendering](https://www.rfc-editor.org/rfc/inline-errata/rfc5880.html)
supports the correction list in the conformance reference. Other external links
are reference material; this audit does not claim exhaustive network checking.

## Validation and limits

Local checks cover file-link occurrences and Markdown heading targets across
the 42 retained Markdown files. Image alt text, heading levels,
closed code fences, and all 63 PowerShell examples pass structural or syntax
checks. A source comparison confirms coverage of all 26 registry settings and
27 manifest event IDs.

Strict `cargo doc --locked --no-deps` with warnings and missing public
documentation denied, all three doctests, `cargo fmt --check`, and
`git diff --check` pass. Local check receipts are under
`target/documentation-current-audit` and are ignored build output.

This is a documentation review. Runtime, ASan, fuzz, MSI installation, and VM
scenarios require their own results for the tested revision; source inspection
and successful documentation checks do not establish those outcomes. See
[development validation](development/validation.md) for the required checks.

The 6.0.0 review also checked every changed prose description against the
dispatcher, status publisher, configuration loader, DPAPI owner, and packet
authentication implementation. Existing diagram labels describe a minimum
publication spacing and refresh target, so they remain accurate. Historical
5.0.0 release notes retain their original validation scope. The
[6.0.0 validation record](releases/6.0.0.md#validation) owns combined-build results;
the performance pages own their earlier recordings and raw numeric data.
