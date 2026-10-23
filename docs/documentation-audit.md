# Documentation Audit: operator and developer guides

This audit helps Windows administrators and Rust maintainers assess the
documentation against the implementation in this checkout.

**Score:** 7/10 before → 10/10 after — ready for the reviewed documentation scope.
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

**Rewrite plan:** completed: organize by supported operator and developer tasks;
verify behavior against source; replace stale descriptions; remove retired
material; then check references, examples, and API documentation.

## Coverage

The inventory includes 39 retained Markdown files: root guides and repository
instructions; operator, protocol, architecture, security, development, and
installation references; release notes; fuzz guides; and runtime provenance. Bundled skill
manuals supply editing instructions and are outside the product documentation
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

Local checks pass for all 507 file-link occurrences and 180 Markdown heading
targets across the 39 retained Markdown files. Image alt text, heading levels,
closed code fences, and all 63 PowerShell examples pass structural or syntax
checks. A source comparison confirms coverage of all 26 registry settings and
27 manifest event IDs.

Strict `cargo doc --locked --offline --no-deps` with warnings and missing public
documentation denied, all three doctests, `cargo fmt --check`, and
`git diff --check` pass. Local check receipts are under
`target/documentation-current-audit` and are ignored build output.

This is a documentation review. Runtime, ASan, fuzz, MSI installation, and VM
scenarios require their own results for the tested revision; source inspection
and successful documentation checks do not establish those outcomes. See
[development validation](development/validation.md) for the required checks.
