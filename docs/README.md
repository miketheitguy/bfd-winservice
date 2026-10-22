# Documentation

Cowabunga, Windows admins and service maintainers! Like, here's your trail map.
This index groups the guides by task, so you can find your line and cruise.
Start with the [project quick start](../README.md#quick-start) for a first
installation, then use the references for configuration, operation, or
development. Dated review records describe the checks performed on their
recorded revisions.

The operational references describe the service-only design introduced in
[v4.0.0](releases/4.0.0.md). For the release boundary and removed interfaces, see
[migration and revision scope](console.md#revision-scope).

## Install and operate the service

Cowabunga, deployment crew. Pick the guide for your mission:

| Task | Guide |
| --- | --- |
| Install, configure, verify, or remove the service | [Set up a BFD session](setup.md) |
| Migrate an older foreground deployment | [Migrate to services](console.md) |
| Inspect installed files, services, defaults, and firewall rules | [Installation inventory](reference/installation.md) |
| Look up registry values, defaults, validation rules, and reload behavior | [Registry configuration reference](configuration.md) |
| Configure an S-BFD initiator, reflector, or anycast target | [Configure Seamless BFD](seamless.md) |
| Connect BFD state changes to a Windows BGP peer | [Control a Windows BGP peer](bgp.md) |
| Query lifecycle status, verify BFD state, or diagnose broker telemetry | [Monitor service status and BFD events](monitoring.md) |
| Enable file output or interpret Operational events | [Logs and events](logging.md) |
| Check ports, firewall requirements, and supported protocol behavior | [Network and protocol behavior](protocol.md) |

For a first session, follow setup through peer verification before adding optional
BGP control. For an existing installation, use monitoring to distinguish process
lifecycle, protocol state, and broker telemetry.

## Understand the architecture and security

Think like Donatello: follow the connections and check the boundaries. For the
architecture deep dive, these references bring the receipts:

| Question | Reference |
| --- | --- |
| How do packet processing, telemetry, BGP actions, and shutdown connect? | [Service communication](service-communication.md), with runtime, lifecycle, and authentication diagrams |
| Which identities, permissions, authentication checks, and build protections apply? | [Security overview](security.md), with focused references for service isolation, packets, local RPC call flows, and build hardening |
| Which Windows RPC settings and per-call checks authenticate the two services? | [Local RPC authentication and authorization](rpc-authentication.md) |
| What are the status fields, accepted ranges, freshness rules, and failure policies? | [RPC session-status query](rpc-session-status-design.md) |

The service communication page provides the process overview. The security guide
maps each trust boundary to a focused reference; the RPC API and status-contract
references provide additional implementation detail.

## Build and validate changes

Turtle power needs build and test receipts, dude:

| Task | Guide |
| --- | --- |
| Set up a build host or contribute changes | [Contributor guide](../CONTRIBUTING.md) |
| Run required, optimized, ASan, Miri, or native checks | [Development validation](development/validation.md) |
| Change library APIs or service boundaries | [Library development](development/library.md) |
| Prepare deployment files, build installers, or publish a release | [Packaging and releases](development/packaging.md) |
| Update Mermaid and Draw.io views | [Diagram maintenance](development/diagrams.md) |
| Fuzz packet acceptance and rejection, classical sessions, or stateful S-BFD initiation and reflection | [Fuzz harness guide](../fuzz/README.md) and [security scope](security/fuzzing.md) |
| Find RFC 5880, RFC 7419, and RFC 7880 requirements and their test coverage | [RFC conformance tests](rfc-conformance.md) |
| Review the RFC 5880 behavior matrix and implementation limits | [RFC 5880 conformance](rfc5880-conformance.md) |
| Interpret dated validation results and review ownership boundaries | [Rust skills validation](../RUST_SKILLS_VALIDATION.md) |

## Review evidence and repository instructions

Even heroes in a half-shell check the dates on their evidence, no cap:

| Document | Purpose |
| --- | --- |
| [Dated correctness reviews](../CODE_REVIEW.md) | Recorded review findings, checks, revisions, and limits |
| [Service-only validation](service-only-validation-2026-10-22.md) | Host, installed-token, installer, and Windows/Ubuntu scenario results for the working tree after v3.0.2 |
| [v4.0.0 release notes](releases/4.0.0.md) | Service-only execution, read-only token validation, removed public APIs, and migration steps |
| [Code, tests, and documentation alignment audit](alignment-audit-2026-10-21.md) | Findings, fixes, release validation, and remaining coverage limits |
| [v2.0.1 release notes](releases/2.0.1.md) | Patch compatibility rationale and corrected deployment behavior |
| [Windows BGP withdrawal and recovery validation](windows-bgp-interop-2026-10-22.md) | RRAS compatibility defects, route-table checks, event messages, and measured recovery |
| [v2.0.2 release notes](releases/2.0.2.md) | Automatic RRAS recovery fixes and patch compatibility rationale |
| [v3.0.0 release notes](releases/3.0.0.md) | Meticulous MD5, keyed-SHA1 reuse, independent services, and public API compatibility impact |
| [v3.0.1 release notes](releases/3.0.1.md) | File-logging-independent BGP failure events and native UDP fixture fixes |
| [v3.0.2 release notes](releases/3.0.2.md) | SCM privilege minimums and exact installer rollback policy for the published release |
| [Documentation audit](documentation-audit.md) | Documentation findings, corrections, review coverage, and validation scope |
| [Archived Rust skills audit](archive/RUST_SKILLS_VALIDATION_2026-10-01.md) | Historical findings retained with their original evidence and supersession warning |
| [AGENTS instructions](../AGENTS.md) and [CLAUDE instructions](../CLAUDE.md) | Repository-specific instructions for coding agents |

Use the current guides for commands and configuration. Keep historical results
tied to their dates and revisions when assessing validation evidence. Old test
results don't earn a fresh victory lap.

## Implementation references

For deeper troubleshooting and maintenance, follow the contracts rather than
copying their details into another guide:

| Topic | Reference |
| --- | --- |
| Native MI methods, provider queues, watchdogs, and cleanup budgets | [BGP provider](reference/bgp-provider.md) |
| Logger queues, buffering, loss, and shutdown ownership | [Logging internals](reference/logging-internals.md) |
| Implementation files by responsibility | [Source map](reference/source-map.md) |
| Removal of older manually provisioned services | [Legacy removal](reference/legacy-installation.md) |
