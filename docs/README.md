# Documentation

For Windows administrators and service maintainers, this index groups the guides
by task. Start with the [project quick start](../README.md#quick-start) for a first
installation, then use the references for configuration, operation, or development.
Dated review records describe the checks performed on their recorded revisions.

## Install and operate the service

Choose the guide for your operational task:

| Task | Guide |
| --- | --- |
| Install, configure, verify, run in a console, or remove the service | [Set up a BFD session](setup.md) |
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

Use these references to trace a boundary or implementation contract:

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

Use these guides for development and implementation checks:

| Task | Guide |
| --- | --- |
| Build, test, prepare deployment files, update diagrams, or contribute changes | [Contribute to BFD Windows service](../CONTRIBUTING.md) |
| Find RFC 5880, RFC 7419, and RFC 7880 requirements and their test coverage | [RFC conformance tests](rfc-conformance.md) |
| Review the RFC 5880 behavior matrix and implementation limits | [RFC 5880 conformance](rfc5880-conformance.md) |
| Find API review guidance, ownership boundaries, and validation commands | [Rust skills validation](../RUST_SKILLS_VALIDATION.md) |

## Review evidence and repository instructions

These records and instructions have distinct purposes:

| Document | Purpose |
| --- | --- |
| [Dated correctness reviews](../CODE_REVIEW.md) | Recorded review findings, checks, revisions, and limits |
| [Documentation audit](documentation-audit.md) | Documentation findings, corrections, review coverage, and validation scope |
| [Archived Rust skills audit](archive/RUST_SKILLS_VALIDATION_2026-10-01.md) | Historical findings retained with their original evidence and supersession warning |
| [AGENTS instructions](../AGENTS.md) and [CLAUDE instructions](../CLAUDE.md) | Repository-specific instructions for coding agents |

Use the current guides for commands and configuration. Keep historical results
tied to their dates and revisions when assessing validation evidence.
