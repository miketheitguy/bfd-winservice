# Documentation

Cowabunga, Windows administrators and service maintainers. Choose a guide for
the task you need to complete. Start with the [project quick start](../README.md#quick-start)
for a first installation.

## Install and operate the service

Use these guides to configure and verify your deployment:

| Task | Guide |
| --- | --- |
| Install, configure, verify, stop, or remove the service | [Set up a BFD session](setup.md) |
| Inspect installed files, services, defaults, and firewall rules | [Installation inventory](reference/installation.md) |
| Look up registry values, validation, and reload behavior | [Registry configuration](configuration.md) |
| Set or update the DPAPI-protected authentication key | [Authentication key administration](configuration.md#authentication-key-administration) |
| Configure an S-BFD initiator, reflector, or anycast target | [Configure Seamless BFD](seamless.md) |
| Connect BFD state to a Windows BGP peer | [Control a Windows BGP peer](bgp.md) |
| Query service lifecycle and interpret BFD events | [Monitoring](monitoring.md) |
| Configure file output and interpret Operational events | [Logs and events](logging.md) |
| Check network requirements and protocol behavior | [Network and protocol behavior](protocol.md) |

## Understand architecture and security

Follow each boundary to its reference:

| Topic | Reference |
| --- | --- |
| Packet processing, telemetry, BGP control, and shutdown | [Service communication](service-communication.md) |
| Service identities, protected objects, authentication, and build protections | [Security overview](security.md) |
| Windows RPC identity and per-call authorization | [RPC authentication](rpc-authentication.md) |
| Status fields, data validation, freshness, and recovery | [RPC session-status contract](rpc-session-status-design.md) |
| Provider queues, native operations, and cleanup budgets | [BGP provider](reference/bgp-provider.md) |
| Logger queues, buffering, output loss, and ownership | [Logging internals](reference/logging-internals.md) |
| Source files by responsibility | [Implementation source map](reference/source-map.md) |

## Build and validate changes

Choose a development task:

| Task | Guide |
| --- | --- |
| Prepare a build host and contribute changes | [Contributor guide](../CONTRIBUTING.md) |
| Run required, optimized, ASan, Miri, or native checks | [Development validation](development/validation.md) |
| Change Rust configuration, engine, and service APIs | [Library development](development/library.md) |
| Build deployment files and publish a release | [Packaging and releases](development/packaging.md) |
| Maintain the diagram source and rendered views | [Diagram maintenance](development/diagrams.md) |
| Fuzz packet, session, initiator, and reflector behavior | [Fuzz harness](../fuzz/README.md) and [security scope](security/fuzzing.md) |
| Map RFC requirements to implementation and tests | [RFC conformance tests](rfc-conformance.md) and [RFC 5880 review](rfc5880-conformance.md) |
| Review correctness, ownership, and security boundaries | [Code review checklist](../CODE_REVIEW.md) |
| Select validation scope and record evidence | [Rust validation guide](../RUST_SKILLS_VALIDATION.md) |

## Performance

Use the [performance section](performance.md) for the latest verified service
measurements from version 6.0.0 or later.

## Release notes

Use these records for version changes, compatibility, and validation results:

| Release | Notes and evidence |
| --- | --- |
| 6.0.1 | [Release notes](releases/6.0.1.md) and [validation record](validation/6.0.1.json): startup-failure test isolation and diagnostics |
| 6.0.0 | [Release notes](releases/6.0.0.md) and [validation record](validation/6.0.0.json): Rust API migration, scheduling, secret ownership, and host/VM validation |
| 5.0.0 | [Release notes](releases/5.0.0.md): DPAPI configuration migration and validation scope |

Repository-specific agent instructions are in [AGENTS.md](../AGENTS.md) and
[CLAUDE.md](../CLAUDE.md).
