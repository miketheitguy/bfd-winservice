# Security, authentication, and build hardening

Cowabunga, security crew. This map helps Windows administrators and maintainers
find the protection for each trust boundary. For installation, use
[Set up a BFD session](setup.md).

The network-facing BFD engine runs as LocalService. A separate LocalSystem
broker manages one configured BGP target. Local RPC authenticates both services;
wire authentication checks remote BFD packets. Windows ACLs protect service
control, configuration, and files. Each boundary needs its own check, dude.

## Find a security topic

Pick the boundary you're checking, turtle crew:

| Topic | Reference |
| --- | --- |
| Service accounts, restricted tokens, startup checks, privileges, object ACLs, and COM/MI provider access | [Service isolation and permissions](security/service-isolation.md) |
| UDP path validation, authentication modes, replay checks, and stored keys | [BFD packet authentication](security/packet-authentication.md) |
| BGP control and telemetry identity checks, ASCII call flows, authorization, and recovery limits | [Local RPC security](security/local-rpc.md) |
| Rust and MSVC flags, native exception policy, test profiles, and artifact verification | [Build hardening and native safety](security/build-hardening.md) |
| Fuzz target boundaries, acceptance/rejection assertions, mutators, sanitizer scope, and artifact handling | [BFD fuzz harness security reference](security/fuzzing.md) |
| Service identity matrix and authentication diagrams | [Local RPC authentication and authorization](rpc-authentication.md) |
| Session-status fields, accepted ranges, freshness, and quarantine | [RPC session-status query](rpc-session-status-design.md) |
| Recorded checks and implementation locations | [Security evidence and validation](#security-evidence-and-validation) and [source map](#source-map) |

## Communication boundaries

The [service communication diagrams](service-communication.md) show process
ownership and call direction. The [RPC identity matrix](rpc-authentication.md#bgp-control-over-local-rpc)
defines the required account and service SID for both channels. Provider calls
use the broker's own identity; BFD never borrows its SYSTEM token.

## Identities and privileges

The [service isolation reference](security/service-isolation.md) owns account,
restricted-token, privilege, SCM, registry, file, and COM/MI policies. Permission
to administer a service does not authorize calls to its private RPC interface.

## Authentication and authorization

RPC authentication identifies the local service. Per-call authorization limits
its operations, and checked conversion validates returned status. An
authenticated source can still lie or withhold replies. Telemetry failures
never request BGP actions; the packet engine owns that policy.

Both RPC directions require the expected account, an enabled non-deny-only
service SID, and that SID in any nonempty caller restricting list. See the
[identity matrix](rpc-authentication.md#bgp-control-over-local-rpc) for the roles.

For remote UDP, [packet authentication](security/packet-authentication.md) is
separate from path validation and firewall filtering. Classical multihop BGP
control requires meticulous keyed authentication.

## Rust compiler and linker hardening

Use [build hardening and native safety](security/build-hardening.md) for compiler
settings, C exception policy, and emitted-artifact checks. Mitigation metadata
does not prove runtime enforcement or the absence of vulnerabilities.

## Security evidence and validation

Bring receipts with dates, no cap. The [validation guide](../RUST_SKILLS_VALIDATION.md)
links checkout checks to dated reviews. [Native RPC verification](security/local-rpc.md#verify-the-implementation)
distinguishes fixture tests from actual installed service-token checks. The
[release workflow](../.github/workflows/build-msi.yml) defines gates; its
configuration alone is not evidence that a run passed.

The design assumes trustworthy Windows authentication, SCM token construction,
protected binaries/configuration, and correct native APIs and FFI. Host
administrators and SYSTEM remain trusted. A matching SID does not attest which
executable runs, and safe Rust validation cannot repair earlier native memory
corruption. See [security limits](security/local-rpc.md#soundness-and-operational-limits).

## Source map

Follow the [implementation source map](reference/source-map.md) for file ownership.
