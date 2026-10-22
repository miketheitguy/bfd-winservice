---
name: windows-service-security
description: Harden Windows service identities, service SID restrictions, privilege allowlists, protected configuration/log/SCM ACLs, privileged broker boundaries, and COM/MI provider hosting. Use for Windows service startup, installer security, least privilege, and service-token verification. Does not grant permission to change live services or provider state.
---

# Windows service security

Read [the service and COM/MI profile](references/service-profile.md) for exact BFD policy and deployment constraints. Apply the architectural principles elsewhere, but derive each application's actual account, privileges, and ACLs from its requirements.

For a network-facing service, preserve firewall filtering, packet/path validation, and configured wire authentication as separate gates. Apply the configured authentication policy before state updates; reject malformed packets and authentication failures without changing accepted state. Read the profile's packet-boundary section for BFD-specific key, sequence, and compatibility constraints; private RPC authentication does not authenticate network peers.

## Keep privileged work behind a narrow broker

Run network-facing work with the least privileged service identity that meets its requirements. Put privileged provider access in a separate broker. Expose a small fixed-operation API, with operation targets loaded from protected configuration. Do not let a lower-privilege caller choose commands, executable paths, arbitrary provider targets, or impersonation identities.

Check each process's own account and enabled/non-deny-only service SID before configured file/registry access, socket creation, endpoint registration, or reporting Running. Check required restricting SIDs for the restricted role. Service display names, process names, executable paths, and same-account membership do not authenticate a service.

Use explicit SCM `RequiredPrivileges` and permanently remove unused privileges before accepting work where the design permits it. Remove impersonation/primary-token assignment privileges from the unprivileged role when not needed. Do not reduce the privileged broker's token mechanically using the network service's allowlist; preserve the provider's reviewed requirements.

## Protect the objects that confer authority

Set explicit appropriate ACLs on SCM controls, installed executables/libraries, configuration/keys, RPC endpoints/interfaces, and logs. Grant service-specific access to service SIDs. Authenticated user access to query status or read allowed logs must not imply permission to start/stop/reconfigure, read secrets, or call a private interface.

Restricted service tokens complement object ACLs. A WRITE_RESTRICTED token is not a complete sandbox or a read-isolation guarantee. Review both ordinary and restricting write checks, including the service-SID grants needed by custom log directories and rotated files.

Never place secrets in event logs, command diagnostics, serialized telemetry, or captured build environments. Rate-limit repeated failures and keep unavailable state distinct from authenticated healthy state. Keep log write privileges narrower than configuration or executable write privileges.

## Preserve COM/MI process security

Initialize COM process security before any provider marshaling/activation that can lock it in. Use an explicit access descriptor, a reviewed authentication floor, Identify as the default proxy impersonation level, disabled activate-as-activator, and disabled custom marshaling. Configure exception and unmarshaling policy explicitly. Fail closed on unexpected late/already-initialized security instead of accepting unknown defaults.

A local MI destination can require IMPERSONATE for execution under the broker's own privileged identity; this is distinct from the private service RPC channel's Identify-only policy. Never attach the unprivileged caller's token while invoking the provider. Preserve the broker's identity and COM/MI settings when adding local RPC in the same process, and test that coexistence with real read-only provider traffic.

## Order startup, shutdown, and installer changes

Make identity/privilege checks and secure registration prerequisites for readiness. Use a bounded worker readiness handshake and explicit failure propagation. Avoid startup dependency cycles: begin peer monitoring only after the service reaches its valid Running state when the architecture requires it.

Bound queues, operation timeouts, recovery/backoff, diagnostics, and shutdown supervision. Keep cleanup possible while a worker fails. Do not abandon callbacks or borrowed native resources during teardown, nor assume a timed-out provider operation never executed.

Preserve preexisting account, privilege, ACL, service recovery, and configuration values in install/repair rollback. Do not reset unknown prior policy to a guessed Windows default. Keep services stopped until required security provisioning is complete before first normal start.

Code/docs changes and local fixtures do not authorize live SCM, registry, firewall, RRAS, or MSI mutation. Use existing task authorization for such changes; do not invent a new approval step for already authorized work. Use disposable hosted installation tests for actual service-token and repair checks. Record any unrun checks honestly.

## Verify claims at their proper scope

Verify process account, enabled and restricting SIDs, retained privileges, object ACLs, endpoint authorization, provider coexistence, readiness, cancellation, rollback, and bounded shutdown. Separate configured policy from observed tokens and runtime behavior. Host administrators remain trusted in this design; do not claim to contain a compromised administrator.

Compiler/linker flags belong to the corresponding language hardening skill. CET enforcement depends on OS/hardware/policy and cannot be established by configuration prose alone.
