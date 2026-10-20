# Security, authentication, and build hardening

For Windows administrators, developers, and security reviewers, this guide maps
the service's trust boundaries and links to the detailed security references.
Use it to find the identity, permission, authentication, or build protection that
applies to a channel. For installation steps, see [Set up a BFD session](setup.md).

The network-facing BFD process runs as LocalService. A separate LocalSystem BGP
broker performs privileged management for one configured target through COM/MI.
Two private local RPC interfaces authenticate both services and authorize their
fixed operations. Windows access-control lists (ACLs) protect service control,
configuration, logs, and RPC access. Configured BFD wire authentication checks
remote packets and is required for classical multihop BGP control. Each control
protects a different boundary.

## Find a security topic

Choose the reference for the boundary you need to inspect:

| Topic | Reference |
| --- | --- |
| Service accounts, restricted tokens, startup checks, privileges, object ACLs, and COM/MI provider access | [Service isolation and permissions](security/service-isolation.md) |
| UDP path validation, authentication modes, replay checks, and stored keys | [BFD packet authentication](security/packet-authentication.md) |
| BGP control and telemetry identity checks, ASCII call flows, authorization, and recovery limits | [Local RPC security](security/local-rpc.md) |
| Rust and MSVC flags, native exception policy, test profiles, and artifact verification | [Build hardening and native safety](security/build-hardening.md) |
| Windows RPC API settings, rights, and alignment with Microsoft guidance | [Local RPC authentication and authorization](rpc-authentication.md) |
| Session-status fields, accepted ranges, freshness, and quarantine | [RPC session-status query](rpc-session-status-design.md) |
| Recorded checks and implementation locations | [Security evidence and validation](#security-evidence-and-validation) and [source map](#source-map) |

## Identities and privileges

The MSI installs BFD with a restricted service SID and a two-privilege allowlist.
The broker retains its separate LocalSystem management identity and removes
all token privileges except `SeChangeNotifyPrivilege` at startup. Both services
check their own account and enabled service SID before opening their private
interfaces. Account membership or an endpoint name alone does not authenticate
a service.

For token checks, write-restriction semantics, installer rollback, console
execution, and local administrative access, see
[Service isolation and permissions](security/service-isolation.md).

## Communication boundaries

The installed services use two private service channels and a provider path:

| Call initiator to receiver | Channel | Purpose |
| --- | --- | --- |
| Broker RPC worker to BFD | Windows local RPC (`ncalrpc`), `BfdWinService.Local.v2` | Mutually authenticated, bounded read-only session-status response. |
| BFD to BGP broker | Windows local RPC (`ncalrpc`), `BfdWinService.Bgp.v1` | Authenticated fixed-target BGP Get/Start/Stop requests. |
| BGP broker to Windows provider | Existing native MI with COM security | Local `PS_BgpPeer` provider operations under the broker's LocalSystem identity. |

Both private service channels use authenticated `ncalrpc` with packet privacy;
`RPC_PROTSEQ_LRPC` is the Windows runtime identifier used by the client binding
and per-call transport check. It does not select a different transport.
The broker alone initiates session-status calls to BFD. BFD alone
initiates BGP control calls to the broker. Each interface has one call-initiation
direction; replies return on that call. Neither interface defines RPC callbacks,
and the fast bindings reject server-initiated callbacks. Local security callbacks
perform authorization inside the receiving process and do not call back to the
client. See [fast-binding restrictions](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind).

BFD receives untrusted UDP packets as LocalService. Its packet worker, state,
and logs retain that service identity. The broker executes separately as
LocalSystem and owns BGP provider access. Its RPC worker shares that process
and uses one fixed BFD identity policy. Local RPC authenticates both service
identities before data is accepted; the broker converts the record into checked
Rust types before caching it.

The [service communication diagrams](service-communication.md) show the
implemented runtime, lifecycle, and authentication boundaries. The
[RPC authentication reference](rpc-authentication.md) explains the Windows
security settings and their alignment with Microsoft guidance.

## Authentication and authorization

Authentication establishes who sent a packet or request. Authorization determines
which actions that identity can perform. Windows uses account and service tokens
for local access; configured BFD wire authentication uses a shared secret. UDP
source and TTL checks do not replace an identity check.

The boundary labels match the [service communication diagrams](service-communication.md):

| Boundary | Detailed policy |
| --- | --- |
| A: Remote UDP peer to BFD | [Packet validation and authentication](security/packet-authentication.md) |
| B: BFD verifies the BGP control RPC server | [BFD authenticates the broker](security/local-rpc.md#bfd-authenticates-the-broker) |
| C: Broker verifies and scopes BFD control requests | [Broker authenticates and authorizes BFD requests](security/local-rpc.md#broker-authenticates-and-authorizes-bfd-requests) |
| D: Broker invokes the Windows BGP provider | [Local Windows provider security](security/service-isolation.md#local-windows-provider-security) |
| E: Local callers inspect or administer services | [Service control, configuration, and diagnostic access](security/service-isolation.md#service-control-configuration-and-diagnostic-access) |
| F: Broker queries BFD telemetry | [Broker authenticates BFD telemetry](security/local-rpc.md#broker-authenticates-bfd-telemetry) |

## Rust compiler and linker hardening

Both executables use Rust instrumentation, MSVC mitigation metadata, and native C
compiler checks. Production panics abort; test profiles use different panic and
diagnostic settings. These protections supplement authentication and input
validation. Their effectiveness depends on the emitted artifacts and applicable
Windows process policy.

For the complete option tables, native FFI exception policy, sanitizer scope, and
verification limits, see [Build hardening and native safety](security/build-hardening.md).

## Security evidence and validation

The design follows least privilege, explicit authorization, defense in depth,
and careful ownership of native resources. Microsoft's
[RPC client-authentication guidance](https://learn.microsoft.com/en-us/windows/win32/rpc/controlling-client-authentication)
supports the callback, call-attribute, and Authz approach. Its
[service access-rights guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
supports restricting service reconfiguration to administrators.

These controls and validation records support the stated security boundaries:

| Practice | What the boundary enforces | Evidence you can inspect |
| --- | --- | --- |
| Least privilege and distinct service identities | LocalService BFD retains two privileges; exact account and enabled service SID checks distinguish services sharing an account. | [Token fixtures](../src/service_identity/tests.rs), [privilege removal](../src/runtime/privileges.rs), and the [recorded reliability/security review](../CODE_REVIEW.md#reliability-and-security-review--2026-10-09). |
| Authenticate, then authorize the specific service | The RPC client pins BFD's account and service SID; BFD checks the interface ACL, call attributes, SYSTEM account, and enabled broker SID. Management operations are denied. | [Native RPC rejection tests](../src/local_rpc/tests.rs), [replacement-server fixture](../src/local_rpc/tests/restricted.rs), and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Keep privileged actions narrow | The BGP broker authenticates BFD before decoding requests and accepts fixed operations for its protected configured target. | [Broker authorization tests](../src/bgp/ipc/tests.rs), [RPC dispatch and identity checks](../src/bgp/ipc.rs), and the [session-status implementation record](../CODE_REVIEW.md#rpc-session-status-implementation--2026-10-15). |
| Validate remote input before changing session state | Protocol, path, and configured authentication checks reject invalid packets without refreshing accepted peer state. Classical multihop BGP requires meticulous keyed authentication. | [RFC boundary tests](../tests/rfc5880.rs), [native UDP tests](../tests/windows_udp.rs), and the [recorded RFC validation](../CODE_REVIEW.md#rfc-5880--rfc-7419--rfc-7880-validation--2026-10-09). |
| Validate native data and preserve ownership through cancellation | Robust MIDL stubs and checked Rust conversion bound status data; pending calls retain their buffers and handles until completion. | [Layout and conversion tests](../src/local_rpc/status/tests.rs), [RPC rejection and cancellation tests](../src/local_rpc/tests.rs), [native completion code](../rpc/client.c), and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Keep telemetry failure separate from control | Invalid replies clear the cache and retry; a stuck worker quarantines telemetry without issuing BGP actions or accumulating replacement workers. | [Supervisor regressions](../src/local_rpc/monitor/tests.rs) and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Check hardening and deployment policy | Executable tests inspect emitted mitigation metadata; the MSI harness checks installed accounts, privileges, ACLs, authentication, and logging. | [Executable checks](../tests/windows_hardening.rs), [MSI harness](../scripts/Test-MsiInstall.ps1), and the configured [validation and release workflow](../.github/workflows/build-msi.yml). The [recorded local RPC review](../CODE_REVIEW.md#local-rpc-security-review--2026-10-15) includes hardening results. |

The 2026-10-15 RPC recovery record reports 29 targeted tests passing in optimized
and AddressSanitizer profiles, including rejection, recovery, cancellation,
and stalled-worker lifetime checks. Those are dated validation records;
they attest to the recorded checks and exercised paths, rather than certify
every deployment. The MSI harness supplies a separate check of actual SCM-issued
identities and was not run locally for that review. Workflow configuration
describes the release gates; it does not by itself establish a successful run.
Use the [validation guide](../RUST_SKILLS_VALIDATION.md#read-the-validation-receipts)
to keep each result tied to its revision.

## Source map

These files implement the authentication, privilege, and native resource
boundaries described in this guide:

| Path | Relevant implementation |
| --- | --- |
| [installer/Package.wxs](../installer/Package.wxs) | Service accounts, dependencies, SCM control/query ACLs, Parameters ACL, and firewall rules |
| [src/service.rs](../src/service.rs) and [src/bgp_broker/service.rs](../src/bgp_broker/service.rs) | SCM lifecycle, startup checks, local RPC lifetime, private broker COM initialization, and conditional BGP broker connection check |
| [src/runtime/privileges.rs](../src/runtime/privileges.rs) | BFD and broker process privilege allowlists |
| [src/transport.rs](../src/transport.rs) | `Datagram::validate`, transport construction, `send`, and `send_reply` |
| [src/session.rs](../src/session.rs), [src/packet.rs](../src/packet.rs), and [src/seamless.rs](../src/seamless.rs) | `receive_checked`, `receive_seamless`, `AuthConfig::verify_decoded`, and `respond_checked` |
| [src/local_rpc.rs](../src/local_rpc.rs) and [src/local_rpc/monitor.rs](../src/local_rpc/monitor.rs) | Private local RPC listener, in-process client, authentication, authorization, supervised worker, and telemetry cache |
| [src/local_rpc/identity.rs](../src/local_rpc/identity.rs) | Per-call transport/authentication checks and bounded Authz identity queries without token attachment |
| [rpc/bfd_local.idl](../rpc/bfd_local.idl), [rpc/client.c](../rpc/client.c), and [rpc/server.c](../rpc/server.c) | Status-only contract, fixed record, MIDL stub bridge, native asynchronous deadlines, and RPC exception boundary |
| [rpc/build.rs](../rpc/build.rs) and [rpc/allocator.c](../rpc/allocator.c) | Native MIDL/MSVC build flags, static library assembly, and RPC allocation hooks |
| [src/runtime/status.rs](../src/runtime/status.rs), [src/local_rpc/status.rs](../src/local_rpc/status.rs), and [src/runtime/state.rs](../src/runtime/state.rs) | Immutable publications and checked RPC projection; the immediate atomic state observer stays separate from detailed telemetry |
| [src/bgp_broker/com.rs](../src/bgp_broker/com.rs) | Private broker COM security for native MI |
| [src/bgp/ipc.rs](../src/bgp/ipc.rs) | `require_broker_identity`, Authz authorization, bounded dispatch, and BGP RPC client/listener |
| [src/bgp.rs](../src/bgp.rs) and [src/bgp_broker.rs](../src/bgp_broker.rs) | Bounded BGP mailbox, state-to-action policy, fixed target, and request dispatch |
| [src/bgp_broker/mi.rs](../src/bgp_broker/mi.rs) | Local MI destination, impersonation option, namespace, and provider calls |
| [src/config/registry.rs](../src/config/registry.rs) | `load_registry`, `SettingsWatch`, and `load_bgp_target` |
| [src/runtime/logging.rs](../src/runtime/logging.rs) and [events/BFD-Service.man](../events/BFD-Service.man) | Diagnostic queues, ETW output, optional file logging, and event channel |
