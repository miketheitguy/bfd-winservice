# Security, authentication, and build hardening

Windows administrators and developers: this is your map of the security lineup,
from incoming packets to privileged BGP management. The MSI-installed services
keep identity checks, permissions, and native resource lifetimes explicit. The
least-privilege setup is dialed in, and the details have receipts. For socket
endpoints and BGP actions, see
[Service communication](service-communication.md).

The network-facing BFD process runs as LocalService and hosts a private local
RPC interface for the LocalSystem BGP broker. The interface authenticates both
services and exposes a connection probe and read-only session telemetry. The
broker performs privileged BGP management for one configured target through its
COM/MI provider integration. Windows access-control lists (ACLs) govern service control,
configuration, logs, and the existing BGP control pipe; optional BFD wire
authentication checks remote packets. These checks protect different boundaries.

No cap: the confidence comes from token checks, ACLs, packet validation, and
recorded rejection tests. Each private service boundary checks the identity and
authority it needs before work proceeds. That is a clean security lineup; a
service name or an open endpoint alone doesn't prove who is calling.

## Security receipts and best practices

The design follows least privilege, explicit authorization, defense in depth,
and careful ownership of native resources. Microsoft's
[RPC client-authentication guidance](https://learn.microsoft.com/en-us/windows/win32/rpc/controlling-client-authentication)
supports the callback, call-attribute, and Authz approach. Its
[service access-rights guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
supports restricting service reconfiguration to administrators. Stoked on the
receipts: the implementation and recorded checks make those choices inspectable.

These controls and validation records support the stated security boundaries:

| Practice | What the boundary enforces | Evidence you can inspect |
| --- | --- | --- |
| Least privilege and distinct service identities | LocalService BFD retains two privileges; exact account and enabled service SID checks distinguish services sharing an account. | [Token fixtures](../src/service_identity/tests.rs), [privilege removal](../src/runtime/privileges.rs), and the [recorded reliability/security review](../CODE_REVIEW.md#reliability-and-security-review--2026-10-09). |
| Authenticate, then authorize the specific service | The RPC client pins BFD's account and service SID; BFD checks the interface ACL, call attributes, SYSTEM account, and enabled broker SID. Management operations are denied. | [Native RPC rejection tests](../src/local_rpc/tests.rs), [replacement-server fixture](../src/local_rpc/tests/restricted.rs), and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Keep privileged actions narrow | The BGP broker authenticates BFD before decoding requests and accepts fixed operations for its protected configured target. | [Broker authorization tests](../src/bgp_broker.rs), [frame and identity checks](../src/bgp/ipc.rs), and the [session-status implementation record](../CODE_REVIEW.md#rpc-session-status-implementation--2026-10-15). |
| Validate remote input before changing session state | Protocol, path, and configured authentication checks reject invalid packets without refreshing accepted peer state. Wire authentication remains optional. | [RFC boundary tests](../tests/rfc5880.rs), [native UDP tests](../tests/windows_udp.rs), and the [recorded RFC validation](../CODE_REVIEW.md#rfc-5880--rfc-7419--rfc-7880-validation--2026-10-09). |
| Validate native data and preserve ownership through cancellation | Robust MIDL stubs and checked Rust conversion bound status data; pending calls retain their buffers and handles until completion. | [Layout and conversion tests](../src/local_rpc/status/tests.rs), [RPC rejection and cancellation tests](../src/local_rpc/tests.rs), [native completion code](../rpc/client.c), and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Keep telemetry failure separate from control | Invalid replies clear the cache and retry; a stuck worker quarantines telemetry without issuing BGP actions or accumulating replacement workers. | [Supervisor regressions](../src/local_rpc/monitor/tests.rs) and the [RPC recovery validation record](../CODE_REVIEW.md#rpc-status-rejection-recovery--2026-10-15). |
| Check hardening and deployment policy | Executable tests inspect emitted mitigation metadata; the MSI harness checks installed accounts, privileges, ACLs, authentication, and logging. | [Executable checks](../tests/windows_hardening.rs), [MSI harness](../scripts/Test-MsiInstall.ps1), and the configured [tagged-release workflow](../.github/workflows/build-msi.yml). The [recorded local RPC review](../CODE_REVIEW.md#local-rpc-security-review--2026-10-15) includes hardening results. |

The latest RPC recovery record reports 29 targeted tests passing in optimized
and AddressSanitizer profiles, including rejection, recovery, cancellation,
and stalled-worker lifetime checks. Those are dated implementation receipts;
they attest to the recorded checks and exercised paths, rather than certify
every deployment. The MSI harness supplies a separate check of actual SCM-issued
identities and was not run locally for that review. Workflow configuration
describes the release gates; it does not by itself establish a successful run.
Use the [validation guide](../RUST_SKILLS_VALIDATION.md#read-the-validation-receipts)
to keep each result tied to its revision. No runtime tests are rerun by this
documentation update.

## Identities and privileges

Least privilege is the main character in this lineup. Windows account and
service-SID checks keep each process on the permissions its role needs.

A security identifier (SID) identifies a Windows account or group. The installer
sets BFD to `SERVICE_SID_TYPE_RESTRICTED` (`3`) and keeps the broker at
`SERVICE_SID_TYPE_UNRESTRICTED` (`1`). BFD's account remains LocalService in
`TokenUser`; `NT SERVICE\BfdWinService` is an enabled normal group and also
appears in `TokenRestrictedSids`. The broker keeps LocalSystem as its account and
its own enabled service group. See Microsoft's
[service SID types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).

The BFD service token is write-restricted. Write access must pass the ordinary
token check and the restricting-SID check. The application's pipe and log-folder
ACLs grant the BFD service SID the required write rights, so shared LocalService
account permissions alone cannot authorize those writes. Other grants, such as
Everyone write access, can still satisfy the restricting check; this is not a
complete sandbox. Read access keeps its ordinary ACL checks. See Microsoft's
[write-restricted token semantics](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

Before loading configuration, creating sockets, or registering local RPC in
service mode, BFD checks its own process token. `TokenUser` must be LocalService. The BFD
SID must be enabled and not deny-only in `TokenGroups`; both that SID and the
write-restricted marker `S-1-5-33` must appear in `TokenRestrictedSids`. These
queries never attach a token to a thread or require `SeImpersonatePrivilege`.
SCM's installed SID-type policy supplies the write restriction; the startup
guard verifies the expected account and SID lists.

The installed services and local callers have these permissions:

| Identity | Permissions and limits |
| --- | --- |
| `BfdWinService`: LocalService with restricted `NT SERVICE\BfdWinService` SID | Receives and sends BFD packets, hosts the private local RPC interface, reads Parameters, writes its configured logs, and requests fixed-target BGP actions through the existing broker pipe. The service SID participates in normal and restricting write checks. SCM limits its process token to `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege`; startup removes unused privileges before accepting traffic. |
| `BfdBgpBroker`: LocalSystem with unrestricted `NT SERVICE\BfdBgpBroker` SID | Queries BFD telemetry on a worker inside the existing broker process, owns the existing BGP control pipe, and invokes the local Windows BGP management provider. Startup checks LocalSystem in `TokenUser` and the enabled broker service group. |
| Elevated Administrators and SYSTEM | Can install, start, stop, and reconfigure either service, modify installed files and Parameters, and manage permissions. Account or Administrator membership alone does not satisfy the private channels' service-specific identity checks. |
| Authenticated non-administrator local users | Can query service configuration/status, enumerate dependents, interrogate the service, and read its service ACL. Can read event/file logs under the applicable Windows permissions. Cannot use the private RPC interface, start, stop, reconfigure, or send custom controls to either installed service. |
| Other LocalService processes | Share BFD's account but not its service SID. Cannot authenticate as BFD to the broker or satisfy the broker identity required by BFD's local RPC interface. |
| Remote network peers | Can send UDP traffic through the configured firewall rules. Packets must pass protocol/path validation and any configured BFD authentication before affecting the session. The BGP pipe rejects remote clients, and `ncalrpc` is local-only. |

The MSI sets BFD's SCM `RequiredPrivileges` list to
`SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege` in a native commit action
after the installation transaction succeeds. Installation leaves the services
stopped, so the allowlist is in place before the first normal service start.
SCM applies it when Windows creates the process. The BFD process also permanently
removes unused token privileges, including
`SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`, before loading
configuration, creating sockets, or registering local RPC. It retains
only `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege` for directory
traversal and global object creation. Local RPC authentication keeps that reduced
service identity and does not attach a caller token to a thread. Access to the
broker comes from its pipe ACL and service identity checks.

The privilege allowlist applies to the installed BFD service. The LocalSystem
BGP broker keeps its separate management identity and privilege requirements.
Deferred account/SID configuration and rollback preserve the existing privilege
policy, including an unspecified or empty list. The commit action sets the BFD
minimum as its last operation that can fail; a rare snapshot-cleanup error is
diagnostic and leaves a recovery snapshot that blocks a later repair until an
administrator removes it. The installer does not reset an unknown prior policy
to an assumed Windows default.

That service-mode boundary is locked in before traffic starts. Foreground
`--console` execution uses the launching account and removes unused
privileges. It provides no BGP control. Removing token privileges does not remove
account or group memberships: an elevated console process still has the
launching administrator's identity. The LocalService boundary applies to the
MSI-installed service.

## Communication boundaries

Each channel has its own authorization lineup. This separation keeps the
network-facing packet engine and privileged provider work on clear, reviewable
paths. The installed services use two private service channels and a provider
path:

| Direction | Channel | Purpose |
| --- | --- | --- |
| Broker RPC worker to BFD | Windows local RPC (`ncalrpc`) | Mutually authenticated probe and bounded read-only session-status response. |
| BFD to BGP broker | `\\.\pipe\BfdWinService.Bgp.v1` | Fixed-target BGP Get/Start/Stop requests under the existing service-token policy. |
| BGP broker to Windows provider | Existing native MI with COM security | Local `PS_BgpPeer` provider operations under the broker's LocalSystem identity. |

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

### Configuration, lifecycle, and logs

Operational visibility is a W: you can inspect lifecycle and events while
Windows keeps service-control and configuration permissions scoped separately.

Elevated Administrators and SYSTEM install, configure, start, and stop the
services. Windows checks registry, SCM, and filesystem permissions independently.
BFD validates its reduced service token before registering its local RPC
interface or accepting network traffic.

Both services publish events through their own bounded logging queues and
report process lifecycle to SCM. BFD can also write its configured file log
under the BFD service SID. Ordinary authenticated local users can query service
lifecycle and read logs under the relevant Windows permissions. These queries
do not return a live BFD session snapshot.

## Authentication and authorization

Authentication establishes who sent a packet or request. Authorization determines
which actions that identity can perform. Windows uses account/service tokens for
local access; BFD wire authentication uses an optional shared secret. Neither
the pipe sequence number nor UDP source/TTL checks replace an identity check.

Both checks belong in the lineup: establish the caller, then check what that
caller can do. The implementation follows that pattern at each private boundary.

### A: Remote BFD and S-BFD packets

Incoming traffic has to earn its spot in the lineup. The firewall and packet
validators check the configured path before a packet can influence peer state;
configured wire authentication adds the shared-key check.

`[AUTH A-fw]` represents Windows kernel UDP firewall filtering through the four
installed program-specific allow rules. `[AUTH A]` represents the application's
separate packet and path checks.

The UDP transport validates the source and destination, ports, interface, and
time to live (TTL)/hop limit for the configured role. Packet/session code validates
BFD structure and discriminators before accepting peer state. See
[UDP inputs and outputs](service-communication.md#udp-inputs-and-outputs) for
the role-specific rules. These path checks alone do not authenticate the peer.

`Auth` defaults to `none`. When enabled, both peers must use the same
authentication type, key ID, and secret. The receiver checks the authentication
section and compares the password or computed keyed digest using constant-time
equality. Authentication failures do not refresh detection or update accepted
session state. The sender adds the configured authentication to outgoing packets.

The supported modes provide these checks:

| `Auth` setting | Check and limitations |
| --- | --- |
| `none` | Protocol/path validation only. Traffic that passes those checks can influence the session and its configured BGP actions without a shared-key check. |
| `simple-password` | Verifies the key ID and matching password. The password travels in cleartext; this mode has no authentication sequence protection. |
| `keyed-md5`, `keyed-sha1` | Verifies the key ID and the RFC-defined digest of the packet with the configured key. Classical BFD enforces a receive sequence window but permits repeated sequences within the protocol rules. |
| `meticulous-md5`, `meticulous-sha1` | Uses the corresponding keyed digest and classical receive window, and rejects repeated sequences. |

The keyed modes follow BFD's MD5/SHA-1 packet format; they are not HMAC or
encryption. BFD authentication does not hide packet contents. A valid shared-key
check establishes possession of the configured secret, rather than a distinct
Windows or certificate identity for each peer.

S-BFD initiators require keyed replies to match an unconsumed, unexpired
outstanding probe. Reflectors verify the configured authentication and copy a
keyed request's sequence into the response without maintaining a per-peer receive
window. These behaviors differ from a classical BFD session's replay checks.

Configure exactly one of `AuthKey` (ASCII) and `AuthKeyHex` (binary key encoded as
hexadecimal) when authentication is enabled. Password/MD5 keys are 1-16 bytes;
SHA-1 keys are 1-20 bytes. `AuthKeyId` is 0-255. One key is active at a time;
restart after changing authentication settings. Keys are stored in Parameters
under its protected ACL, without application-level encryption. Logs and
configuration errors omit key values. See
[Configure authentication](configuration.md#authentication) for the settings
and an example.

### B: BFD authenticates the broker

The broker identity check brings receipts from Windows itself. Matching the pipe
server PID to SCM keeps the client from trusting a process on name alone.

Before exchanging messages on `\\.\pipe\BfdWinService.Bgp.v1`, the BFD client calls
`GetNamedPipeServerProcessId`. It queries the Service Control Manager (SCM) for
the running `BfdBgpBroker` service and requires the Windows-reported pipe server
PID to match the SCM process ID. It does not trust a PID supplied in a message.
This rejects a process that claims the pipe name without being the running broker.

The client requests individual data read/write rights, rather than generic write
rights that also permit pipe-instance creation. It opens the pipe with
`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, allowing identity inspection.
See Microsoft's [named-pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

### C: Broker authenticates and authorizes BFD requests

The privileged action boundary is dialed in: a caller needs the BFD account,
enabled service SID, and the applicable restricting-SID checks. That is the
service identity understood by the broker's authorization policy.

The broker checks its own process token at startup for LocalSystem in `TokenUser`
and an enabled, non-deny-only `NT SERVICE\BfdBgpBroker` entry in `TokenGroups`.
It creates a single pipe instance with an explicit,
protected ACL: the BFD service SID gets data read/write access, and the broker
SID gets full access. The BFD client cannot create server instances or change
the ACL. `PIPE_REJECT_REMOTE_CLIENTS` rejects remote connections;
`FILE_FLAG_FIRST_PIPE_INSTANCE` makes startup fail if another process already
owns the pipe name.

For every request, the broker calls `ImpersonateNamedPipeClient` to obtain the
client's identification token. It opens that token for `TOKEN_QUERY` with
`OpenAsSelf`. It requires LocalService in `TokenUser`, an enabled, non-deny-only
`NT SERVICE\BfdWinService` entry in `TokenGroups`, and that service SID in the
restricting list of a restricted client token. Direct account and group queries
need only `TOKEN_QUERY` and distinguish the logon account from group membership.
The explicit restricting-list check also applies to write-restricted tokens;
the native write-restricted fixture still reports account membership through
`CheckTokenMembership`. Unrelated LocalService processes and ordinary
administrator clients fail these checks. See Microsoft's
[CheckTokenMembership behavior](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership).
The broker calls
`RevertToSelf` before provider work; failed reversion aborts the process.
The client uses static pipe security-context tracking. Each request checks the
connection's captured identity, rather than the current identity of a process
that might receive a duplicated pipe handle. Handles are not inheritable;
duplicating an authorized connection transfers that connection's capability.

Identification exposes the caller's identity for checking. It does not grant
permission to open files, registry keys, or provider objects as that caller.
See Microsoft's [impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels).

After identification, the broker validates the fixed 24-byte frame, protocol
version, operation allowlist (`Get`, `Start`, `Stop`), and next connection sequence
number. Replies carry status/error information. This sequence check orders the
local protocol; the Windows token and ACL establish caller identity.

The fixed target keeps the action scope tight, no cap. The broker independently
reads only the BGP peer name and routing domain from
protected Parameters at startup. Requests cannot specify a peer, routing domain,
command, path, or registry key. The broker uses its own LocalSystem authority
only for that fixed target. This is the service's BGP action policy, not an
interactive administrator credential passed through the BFD process.

### D: Broker accesses the local Windows provider

Provider access stays in its own lane, dude: the broker ends pipe identification
before native MI runs under its management identity. That explicit transition
keeps caller inspection separate from privileged provider work.

Native Management Infrastructure (MI) calls target the local
`root/Microsoft/Windows/RemoteAccess` namespace and `PS_BgpPeer` class. The
destination explicitly requests `IMPERSONATE`, so the Windows provider can
access resources under the broker's LocalSystem identity. Pipe identification
has already ended. Windows governs provider authorization; the application
supplies no separate provider password or remote MI destination.

The broker's private Component Object Model (COM) initialization supports native
MI. Its process security descriptor admits only local SYSTEM.
It explicitly sets `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` and an outgoing default of
`IDENTIFY`. Packet integrity protects against message tampering without encrypting
the payload. See Microsoft's [COM authentication levels](https://learn.microsoft.com/en-us/windows/win32/com/authentication-level).

The broker sets `EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL` to prevent
activate-as-activator launches under its privileged identity and restrict custom
marshaling. The MI destination's explicit `IMPERSONATE` setting is scoped to
provider calls. It applies the shared `DONOT_HANDLE_ANY` exception policy and
strong unmarshaling policy before opening MI. A read-only native provider schema
test verifies compatibility with these settings and the SYSTEM-only descriptor;
it does not exercise a live BGP operation. See Microsoft's
[COM security capabilities](https://learn.microsoft.com/en-us/windows/win32/api/objidl/ne-objidl-eole_authentication_capabilities).

Windows Routing and Remote Access Service (RRAS) manages the final BGP connection
to the remote BGP peer. This repository invokes its local provider and does not
configure BGP wire
authentication. Provider permissions and RRAS process identity depend on the
host's Windows configuration.

### E: Service control, configuration, and diagnostic access

The administrator boundary has a clean break between observation and control.
Authenticated readers can inspect the granted service information; elevated
administrators and SYSTEM hold the configuration and control rights.

Windows checks the caller's access token against each object's ACL. There is no
application login or shared password for `Start-Service`, `Stop-Service`, registry
edits, or log reads. Use an elevated administrator token for service control and
configuration changes; SYSTEM retains full control.

The MSI provisions protected permissions for these objects:

| Object | Write/control access | Read/query access |
| --- | --- | --- |
| Both SCM service objects | SYSTEM and Administrators have full control, including Start/Stop and configuration changes. | Authenticated Users have query-config, query-status, enumerate-dependents, interrogate, and read-control rights (`0x2008d`). No Start/Stop, reconfiguration, or custom controls. |
| Installed executables, manifest, logging script, and installation directory | SYSTEM and Administrators have full control. | Users and the BFD service SID have read/execute access. |
| `HKLM\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters` | SYSTEM and Administrators have full control. | BFD service SID has read access; the LocalSystem broker reads its BGP target. Ordinary users cannot read authentication keys. |
| Default file-log directory | SYSTEM and Administrators have full control; BFD service SID has Modify access. | Users retain read access. Custom log paths use their provisioned filesystem ACLs. |
| `BFD-Service/Operational` event channel | Windows Event Log permissions govern event publication and channel management. | The manifest supplies no custom channel access ACL; existing Windows log-read permissions remain in effect. |

The BFD service SID's write restriction adds a token check; it does not replace
these object ACLs or restrict every read. The explicit service-SID grant on the
BGP control pipe and the log-folder Modify grant support both write checks. A custom log path must grant
the BFD service SID access to its folder, active file, and rotated file; a grant
only to the shared LocalService account is insufficient for restricted writes.

The BFD service reads its configuration at startup. S-BFD timing and reflector
maintenance settings can reload through registry notifications, with polling
as a fallback. The broker's fixed target requires a restart to reload.

BFD writes Operational events through Event Tracing for Windows (ETW) and an
optional file log through a bounded logging queue. The broker writes Operational
events through its own queue and does not open the BFD file log. Both services
report lifecycle status and exit codes to
SCM. A service-status query reports Running/Stopped and process lifecycle, rather
than the BFD session's Up/Down state. See
[Monitor service status and BFD events](monitoring.md) and
[Logs and events](logging.md).

### F: Private local RPC authentication

BFD hosts `BfdWinService.Local.v1` on `ncalrpc`, interface version `1.1`.
`Probe` checks connectivity; `GetSessionStatusV1` returns a fixed session-status
record. Both require the same service-specific authentication and authorization.

This RPC boundary understood the assignment: local transport, explicit service
identities, read-only telemetry, and bounded work. The security checks stay
separate from the packet engine and the broker's BGP action policy.

The broker uses a dedicated RPC worker and supervisor inside its existing
process. It creates no helper process or reply pipe and does not change its
provider token or COM/MI initialization. One BFD identity policy remains fixed
for the process lifetime; separate bindings are not treated as cache flushing.

The API receipts are in [local RPC setup](../src/local_rpc.rs) and
[per-call identity validation](../src/local_rpc/identity.rs). The ASCII diagrams
show the logical security gates, rather than the RPC runtime's exact handshake
or callback scheduling.

#### Binding and server setup

The setup lineup checks both directions. The broker specifies its expected
server identity; BFD separately registers the endpoint, application interface,
and management policy:

```text
BROKER CLIENT: one fixed BFD identity policy
  RpcBindingCreateW
    RPC_PROTSEQ_LRPC -> BfdWinService.Local.v1
    RPC_C_AUTHN_WINNT + RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    RPC_SECURITY_QOS_V5_W:
      MUTUAL_AUTH, STATIC, IDENTIFY, EffectiveOnly=1
      Sid=LocalService
      ServerSecurityDescriptor=LocalService AND BFD service SID
          |
          v
  RpcBindingSetOption(RPC_C_OPT_UNIQUE_BINDING, 1)
          |
          v
  Native RpcBindingBind, then GetSessionStatusV1 (Probe in tests)
    server identity mismatch or API failure -> query fails; no status

BFD SERVER: verify its own restricted service token first
  RpcMgmtSetAuthorizationFn(deny_management)
    management request -> ERROR_ACCESS_DENIED
          |
          v
  RpcServerUseProtseqEpW("ncalrpc", endpoint, broker-SID ACL)
          |
          v
  RpcServerRegisterAuthInfoW(RPC_C_AUTHN_WINNT)
          |
          v
  RpcServerRegisterIf3(interface, flags, authorize, broker-SID ACL)
    setup failure -> fail startup; no fallback policy
          |
          v
  Windows interface ACL check -> security callback -> manager
    ACL denial -> reject before callback or manager
```

`RpcBindingCreateW` builds a fast binding; success alone establishes neither
connectivity nor server identity. The native wrapper subsequently calls
`RpcBindingBind`. The binding uses Windows credentials through a null
`AuthIdentity`; it supplies no application password. See Microsoft's
[RpcBindingCreateW reference](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingcreatew).

The client sets `RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH`,
`RPC_C_QOS_IDENTITY_STATIC`, and `RPC_C_IMP_LEVEL_IDENTIFY` in
`RPC_SECURITY_QOS_V5_W`. Static tracking captures credentials for that binding;
Identify permits identity and ACL checks without allowing BFD to access
resources as the privileged broker. `EffectiveOnly=1` exposes enabled privileges
only; it is not the service-group authorization check. See Microsoft's
[QOS V5 contract](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

`QOS.Sid` identifies LocalService, while `ServerSecurityDescriptor` contains one
conditional allow ACE requiring both LocalService and the BFD service SID.
`Member_of` tests all listed enabled SIDs for an allow ACE; two independent allow
ACEs would instead permit either identity. The descriptor adds the
service-specific server check: the mutual-authentication capability flag alone
is insufficient because a provider can report that capability without
establishing the server's identity. See Microsoft's
[conditional ACE semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
and [QOS provider caveat](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos_v5_w).

On BFD, `RpcMgmtSetAuthorizationFn` denies every runtime management operation
before the endpoint opens. This is separate from the application interface's
ACL and callback. `RpcServerUseProtseqEpW` registers only `ncalrpc` with an
explicit broker-SID endpoint ACL; `RpcServerRegisterAuthInfoW` registers WINNT
without a custom key callback. See Microsoft's
[management authorization](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcmgmtsetauthorizationfn),
[endpoint registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserveruseprotseqepw),
and [authentication registration](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterauthinfow).

`RpcServerRegisterIf3` also receives an explicit broker-SID interface ACL and
the authorization callback. Windows checks that ACL before invoking the
callback, including the access restrictions of the caller's token. The endpoint
ACL alone is insufficient. The interface uses these flags:

| Flag | Purpose and limit |
| --- | --- |
| `RPC_IF_ALLOW_LOCAL_ONLY` | Reject remote clients; the callback additionally requires LRPC and confirmed local origin. |
| `RPC_IF_ALLOW_SECURE_ONLY` | Reject unauthenticated calls; this flag alone does not require privacy, exclude null sessions, or prove a privileged caller. |
| `RPC_IF_SEC_NO_CACHE` | Run the security callback for each call; this does not disable every Windows identity or association cache. |
| `RPC_IF_AUTOLISTEN` | Give this interface an automatic listening lifetime without calling process-wide `RpcServerListen` or `RpcMgmtStopServerListening`. |

See Microsoft's [RpcServerRegisterIf3 ordering](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterif3)
and [interface flag definitions](https://learn.microsoft.com/en-us/windows/win32/rpc/interface-registration-flags).

#### Per-call authorization and cleanup

The interface callback and the application manager both call the same identity
guard. The manager repeats the guard before loading a status snapshot. That
second check is a solid W for explicit authorization at the point of use:

```text
Windows interface ACL passes
          |
          v
  RpcServerInqCallAttributesW(RPC_CALL_ATTRIBUTES_V2_W)
    require LRPC + rcclLocal + NullSession=0 + WINNT + privacy
    API failure or mismatch -------------------------> DENY
          |
          v
  RpcGetAuthorizationContextForClient(ImpersonateOnReturn=FALSE)
    API failure or null context ---------------------> DENY
          |
          v
  AuthzGetInformationFromContext
    AuthzContextInfoUserSid    -> TOKEN_USER
    AuthzContextInfoGroupsSids -> TOKEN_GROUPS
          |
          v
  Validate native buffer lengths, group entries, and SID bounds
          |
          v
  EqualSid: user == SYSTEM
  EqualSid: group == broker service SID
    group enabled; not SE_GROUP_USE_FOR_DENY_ONLY
          |
          +-- query / bounds / identity failure --+
          |                                     |
          v                                     v
  RpcFreeAuthorizationContext        RpcFreeAuthorizationContext
          |                                     |
          v                                     v
        ALLOW                                  DENY

Callback allows -> manager repeats guard -> bounded snapshot copy
```

`RpcServerInqCallAttributesW` receives a version-2 structure with
`RPC_QUERY_IS_CLIENT_LOCAL`. The code requires `RPC_PROTSEQ_LRPC`, `rcclLocal`,
`NullSession == 0`, `RPC_C_AUTHN_WINNT`, and an authentication level at least
`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`. Unavailable or unexpected attributes deny the
call. See Microsoft's [call-attribute query](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcserverinqcallattributesw)
and [version-2 fields](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_w).

`RpcGetAuthorizationContextForClient` uses `ImpersonateOnReturn=FALSE` and zero
or null reserved parameters. The Authz queries read the authenticated caller's
identity without leaving its token attached to the BFD thread. This path does
not call `RpcImpersonateClient` or require added `SeImpersonatePrivilege`.
See Microsoft's [authorization-context contract](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcgetauthorizationcontextforclient).

`AuthzGetInformationFromContext` retrieves `AuthzContextInfoUserSid` and
`AuthzContextInfoGroupsSids`. `EqualSid` compares the account with SYSTEM and
the service group with `NT SERVICE\BfdBgpBroker`; the group must have
`SE_GROUP_ENABLED` and lack `SE_GROUP_USE_FOR_DENY_ONLY`. A same-account process
without that group fails. These explicit identity comparisons supplement the
runtime ACL check; they do not reimplement restricted-token access checking.
See Microsoft's [Authz query](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzgetinformationfromcontext),
[information classes](https://learn.microsoft.com/en-us/windows/win32/api/authz/ne-authz-authz_context_information_class),
and [EqualSid preconditions](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid).

The Rust wrapper bounds each identity result to 1 MiB, uses initialized aligned
storage, and checks structure lengths, group-count arithmetic, SID alignment,
revision, and SID body bounds before native comparison. An acquired context is
owned by a drop guard and released with `RpcFreeAuthorizationContext` on both
success and rejection, rather than `AuthzFreeContext`. See Microsoft's
[RPC context release](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcfreeauthorizationcontext).

The ownership story is dialed in too: each acquired context has a release path,
including rejected calls. Native parsing still carries its documented bounds
and layout obligations.

#### Authz responsibilities

The implemented Authz path fits the requirement to compare the exact account
SID and enabled service SID directly. The W is the exact authorization policy
and its rejection coverage. The Authz wrapper owns native buffer parsing,
context lifetime, and cleanup. The authorization policy,
transport/authentication checks, correct API use, and
reviewed FFI boundary determine whether the implementation enforces its intended
trust boundary.

#### Soundness and operational limits

The layered design is sound for the stated local-service identity boundary, and
the regression receipts back that assessment. Windows checks the expected
server, the interface ACL gates callers, the callback and manager require the
exact broker identity, and BFD never adopts the broker's token for resource
access. Stoked on that separation: the network-facing process keeps its reduced
identity throughout the exchange. This is a design assessment, not a proof of
Rust memory soundness or the absence of vulnerabilities. It assumes trustworthy
Windows authentication, SCM service-token construction, protected configuration
and binaries, and the native RPC/Authz implementation. Administrators and SYSTEM
that can replace code or change service policy remain trusted; a matching SID
does not attest which executable is running.

The status and availability boundaries apply these additional checks:

| Surface | Enforced policy and limit |
| --- | --- |
| Status record | Robust fixed-size MIDL stubs and one Rust conversion use enums, `TryFrom`, `NonZero`, checked time arithmetic, and canonical optional fields. Valid shape does not prove a report is truthful. |
| Invalid status | Discard the whole record, clear prior cached telemetry, retry with capped backoff, and rate-limit Error 301 to once per minute; provider work continues. |
| Native boundary | MIDL, the C exception bridge, Windows APIs, and unsafe Rust wrappers must uphold their layout, bounds, and lifetime contracts. Safe Rust validation cannot repair prior native memory corruption. |
| Authorized malicious source | A compromised authorized BFD process can return structurally valid false telemetry or withhold replies. Authentication establishes source identity, not session truth. |

The recovery path keeps its balance when telemetry gets choppy. Native bind and
call deadlines are two seconds each. An eight-second supervisor
budget quarantines a stuck worker. Its owned native storage remains live;
shutdown does not kill that thread, free pending buffers, or wait indefinitely
for it. At most one monitored RPC operation can remain unfinished.

Completed failures back off through 1, 2, 4, 8, 16, then 30 seconds. A valid reply
resets polling to one second, and Stop interrupts the wait. Rejecting a field
does not establish memory corruption or require quarantine. Fatal native faults
are not converted to recoverable RPC errors. Authentication prevents unrelated
processes from injecting replies; checked conversion handles incorrect values
from an authenticated source. See
[injection and Rust's safety boundary](rpc-session-status-design.md#injection-and-rusts-safety-boundary).

`MaxRpcSize` does not constrain LRPC, and
`MaxCalls` is best effort; a separate nonblocking permit caps status managers at
four. RPC workers read snapshots without taking a lock on the packet engine.
These bounds reduce contention but do not guarantee availability under host
resource exhaustion or an authorized client's repeated requests. Status fetches,
invalid replies, timeouts, and quarantine never fabricate a BFD Down state or
issue BGP actions. The existing BGP control pipe and COM/MI provider policy remain
separate.

Native tests cover malformed replies, identity rejection, cancellation, and
same-process coexistence with real read-only MI provider traffic. Installed
SCM-issued identities still require the separate MSI first-start/repair check.
For API settings and primary references, see
[RPC authentication](rpc-authentication.md). For payload bounds and failure
policy, see [RPC session-status query](rpc-session-status-design.md).

## Rust compiler and linker hardening

Hardening brings another set of checks to the lineup: guarded indirect calls,
stack protection, relocation metadata, and explicit failure behavior. These
layers add protection around the identity and input-validation boundaries.

The settings in [Cargo.toml](../Cargo.toml) and
[.cargo/config.toml](../.cargo/config.toml) apply to both executables. The build
targets `x86_64-pc-windows-msvc` and rejects other Windows architectures.
[rust-toolchain.toml](../rust-toolchain.toml) pins the nightly compiler and includes
`rust-src` for rebuilding the standard library.

Compiler instrumentation and executable metadata make certain attacks harder
or terminate the process when checks fail. They do not replace authentication,
ACLs, or correct handling of untrusted packets.

### Rust compiler options

The compiler and Cargo profiles provide these protections:

| Setting | Security benefit and scope |
| --- | --- |
| `-C control-flow-guard=yes` | Inserts checks on indirect calls and emits valid-call-target metadata. Together with `/GUARD:CF`, lets Windows reject invalid call targets caused by corrupted function pointers. See [Rust CFG options](https://doc.rust-lang.org/rustc/codegen-options/index.html#control-flow-guard). |
| `-C relocation-model=pic` | Generates position-independent code suitable for relocation, supporting randomized load addresses. ASLR also needs linker metadata and Windows support. See [Rust relocation models](https://doc.rust-lang.org/rustc/codegen-options/index.html#relocation-model). |
| `-Z stack-protector=all` | Requests stack canaries in all functions and checks them on return to detect stack corruption. This is Rust's compiler instrumentation; MSVC's `/GS` is a C/C++ compiler option. Canaries detect some corruption, not every memory error. See [Rust stack protector](https://doc.rust-lang.org/unstable-book/compiler-flags/stack-protector.html). |
| `-Z ehcont-guard=yes` | Emits valid exception continuation targets for the linker. With `/GUARD:EHCONT`, supports Windows validation of resumed instruction pointers. See [EH continuation metadata](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata?view=msvc-170). |
| `overflow-checks = true` in development and release | Makes overflowing ordinary integer arithmetic panic instead of silently wrapping. Explicit `wrapping_*`, `saturating_*`, and `checked_*` operations retain their intended behavior. See [Cargo overflow checks](https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks). |
| `panic = "abort"` in production release | Immediately terminates on a panic rather than unwinding through the process. Destructors, BGP cleanup, and normal service-stop logging do not run on this path. Normal handled errors still use `Result` and cleanup. See [Cargo panic strategy](https://doc.rust-lang.org/cargo/reference/profiles.html#panic). |

`stack-protector` and `ehcont-guard` use nightly Rust. Cargo's
[`build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std)
configuration rebuilds `std` and `panic_unwind` with target flags, extending
instrumentation to the service, its Rust dependencies, and the target standard
library. Windows system DLLs retain their own build settings. The explicit target
keeps host build scripts and procedural macros on default host settings.

### MSVC linker options

The executable brings its mitigation receipts to the break. Rust passes these
options through `-C link-arg=...` to the MSVC linker:

| Option | Security benefit and scope |
| --- | --- |
| `/MACHINE:X64` | Selects the supported 64-bit executable architecture. This enables the x64 mitigation configuration; architecture selection alone is not an access control. |
| [`/DYNAMICBASE`](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170) | Marks the image for address space layout randomization (ASLR), making useful code/data locations less predictable. |
| [`/HIGHENTROPYVA`](https://learn.microsoft.com/en-us/cpp/build/reference/highentropyva?view=msvc-170) | Enables high-entropy 64-bit ASLR, increasing the address space available for randomization. Requires `/DYNAMICBASE` and `/LARGEADDRESSAWARE`. |
| [`/LARGEADDRESSAWARE`](https://learn.microsoft.com/en-us/cpp/build/reference/largeaddressaware-handle-large-addresses?view=msvc-170) | Lets the image use addresses above 2 GB and supports high-entropy ASLR. It is not a memory-safety check. |
| [`/NXCOMPAT`](https://learn.microsoft.com/en-us/cpp/build/reference/nxcompat-compatible-with-data-execution-prevention?view=msvc-170) | Declares compatibility with Data Execution Prevention (DEP/NX), which prevents execution from pages marked as data. Does not prevent corruption or reuse of existing executable code. |
| [`/GUARD:CF`](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks?view=msvc-170) | Includes CFG image flags and valid-call-target tables. Works with Rust's CFG instrumentation; the linker switch alone does not add call-site checks. |
| [`/GUARD:EHCONT`](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata?view=msvc-170) | Links EH continuation metadata for Windows instruction-pointer validation during context restoration. An enabled empty table is valid when the image has no continuation targets. |
| [`/CETCOMPAT`](https://learn.microsoft.com/en-us/cpp/build/reference/cetcompat?view=msvc-170) | Marks compatibility with Control-flow Enforcement Technology (CET) shadow stacks, which protect return addresses against return-oriented attacks. Actual enforcement requires suitable hardware, Windows support, and process mitigation policy. |

Structured Exception Handling Overwrite Protection (SEHOP) is a separate Windows
process policy. It is not enabled by these linker flags. On x64, exception
handlers use table-based metadata; `/SAFESEH` is an x86-only option. See
[Enable SEHOP for the executable](setup.md#enable-sehop-for-the-executable)
for the deployment setting.

### Diagnostics, lint policy, and security limits

The review tooling keeps the engineering lineup honest. AddressSanitizer (ASan)
adds runtime memory-error detection to test builds, and strict lints make their
configured violations fail the relevant checks. These settings control
diagnostics and code checks:

| Setting | Benefit and limitation |
| --- | --- |
| Release `opt-level = 3` | Optimizes runtime code. Optimization is not an authentication or memory-safety mechanism. |
| Development `debug = 2`; ASan inherits development | Retains full debugging information and PDBs to investigate failures. AddressSanitizer is test instrumentation for detecting memory errors, not a production authorization check. |
| Release `debug = 0`, `strip = "symbols"`, and `/DEBUG:NONE` | Omits debug information/symbols and suppresses MSVC PDB generation, reducing distributed diagnostic metadata. Release crash dumps lack matching PDBs for source-level debugging. These settings do not make code secret or verify executable integrity. |
| `-Z src-hash-algorithm=sha256` | Uses SHA-256 source checksums when debug information is emitted, helping debuggers match source files. These are not an executable signature or runtime authentication. |
| `warnings`, `unsafe_code`, `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks`, and `clippy::unwrap_used` set to `deny` | Makes warnings, unapproved unsafe code, implicit unsafe operations, undocumented unsafe blocks, and production `unwrap()` calls fail the relevant checks. Narrow Windows API boundaries explicitly allow required unsafe code and still require safety explanations. |

Cargo's [profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html)
describes optimization and debug settings. Rust ownership, initialization, and
bounds checks protect safe Rust code; Windows API calls still depend on correctly
reviewed unsafe boundaries. The build also compiles native C for local RPC;
those files have a separate compiler configuration.

### Native RPC compiler options

The C boundary gets its own protection lineup. Its stack-buffer, control-flow,
and additional compiler checks complement the Rust settings; their exact scope
is documented here so the stoke stays grounded.

[rpc/build.rs](../rpc/build.rs) runs the Windows SDK MIDL compiler with
`/env x64 /robust /Oicf /app_config`. It generates separate client and server
stubs; the client ACF selects asynchronous calls. MSVC `cl.exe` compiles both
generated stubs and `rpc/client.c`, `rpc/server.c`, and `rpc/allocator.c` with
`/MD /GS /guard:cf /guard:ehcont /sdl /W4 /D_WIN32_WINNT=0x0602`.
`lib.exe` combines the objects into `bfd_local_rpc.lib`, which links with
`Rpcrt4` into the Rust executables.

`/GS` provides native stack-buffer checks, `/guard:cf` and `/guard:ehcont`
provide native control-flow metadata, and `/sdl` enables additional MSVC security
checks. `/W4` selects warnings; the script does not pass `/WX`. These C compiler
options are separate from the Rust flags. See Microsoft's
[MSVC security checks](https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks?view=msvc-170).

The native compile step does not pass `/analyze`, `/Zi`, or an AddressSanitizer
option. `cargo asan` instruments Rust and the rebuilt Rust standard library;
it does not instrument these C translation units. Native stubs and wrappers
remain outside safe Rust's guarantees.

### Test-profile differences

The `test-release` alias overrides panic handling to `unwind` for the test graph.
It tests release optimizations but does not reproduce production's abort strategy.
The `asan` alias adds sanitizer instrumentation to tests, including the rebuilt
standard library, and retains the other target hardening settings.

Cargo's nightly `profile-rustflags` feature adds release-only `/DEBUG:NONE`
alongside the shared target flags, preserving development and ASan debug output.

### Verification

This is where the hardening claims show their receipts. The recorded reviews
link successful checks to their revisions, and the executable tests inspect
what the build actually emitted. That is a solid verification habit, dude.

[tests/windows_hardening.rs](../tests/windows_hardening.rs) checks both executable
images for architecture, relocations, ASLR/NX/CFG flags, CFG tables, security-cookie
metadata, EH continuation data, CET compatibility, and profile-specific debug
output. These checks verify emitted metadata. A security-cookie address alone
does not prove every function has stack-protector instrumentation, and a CET flag
does not prove that the host enforces shadow stacks.

For build commands, sanitizer checks, compiler-output inspection, and verification
of production artifacts, see [Build security](../CONTRIBUTING.md#build-security).
Recheck those settings after changing the toolchain, profiles, or compiler/linker
overrides.

## Source map

These files bring receipts for the whole lineup: they define the authentication
and privilege boundaries, with the implementation details behind the claims:

| Path | Relevant implementation |
| --- | --- |
| [installer/Package.wxs](../installer/Package.wxs) | Service accounts, dependencies, SCM control/query ACLs, Parameters ACL, and firewall rules |
| [src/service.rs](../src/service.rs) and [src/bgp_broker/service.rs](../src/bgp_broker/service.rs) | SCM lifecycle, startup checks, local RPC lifetime, private broker COM initialization, and conditional BGP broker probe |
| [src/runtime/privileges.rs](../src/runtime/privileges.rs) | BFD privilege allowlist; the in-process broker client retains the existing provider token |
| [src/transport.rs](../src/transport.rs) | `Datagram::validate`, transport construction, `send`, and `send_reply` |
| [src/session.rs](../src/session.rs), [src/packet.rs](../src/packet.rs), and [src/seamless.rs](../src/seamless.rs) | `receive_checked`, `receive_seamless`, `AuthConfig::verify_decoded`, and `respond_checked` |
| [src/local_rpc.rs](../src/local_rpc.rs) and [src/local_rpc/monitor.rs](../src/local_rpc/monitor.rs) | Private local RPC listener, in-process client, authentication, authorization, supervised worker, and telemetry cache |
| [src/local_rpc/identity.rs](../src/local_rpc/identity.rs) | Per-call transport/authentication checks and bounded Authz identity queries without token attachment |
| [rpc/bfd_local.idl](../rpc/bfd_local.idl), [rpc/client.c](../rpc/client.c), and [rpc/server.c](../rpc/server.c) | Probe/status contract, fixed record, MIDL stub bridge, native asynchronous deadlines, and RPC exception boundary |
| [rpc/build.rs](../rpc/build.rs) and [rpc/allocator.c](../rpc/allocator.c) | Native MIDL/MSVC build flags, static library assembly, and RPC allocation hooks |
| [src/runtime/status.rs](../src/runtime/status.rs), [src/local_rpc/status.rs](../src/local_rpc/status.rs), and [src/runtime/state.rs](../src/runtime/state.rs) | Immutable publications and checked RPC projection; the immediate atomic state observer stays separate from detailed telemetry |
| [src/bgp_broker/com.rs](../src/bgp_broker/com.rs) | Private broker COM security for native MI |
| [src/bgp/ipc.rs](../src/bgp/ipc.rs) | `require_broker_identity`, `identify_client`, `verify_server`, frame validation, and pipe listener |
| [src/bgp.rs](../src/bgp.rs) and [src/bgp_broker.rs](../src/bgp_broker.rs) | Bounded BGP mailbox, state-to-action policy, fixed target, and request dispatch |
| [src/bgp_broker/mi.rs](../src/bgp_broker/mi.rs) | Local MI destination, impersonation option, namespace, and provider calls |
| [src/config/registry.rs](../src/config/registry.rs) | `load_registry`, `SettingsWatch`, and `load_bgp_target` |
| [src/runtime/logging.rs](../src/runtime/logging.rs) and [events/BFD-Service.man](../events/BFD-Service.man) | Diagnostic queues, ETW output, optional file logging, and event channel |
