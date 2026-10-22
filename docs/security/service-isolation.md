# Service isolation and permissions

Cowabunga, service crew. Check the token before the mission starts. Windows
admins and developers, let's check which permissions each process actually gets,
dude. This reference explains installed service identities, privilege reduction,
protected objects, and the broker's Component Object Model (COM) and Management
Infrastructure (MI) provider boundary. Use it to distinguish service isolation
from local administrative access. For channel authentication, see
[Local RPC security](local-rpc.md).

See the [security overview](../security.md) for the full boundary map. On this
page:

- [Service tokens and privileges](#identities-and-privileges)
- [Object permissions](#protected-object-permissions)
- [Provider security](#local-windows-provider-security)

## Identities and privileges

Keep every turtle in its assigned permissions lane. Windows account and
service-SID checks keep each process in its lane with the permissions its role
needs. The network-facing BFD service and the privileged BGP broker use separate
identities.

### Installed service tokens

A security identifier (SID) identifies a Windows account or group. The installer
sets BFD to `SERVICE_SID_TYPE_RESTRICTED` (`3`) and keeps the broker at
`SERVICE_SID_TYPE_UNRESTRICTED` (`1`). BFD's account remains LocalService in
`TokenUser`; `NT SERVICE\BfdWinService` is an enabled normal group and also
appears in `TokenRestrictedSids`. The broker keeps LocalSystem as its account
and its own enabled service group. See Microsoft's [service SID
types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).

The BFD service token is write-restricted. Write access must pass the ordinary
token check and the restricting-SID check. The RPC interface and log-folder ACLs
explicitly grant the BFD service SID access, so shared LocalService account
permissions alone cannot authorize those writes. Other grants, such as Everyone
write access, can still satisfy the restricting check; this is not a complete
sandbox. Read access keeps its ordinary ACL checks. See Microsoft's
[write-restricted token
semantics](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

### Startup identity checks

Channel Donatello: inspect the token before opening resources. Identity
preflight, buddy: before loading configuration, creating sockets, or registering
local RPC in service mode, BFD checks its own process token. `TokenUser` must be
LocalService. The BFD SID must be enabled and not deny-only in `TokenGroups`;
both that SID and the write-restricted marker `S-1-5-33` must appear in
`TokenRestrictedSids`. These queries never attach a token to a thread or require
`SeImpersonatePrivilege`. SCM's installed SID-type policy supplies the write
restriction; the startup guard verifies the expected account and SID lists.

### Permissions by identity

Here's the permissions lineup for installed services and local callers:

| Identity | Permissions and limits |
| --- | --- |
| `BfdWinService`: LocalService with restricted `NT SERVICE\BfdWinService` SID | Receives and sends BFD packets, hosts the private local RPC interface, reads Parameters, writes its configured logs, and requests fixed-target BGP actions through the broker control RPC interface. The service SID participates in normal and restricting write checks. SCM limits its process token to `SeChangeNotifyPrivilege`; startup removes unused privileges before accepting traffic. |
| `BfdBgpBroker`: LocalSystem with unrestricted `NT SERVICE\BfdBgpBroker` SID | Queries BFD telemetry on a worker inside the existing broker process, owns the BGP control RPC interface, and invokes the local Windows BGP management provider. Startup checks LocalSystem in `TokenUser` and the enabled broker service group, then permanently removes all privileges except `SeChangeNotifyPrivilege` before initializing COM/MI, loading its target, or registering RPC. |
| Elevated Administrators and SYSTEM | Can install, start, stop, and reconfigure either service, modify installed files and Parameters, and manage permissions. Account or Administrator membership alone does not satisfy the private channels' service-specific identity checks. |
| Authenticated non-administrator local users | Can query service configuration/status, enumerate dependents, interrogate the service, and read its service ACL. Can read event/file logs under the applicable Windows permissions. Cannot use the private RPC interface, start, stop, reconfigure, or send custom controls to either installed service. |
| Other LocalService processes | Share BFD's account but not its service SID. Cannot authenticate as BFD to the broker or satisfy the broker identity required by BFD's local RPC interface. |
| Remote network peers | Can send UDP traffic through the configured firewall rules. Packets must pass protocol/path validation and any configured BFD authentication before affecting the session. Both private RPC interfaces require local `ncalrpc` calls. |

### BFD privilege allowlist

Turtle power comes with a deliberately small privilege list. The MSI sets BFD's
SCM `RequiredPrivileges` list to only `SeChangeNotifyPrivilege` in a native
commit action after the installation transaction succeeds. Installation leaves
the services stopped, so the allowlist
is in place before the first normal service start. SCM applies it when Windows
creates the process. The BFD process also permanently removes unused token
privileges, including `SeImpersonatePrivilege` and
`SeAssignPrimaryTokenPrivilege`, before loading configuration, creating sockets,
or registering local RPC. It retains only `SeChangeNotifyPrivilege` to bypass
directory traversal checks; see Microsoft's [privilege
constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants).
BFD uses unnamed synchronization events and does not create global file-mapping
or symbolic-link objects. Its RPC and socket paths do not require
`SeCreateGlobalPrivilege`; see Microsoft's [kernel object namespace
rules](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces).
Local RPC authentication keeps that reduced service identity and does not attach
a caller token to a thread. Access to the broker comes from its RPC interface
ACL and service identity checks.

### Broker privilege allowlist

A privileged broker still needs ninja discipline. The LocalSystem broker
permanently removes every token privilege except `SeChangeNotifyPrivilege` after
verifying its service identity and before initializing COM/MI, loading its
target, or registering RPC. Failure to reduce the token fails startup. Provider
calls use the broker's own account without `SeImpersonatePrivilege`. Its SYSTEM
account and group memberships still confer administrative access; privilege
removal does not sandbox the broker. A smaller privilege list is, like, tubular,
but it doesn't erase the account's authority.

The MSI also sets the broker's SCM `RequiredPrivileges` list to only
`SeChangeNotifyPrivilege`. SCM removes other privileges when creating the
process, before loader initialization. Startup reduction remains a second check.
The MSI test inspects the running broker token after startup and repair; a
separate isolated test reads the local provider schema with the reduced token.

### Installation and rollback

Keep the rollback plan totally tubular, including unusual prior settings.
Deferred account/SID configuration and rollback preserve the existing privilege
policy, including an unspecified or empty list. The protected snapshot records
both services' exact privilege policies before any mutation. The commit action
sets both minimum lists; if either change fails, rollback restores both prior
policies. Clearing a previous explicit list uses SCM's empty-list API request
and verifies the result. A previously explicit empty registry value retains its
exact representation after SCM's policy is restored. A snapshot-cleanup error is
diagnostic and leaves a recovery snapshot that blocks a later repair until an
administrator removes it. The installer does not substitute an assumed list of
Windows account privileges for an unspecified prior policy.

### Console execution

A console mission uses the launching identity, turtle crew. Foreground
`--console` execution uses the launching account and removes unused privileges.
It provides no BGP control. Removing token privileges does not remove account or
group memberships: an elevated console process still has the launching
administrator's identity. The LocalService boundary applies to the MSI-installed
service.

## Service control, configuration, and diagnostic access

Know who can read, configure, and kick shell with service controls.
Authenticated readers can inspect the granted service information; elevated
administrators and SYSTEM hold the configuration and control rights.

Windows checks the caller's access token against each object's ACL. There is no
application login or shared password for `Start-Service`, `Stop-Service`,
registry edits, or log reads. Use an elevated administrator token for service
control and configuration changes; SYSTEM retains full control.

### Protected object permissions

Object-permission vibe check: the MSI protects these objects:

| Object | Write/control access | Read/query access |
| --- | --- | --- |
| Both SCM service objects | SYSTEM and Administrators have full control, including Start/Stop and configuration changes. | Authenticated Users have query-config, query-status, enumerate-dependents, interrogate, and read-control rights (`0x2008d`). No Start/Stop, reconfiguration, or custom controls. |
| Installed executables, manifest, logging script, and installation directory | SYSTEM and Administrators have full control. | Users and the BFD service SID have read/execute access. |
| `HKLM\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters` | SYSTEM and Administrators have full control. | BFD service SID has read access; the LocalSystem broker reads its BGP target. Ordinary users cannot read authentication keys. |
| Default file-log directory | SYSTEM and Administrators have full control; BFD service SID has Modify access. | Users retain read access. Custom log paths use their provisioned filesystem ACLs. |
| `BFD-Service/Operational` event channel | Windows Event Log permissions govern event publication and channel management. | The manifest supplies no custom channel access ACL; existing Windows log-read permissions remain in effect. |

The BFD service SID's write restriction adds a token check; it does not replace
these object ACLs or restrict every read. The explicit service-SID grant on the
BGP control RPC interface and the log-folder Modify grant support both write
checks. A custom log path must grant the BFD service SID access to its folder,
active file, and rotated file; a grant only to the shared LocalService account
is insufficient for restricted writes.

### Configuration and operational visibility

The BFD service reads its configuration at startup. S-BFD timing and reflector
maintenance settings can reload through registry notifications, with polling as
a fallback. The broker's fixed target requires a restart to reload.

BFD writes Operational events through Event Tracing for Windows (ETW) and an
optional file log through a bounded logging queue. The broker writes Operational
events through its own queue and does not open the BFD file log. Both services
report lifecycle status and exit codes to SCM. A service-status query reports
Running/Stopped and process lifecycle, rather than the BFD session's Up/Down
state. See [Monitor service status and BFD events](../monitoring.md) and [Logs
and events](../logging.md).

## Local Windows provider security

Check the provider boundary before the pizza victory lap. Keep this one
straight, no cap: the broker executes provider work under its own LocalSystem
identity. RPC authorization does not attach a caller token to the provider
worker.

Native Management Infrastructure (MI) calls target the local
`root/Microsoft/Windows/RemoteAccess` namespace and `PS_BgpPeer` class. The
destination explicitly requests `IMPERSONATE`, so the Windows provider can
access resources under the broker's LocalSystem identity. Windows governs
provider authorization; the application supplies no separate provider password
or remote MI destination.

The broker's private Component Object Model (COM) initialization supports native
MI. Its process security descriptor admits only local SYSTEM. It explicitly sets
`RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` and an outgoing default of `IDENTIFY`. Packet
integrity protects against message tampering without encrypting the payload. See
Microsoft's [COM authentication
levels](https://learn.microsoft.com/en-us/windows/win32/com/authentication-level).

The broker sets `EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL` to prevent
activate-as-activator launches under its privileged identity and restrict custom
marshaling. The MI destination's explicit `IMPERSONATE` setting is scoped to
provider calls. It applies the shared `DONOT_HANDLE_ANY` exception policy and
strong unmarshaling policy before opening MI. A read-only native provider schema
test verifies compatibility with these settings and the SYSTEM-only descriptor;
it does not exercise a live BGP operation. See Microsoft's [COM security
capabilities](https://learn.microsoft.com/en-us/windows/win32/api/objidl/ne-objidl-eole_authentication_capabilities).

Windows Routing and Remote Access Service (RRAS) manages the final BGP
connection to the remote BGP peer. This repository invokes its local provider
and does not configure BGP wire authentication. Provider permissions and RRAS
process identity depend on the host's Windows configuration.

## Numeric service SIDs

The numeric service SIDs are fixed by the Windows service names:

| Service | SID |
| --- | --- |
| `BfdWinService` | `S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512` |
| `BfdBgpBroker` | `S-1-5-80-3301813337-1731295767-1225795713-3993009034-49020719` |
