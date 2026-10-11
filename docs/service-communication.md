# Service communication and privilege boundaries

For developers and Windows administrators, this diagram maps the installed
services' inputs, outputs, authentication checks, and privilege boundaries.
The editable [draw.io diagram](service-communication.drawio) includes runtime
communication and a separate configuration, lifecycle, and logging page.
It describes the MSI service configuration; `--console` uses the launching
account, removes unused token privileges, and provides no BGP control.

`-->` means a request or data flow. Vertical `^` / `|` / `v` arrows show requests
and responses or packets in both directions. Letters identify the checks explained
after the diagram. The two executables run in separate processes. Packet
processing and the optional BGP worker share the BFD process identity.
The installer enables both service SIDs with type `UNRESTRICTED`; BFD reduces
its token privileges before accepting
network traffic. LocalService is a Windows service account, not a standard
interactive user.

```text
EXTERNAL NETWORK / UNTRUSTED
[Remote BFD / S-BFD peer]
          ^
          | UDP probes/replies
          v
+--------------------------------------------------------------------------------+
| LOCAL SERVICE: BfdWinService / bfd-winservice.exe                              |
| Identity: LocalService + NT SERVICE\BfdWinService                              |
| Retains: SeChangeNotifyPrivilege, SeCreateGlobalPrivilege                      |
|                                                                                |
|   [UDP transport]                                                              |
|         | RX                                                                   |
|         v                                                                      |
|   [A: path checks + optional BFD auth]                                         |
|         | accepted packet                                                      |
|         v                                                                      |
|   [Session / timers / S-BFD reflector] --> [In-process state snapshot only]    |
|         |     |                                                                |
|         |     +----> encode + configured auth ----> UDP TX                     |
|         |                                                                      |
|         +----> [BGP worker: optional; bounded action queue]                    |
|                             |                                                  |
|                    [B: verify broker PID through SCM]                          |
+--------------------------------------------------------------------------------+
                             ^
                             | Get / Start / Stop; status/error reply
                             | \\.\pipe\BfdWinService.Bgp.v1
                             v
+--------------------------------------------------------------------------------+
| LOCAL SYSTEM: BfdBgpBroker / bfd-bgp-broker.exe                                |
| Identity: LocalSystem + NT SERVICE\BfdBgpBroker                                |
|                                                                                |
|   [C: startup identity check + pipe ACL + per-request client check]            |
|         | identification ends; RevertToSelf before provider work               |
|         v                                                                      |
|   [Validate 24-byte frame; operation allowlist; next sequence number]          |
|         |                                                                      |
|   [Fixed BGP target loaded from protected registry at startup]                 |
|         |                                                                      |
|   [Native MI client: Get / Start / Stop]                                       |
+--------------------------------------------------------------------------------+
                             ^
                             | Local MI; broker's LocalSystem identity
                             v
+--------------------------------------------------------------------------------+
| WINDOWS MANAGEMENT PROVIDER / OS-MANAGED PRIVILEGE BOUNDARY                    |
|   [D: provider access under broker identity; scoped IMPERSONATE]               |
|   root/Microsoft/Windows/RemoteAccess : PS_BgpPeer                             |
|                             |                                                  |
|                         [RRAS / BGP]                                           |
+--------------------------------------------------------------------------------+
                             ^
                             | OS-managed BGP connection (outside this repo)
                             v
                       [Remote BGP peer]
```

Packet validation and authentication run before accepted traffic can change
session state or refresh detection. Detection timeouts also change state and
can cause BGP actions.

The broker's private COM initialization supports native MI and admits only local
SYSTEM and Administrators. It grants no Authenticated Users or generic
Service-group access. See [Monitor service status and BFD events](monitoring.md)
for lifecycle queries and event-log monitoring.

## Authentication and authorization checks

The boundaries enforce different identities and permissions:

| Check | Where it runs | What it enforces |
| --- | --- | --- |
| A | BFD UDP transport, then session or reflector | Validates source/port, destination, interface, TTL/hop limit, BFD structure, and discriminators. If configured, verifies the shared password or keyed digest and applicable sequence rules. Path validation alone does not authenticate a peer. |
| B | BFD pipe client | Compares the Windows-reported named-pipe server PID with the running `BfdBgpBroker` SCM PID before exchanging messages. Opens the connection at `SECURITY_IDENTIFICATION`, with data read/write rights. |
| C | Broker startup, pipe creation, and every request | Startup requires LocalSystem and the enabled broker service SID. The protected pipe ACL grants BFD service SID data access and broker SID full access; remote pipe clients are rejected. Each request requires both enabled `NT SERVICE\BfdWinService` SID and LocalService SID. Identification is reverted before MI. Ordinary administrator clients and unrelated LocalService processes fail these client checks. |
| D | Broker's local MI destination and Windows provider | Uses the broker's LocalSystem identity after pipe identification ends. The MI destination explicitly requests `IMPERSONATE` so the local provider can access that identity. Windows owns provider authorization; the repository adds no provider password exchange or remote MI destination. |
| E | Windows registry, SCM, installer, and filesystem | Protected SCM ACLs give SYSTEM and Administrators full control and Authenticated Users query config/status, enumerate-dependents, interrogate, and read-control rights only. Start/Stop and reconfiguration require elevated Administrator or SYSTEM. Parameters grant SYSTEM/Administrators full control and BFD service SID read access. Non-administrators retain event/file log reads under the existing permissions. |

BFD wire authentication defaults to `none`. Supported alternatives are
`simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, and
`meticulous-sha1`. Simple passwords travel in cleartext. Classical keyed modes
use a receive sequence window; meticulous modes also reject repeated sequences.
S-BFD initiators require keyed replies to match unconsumed, unexpired probes.
Reflectors verify the configured authentication and copy a keyed request's
sequence into the response without keeping a receive window.

The authenticated pipe establishes which local process can request BGP actions.
Remote BFD peer authentication remains a separate check at A. With `Auth=none`,
traffic that passes protocol and path checks can influence the session and its
configured BGP actions without a shared-key check.

## UDP inputs and outputs

The selected role determines the socket endpoints. `P` and `Q` denote the local
and peer stable source ports, respectively, each in 49152-65535. The port
numbers can differ. Outgoing TTL/hop limit is 255.

| Role | Outgoing packet | Incoming packet | Receive TTL/hop limit |
| --- | --- | --- | --- |
| Classical single-hop | local:P -> peer:3784 | peer:Q -> local:3784 | Exactly 255 |
| Classical multihop | local:P -> peer:4784 | peer:Q -> local:4784 | Required metadata; `MinTtl` threshold if configured |
| S-BFD initiator | local:P -> reflector:7784 | reflector:7784 -> local:P | Required metadata; `MinTtl` threshold if configured |
| S-BFD reflector | local:7784 -> initiator's source port | initiator's source port -> local:7784 | Required metadata; `MinTtl` threshold if configured |

Classical point-to-point mode identifies the peer by its configured link and
discriminator rather than requiring a fixed source IP. S-BFD uses configured
peer/allowed-source rules. The reflector's runtime accepts nonzero source ports
other than 7784; the installed firewall limits requests to 49152-65535.

## Configuration, lifecycle, and diagnostic paths

These paths complement the runtime diagram:

```text
ELEVATED ADMINISTRATOR / SYSTEM
  |
  +-- [E: registry ACL] --> HKLM\SYSTEM\CurrentControlSet\Services\
  |                         BfdWinService\Parameters
  |                         |
  |                         +-- read --> BFD: session settings + auth keys
  |                         +-- read --> Broker: BGP peer name + routing domain
  |
  +-- [E: SCM access] ----> Start / Stop / lifecycle for both services
  |                         BFD depends on BfdBgpBroker
  |                         Broker depends on RpcSs
  |
  +-- MSI provisioning --> service accounts/SIDs, protected service ACLs,
                            executable/registry/log ACLs, UDP firewall rules

OUTPUT UNDER EACH SERVICE'S OWN IDENTITY
  BfdWinService -- bounded logging queue --> ETW / BFD-Service/Operational
                  +-----------------------> optional configured file log
  BfdBgpBroker -- bounded logging queue ---> ETW / BFD-Service/Operational
  Both services --------------------------> SCM status / exit codes

AUTHENTICATED LOCAL USER / READ-ONLY MONITORING
  +-- [E: SCM query rights] --> Running / Stopped and service configuration
  |                             No Start/Stop or custom control rights
  +-- [Windows log ACLs] ----> read Operational events and file logs
```

The BFD service reads its configuration at startup. S-BFD timing and reflector
maintenance settings can reload through registry notifications, with polling
as a fallback. The broker independently reads only its BGP target at startup;
requests cannot supply a peer name, routing domain, command, path, or registry key.
The broker does not open the BFD file log. Windows governs access to event logs;
the manifest does not declare a custom channel access ACL. The installed default
file-log folder keeps Users read access; custom log paths use their provisioned
filesystem ACLs. Non-administrators can query Windows service status and read logs,
but cannot Start/Stop either installed service. Windows service status reports
process lifecycle, not the BFD session's Up/Down state.

## BGP behavior

BGP control runs only when `BgpPeerName` is configured for classical BFD or an
S-BFD initiator. Reflectors reject BGP control. Plain BFD still has the installed
SCM dependency on the broker, but starts no BGP worker and makes no pipe probe.

Startup reads BGP status without changing the peer. Entering Up requests Start
if needed; Down after the session has established requests Stop. Peer AdminDown
or an administrative service stop withdraws the controller's own latest Stop
with Start when needed. Crashes and pipe disconnections do not themselves stop
the BGP peer.

The final RRAS-to-remote-peer link represents Windows-managed BGP behavior.
This repository invokes the local management provider; it does not implement
the BGP connection or configure its wire authentication. The actual RRAS
process token and deployed provider/channel ACLs require host inspection.

## Source map

These source files define the boundaries shown in the diagram:

| Path | Relevant implementation |
| --- | --- |
| [installer/Package.wxs](../installer/Package.wxs) | Service accounts, dependencies, SCM control/query ACLs, Parameters ACL, and firewall rules |
| [src/service.rs](../src/service.rs) and [src/bgp_broker/service.rs](../src/bgp_broker/service.rs) | SCM lifecycle, startup checks, private broker COM initialization, and conditional broker probe |
| [src/runtime/privileges.rs](../src/runtime/privileges.rs) | `RETAINED` and `drop_privileges` |
| [src/transport.rs](../src/transport.rs) | `Datagram::validate`, transport construction, `send`, and `send_reply` |
| [src/session.rs](../src/session.rs), [src/packet.rs](../src/packet.rs), and [src/seamless.rs](../src/seamless.rs) | `receive_checked`, `receive_seamless`, `AuthConfig::verify_decoded`, and `respond_checked` |
| [src/bgp_broker/com.rs](../src/bgp_broker/com.rs) and [src/runtime/state.rs](../src/runtime/state.rs) | Private broker COM security and the in-process atomic state observer |
| [src/bgp/ipc.rs](../src/bgp/ipc.rs) | `require_broker_identity`, `identify_client`, `verify_server`, frame validation, and pipe listener |
| [src/bgp.rs](../src/bgp.rs) and [src/bgp_broker.rs](../src/bgp_broker.rs) | Bounded BGP mailbox, state-to-action policy, fixed target, and request dispatch |
| [src/bgp_broker/mi.rs](../src/bgp_broker/mi.rs) | Local MI destination, impersonation option, namespace, and provider calls |
| [src/config/registry.rs](../src/config/registry.rs) | `load_registry`, `SettingsWatch`, and `load_bgp_target` |
| [src/runtime/logging.rs](../src/runtime/logging.rs) and [events/BFD-Service.man](../events/BFD-Service.man) | Diagnostic queues, ETW output, optional file logging, and event channel |
