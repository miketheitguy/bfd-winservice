# Service communication

For developers and Windows administrators, this page maps the installed
services' network endpoints, private local RPC interfaces, and BGP actions. See
[Security, authentication, and build hardening](security.md) for identities,
permissions, and authentication boundaries.

The key receipt: the packet engine drives BGP actions. The broker's status cache
is for observation, and an SCM `Running` status doesn't mean the session is Up.

BFD hosts an authenticated local RPC interface for the broker. The broker calls
it from a worker thread inside its existing process. BGP control uses a separate
authenticated local RPC interface; the Windows provider COM/MI API retains its
own contract.

Both service channels use Windows local RPC (`ncalrpc`) with WINNT packet
privacy, mutual service-identity checks, protected service-SID ACLs, and per-call
Authz authorization. The protocol name is `ncalrpc` on both paths; LRPC is the
Windows runtime's local-RPC name, not a separate transport or weaker mode.
Neither path uses TCP or the RPC named-pipe transport.

Each interface permits calls initiated in one direction:

| Call initiator | RPC server | Endpoint (`ncalrpc`) | Operations |
| --- | --- | --- | --- |
| Broker's telemetry worker | BFD service | `BfdWinService.Local.v2` | `GetSessionStatusV1` |
| BFD's BGP worker | BGP broker | `BfdWinService.Bgp.v1` | Control liveness check, `Get`, `Start`, `Stop` |

Diagram arrows show **call initiation**, from client to server. BFD returns
status replies to the broker; the broker returns control results to BFD
on their respective calls. These replies do not initiate reverse RPC calls.
Neither interface defines RPC callback operations, and fast bindings reject
server-initiated RPC callbacks. Local authorization callbacks only check access
inside the receiving process. See [Windows fast-binding restrictions](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind).

The runtime and lifecycle diagrams are embedded below as Mermaid. The
[RPC authentication diagram](rpc-authentication.md#rpc-authentication-flow)
shows the client, Windows RPC, and server checks. Their matching
[editable draw.io source](service-communication.drawio) has three pages.

Telemetry uses `BfdWinService.Local.v2`, `BfdLocal` version `2.0`.
The BGP control endpoint remains
`BfdWinService.Bgp.v1`, `BgpControl` version `1.0`.
The `V1` suffix in `GetSessionStatusV1` identifies the status-record schema;
the telemetry endpoint and RPC interface use version 2.

The [authentication diagram](rpc-authentication.md#rpc-authentication-flow)
names the client binding, server registration, call-attribute, Authz, SID, and
cleanup functions. For ASCII call flows and the security assessment, see
[private local RPC authentication](security/local-rpc.md#broker-authenticates-bfd-telemetry).

## Runtime flow

The boxes group work by process. Blue represents BFD, purple represents the
broker, amber marks authentication gates, green marks checked telemetry, and
gray represents Windows or a network peer. RPC arrows show call initiation;
responses return on the same call. The dashed BGP link is Windows-managed.
Classical multihop BGP control requires meticulous keyed authentication.

```mermaid
---
config:
  flowchart:
    wrappingWidth: 500
---
flowchart TB
    accTitle: Runtime boundaries: BfdWinService.Local.v2 and BfdLocal 2.0
    accDescr: The broker initiates authenticated local session-status RPC to BFD. BFD initiates a separate BGP control RPC to the broker. The packet engine drives BGP actions; the telemetry cache is observational. The broker retains only SeChangeNotifyPrivilege.
    %% Mirrors service-communication.drawio, page 1.

    subgraph rt_bfd["BfdWinService | bfd-winservice.exe"]
        direction TB
        rt_bfd_token["<b>BFD process identity</b><br/>LocalService + restricted BFD service SID<br/>SeChangeNotifyPrivilege + SeCreateGlobalPrivilege<br/>Validate identity before configured resources"]:::bfd
        rt_engine["<b>[A] BFD / S-BFD packet engine</b><br/>One owner of mutable session and timers<br/>Path validation + configured wire authentication<br/>Engine state drives the separate BGP worker<br/>Multihop BGP requires meticulous keyed authentication"]:::bfd
        rt_publisher["<b>Immutable status publication</b><br/>ArcSwap snapshot + coherent capture metadata<br/>Changes: 100 ms minimum; refresh target: 1 s<br/>Scheduling can delay either publication"]:::bfd
        rt_rpc["<b>[F] Authenticated local RPC server</b><br/>Endpoint: BfdWinService.Local.v2<br/>Interface: BfdLocal 2.0 / ncalrpc<br/>Operation: GetSessionStatusV1<br/>Broker SID ACL + exact SYSTEM caller / Authz<br/>One snapshot per status query; four manager permits<br/>Runtime management denied"]:::gate
        rt_bgp_client["<b>[B] Optional BGP RPC client worker</b><br/>Initiates Get / Start / Stop from engine state<br/>AdminDown releases BFD's own Stop<br/>Pin SYSTEM AND broker SID / QOS V5"]:::bfd
    end

    subgraph rt_broker["BfdBgpBroker | bfd-bgp-broker.exe"]
        direction TB
        rt_broker_token["<b>Broker process identity</b><br/>SYSTEM + enabled broker service SID<br/>Retain only SeChangeNotifyPrivilege<br/>Remove other privileges before COM / MI and RPC"]:::broker
        rt_monitor["<b>Status supervisor</b><br/>Starts after SCM Running; normal polling: 1 s<br/>One owned RPC worker; eight-second supervision budget<br/>Stop remains responsive during backoff or native stalls"]:::broker
        rt_cache["<b>Typed status cache: freshness needs receipts</b><br/>Native MIDL bounds + checked Rust conversion<br/>Fresh if snapshot age + fetch + elapsed &le; 2 s<br/>Invalid data clears cache; retry backoff: 1-30 s<br/>Worker stall: quarantine until broker restart<br/>Cache state never requests a BGP action"]:::cache
        rt_client["<b>[F] RPC client inside this broker process</b><br/>Initiates GetSessionStatusV1 calls<br/>Pin LocalService AND BFD service SID<br/>QOS V5 / static Identify / EffectiveOnly / privacy<br/>Asynchronous bind + status call: 2 s each<br/>Provider worker remains independent"]:::gate
        rt_control["<b>[C / D] BGP ncalrpc server + provider worker</b><br/>BfdWinService.Bgp.v1 / BgpControl 1.0<br/>LocalService + BFD SID / Authz; no impersonation<br/>One-slot queue; serialized native MI"]:::broker
    end

    rt_remote["<b>Remote BFD peer</b><br/>UDP BFD / S-BFD<br/>[A-fw] Program firewall rules<br/>[A] Packet / path checks<br/>Wire auth defaults to none"]:::external
    rt_provider["<b>[D] Windows BGP provider / RRAS</b><br/>Native PS_BgpPeer COM / MI; configured target<br/>Provider and wire behavior: Windows-managed"]:::external
    rt_bgp_peer["<b>Remote BGP peer</b><br/>Connection managed by Windows RRAS"]:::external

    rt_remote <-->|"UDP"| rt_engine
    rt_engine -->|"scheduled publication"| rt_publisher
    rt_publisher -->|"one immutable view"| rt_rpc
    rt_client -->|"Session status<br/>ncalrpc"| rt_rpc
    rt_client -->|"validate result"| rt_cache
    rt_bgp_client -->|"BGP control<br/>ncalrpc"| rt_control
    rt_control -->|"COM / MI"| rt_provider
    rt_provider -.->|"BGP"| rt_bgp_peer

    %% Invisible links align independent sections; they do not represent calls.
    rt_bfd_token ~~~ rt_engine
    rt_rpc ~~~ rt_bgp_client
    rt_broker_token ~~~ rt_monitor
    rt_monitor ~~~ rt_client
    rt_cache ~~~ rt_control

    classDef bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43
    classDef broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43
    classDef gate fill:#FFF4D9,stroke:#B98521,color:#1C2B43
    classDef cache fill:#EAF5EC,stroke:#558563,color:#1C2B43
    classDef external fill:#F1F3F6,stroke:#778397,color:#1C2B43
    classDef note fill:#FFFFFF,stroke:#B8C2D0,color:#1C2B43
    style rt_bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43
    style rt_broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43
```

The two installed services use these paths:

1. `BfdWinService` receives and validates UDP packets and executes BFD/S-BFD
   timers as LocalService. Its mutable session has one engine owner.
2. The engine coalesces telemetry into an immutable `ArcSwap` snapshot, normally
   at most every 100 milliseconds, with a one-second unchanged refresh.
3. BFD's private `ncalrpc` interface, `BfdWinService.Local.v2`, exposes only
   `GetSessionStatusV1`. An RPC worker authorizes the broker, loads one
   snapshot, and copies a fixed record without requesting packet-loop work.
4. The broker's RPC worker runs inside `bfd-bgp-broker.exe`. It authenticates BFD
   and converts the reply into checked Rust types before publishing its cache.
   There is no helper executable instance, stdout transport, or additional pipe.
5. When `BgpPeerName` is configured, BFD's separate BGP worker sends `Get`,
   `Start`, or `Stop` on the `ncalrpc` endpoint `BfdWinService.Bgp.v1`. The client
   pins SYSTEM and the broker SID; the broker checks BFD through Authz without
   impersonation.
6. The broker invokes native Management Infrastructure (MI) against the local
   `PS_BgpPeer` provider for its configured target. Windows RRAS manages the BGP
   connection to the remote peer.

The status cache is observational. Invalid, unavailable, or stale telemetry does
not request a BGP action or become a fabricated BFD state. The provider worker
remains independent of telemetry and uses the broker's reduced SYSTEM token
and configured COM/MI security.

## Service lifecycle

SCM starts BFD as soon as the broker reports Running. The broker's telemetry
worker runs concurrently with BFD startup.

```mermaid
---
config:
  flowchart:
    wrappingWidth: 500
---
flowchart TB
    accTitle: Service lifecycle: startup, status fetching, and administrative shutdown
    accDescr: SCM starts RpcSs, the broker, and BFD in dependency order. Both services validate and reduce their tokens before accepting work. The status supervisor owns one RPC worker and quarantines stalled telemetry while the provider continues. Shutdown preserves native ownership.
    %% Mirrors service-communication.drawio, page 2.

    lc_scm["<b>[E] Windows Service Control Manager</b><br/>RpcSs → BfdBgpBroker → BfdWinService<br/>Applies installed accounts, service SIDs, and privilege policy"]:::external
    subgraph lc_broker["Broker service process"]
        direction TB
        lc_broker_init["<b>1. Verify broker identity; initialize provider host</b><br/>SYSTEM account + enabled broker service group<br/>Retain only SeChangeNotifyPrivilege<br/>Initialize COM / MI; load protected target"]:::broker
        lc_broker_running["<b>2. Secure BGP RPC; then report SCM Running</b><br/>BFD-SID ACL / local private calls / Authz / deny management"]:::broker
        lc_monitor["<b>3. Start supervisor and one RPC worker</b><br/>Both are threads inside bfd-bgp-broker.exe<br/>One in-flight call; polling: 1 s; backoff: 1-30 s<br/>BGP RPC / provider worker remains independent"]:::broker
        lc_call["<b>Authenticated bind + GetSessionStatusV1</b><br/>BfdWinService.Local.v2 / BfdLocal 2.0<br/>Fixed BFD account / service-SID policy<br/>Native asynchronous deadlines: 2 s bind + 2 s call<br/>Supervisor budget: 8 s; never kill the native worker"]:::gate
        lc_cache["<b>Supervise results; maintain the typed cache</b><br/>Native bounds and Rust conversion before publication<br/>Valid data: typed cache; reset retry history<br/>Invalid / failed reply: clear cache; backoff 1–30 s<br/>Stop interrupts backoff; no fabricated state"]:::cache
        lc_quarantine["<b>Stuck worker: quarantine telemetry</b><br/>Clear prior telemetry; retain native call storage<br/>Log one Error 301; fetches stop until broker restart<br/>Keep provider running; no BGP action or automatic restart"]:::gate
    end

    subgraph lc_bfd["BFD service | LocalService + restricted SID"]
        direction TB
        lc_bfd_start["<b>4. SCM starts BFD after the broker dependency</b><br/>StartPending checkpoints advance during initialization"]:::bfd
        lc_bfd_guard["<b>5. Validate and reduce the BFD token</b><br/>LocalService + enabled BFD service group<br/>BFD SID + S-1-5-33 in restricting list<br/>Remove unused privileges before configured resources"]:::gate
        lc_engine["<b>6. Create engine and its read-only status observer</b><br/>Initial snapshot and capture metadata exist before RPC<br/>Configured BGP startup verifies its control connection"]:::bfd
        lc_listener["<b>7. Register the private RPC interface</b><br/>Deny runtime management before opening the endpoint<br/>Explicit descriptor + per-call callback + manager authorization<br/>Read one Arc snapshot; no engine lock or query messages"]:::gate
        lc_bfd_running["<b>8. Report Running; execute the packet engine</b><br/>Lifecycle, RPC success, and session state are separate<br/>Nominal publication: changed 100 ms / refresh 1 s"]:::bfd
    end

    lc_shutdown["<b>Administrative shutdown and ownership</b><br/>Close status observation when packet processing ends. On administrative stop, announce AdminDown as the role permits.<br/>For a communicating classical session, repeat permitted announcements up to the MaxShutdownAnnounceMs limit.<br/>Withdraw the latest BGP Stop issued by BFD with Start when needed. Finish the final action (20 s per broker call), then drain RPC.<br/>SCM cleanup budgets: BFD 60 s plus announcement period; broker 60 s. These differ from the 8 s telemetry supervision budget.<br/>Broker joins the RPC supervisor; an unfinished native worker retains its stack, binding, events, and output until completion or process exit.<br/>Telemetry failures never request BGP actions. A stuck RPC worker is quarantined without launching replacements or aborting the provider host."]:::note

    lc_scm -->|"start dependency"| lc_broker_init
    lc_broker_init -->|"initialized"| lc_broker_running
    lc_broker_running -->|"background"| lc_monitor
    lc_monitor -->|"supervise"| lc_cache
    lc_cache <-->|"request / result"| lc_call
    lc_call -->|"stalled"| lc_quarantine
    lc_broker_running -->|"dependency ready"| lc_bfd_start
    lc_bfd_start -->|"validate"| lc_bfd_guard
    lc_bfd_guard -->|"reduced token"| lc_engine
    lc_engine -->|"observer"| lc_listener
    lc_listener -->|"ready"| lc_bfd_running
    lc_call -->|"Session status<br/>ncalrpc"| lc_listener

    %% Invisible links align independent sections; they do not represent calls.
    lc_bfd_running ~~~ lc_shutdown
    lc_quarantine ~~~ lc_shutdown

    classDef bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43
    classDef broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43
    classDef gate fill:#FFF4D9,stroke:#B98521,color:#1C2B43
    classDef cache fill:#EAF5EC,stroke:#558563,color:#1C2B43
    classDef external fill:#F1F3F6,stroke:#778397,color:#1C2B43
    classDef note fill:#FFFFFF,stroke:#B8C2D0,color:#1C2B43
    style lc_broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43
    style lc_bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43
```

SCM starts `RpcSs`, then `BfdBgpBroker`, then its dependent `BfdWinService`.
The broker secures its BGP control RPC interface before reporting Running,
then starts the telemetry monitor and retries while BFD initializes. BFD gives
RPC a read-only observer before moving the engine to its packet worker. Neither SCM Running nor RPC success implies a session is Up.

BFD closes its observer as soon as packet processing ends, before announcements
and BGP cleanup. After cleanup, it unregisters and drains its interface before
releasing the security descriptor. The broker stops its
supervisor without joining an unfinished native RPC worker. That single owned
worker retains its native call storage until completion or process exit; it is
never forcibly terminated or replaced repeatedly.

An administrative BFD stop repeats AdminDown announcements for a communicating
classical session's detection period, capped by `MaxShutdownAnnounceMs`. Other
roles or sessions attempt one role-permitted notification; reflectors send none.
It also withdraws the controller's own
latest BGP Stop with Start when needed, then finishes the latest queued action.
Each final broker call has a 20-second limit. BFD's SCM supervisor allows
60 seconds plus the announcement period for cleanup; the broker's stop budget
is 60 seconds. These service cleanup budgets are separate from the eight-second
RPC telemetry budget. See [BGP lifecycle and shutdown](bgp.md).

## Private local RPC status

`src/local_rpc.rs` owns registration and the fixed BFD client identity policy.
`src/local_rpc/status.rs` owns the fixed record and conversion into Rust domain
types. `src/local_rpc/monitor.rs` owns one supervised RPC worker and the cache.
Both broker threads run inside the existing service process.

Authentication pins LocalService plus the BFD service SID on the client. BFD
requires SYSTEM plus the broker service SID on every call. Static Identify
credentials and packet privacy protect the exchange without enabling additional
privileges. Broker startup permanently removes every token privilege except
`SeChangeNotifyPrivilege` before COM/MI initialization; provider calls retain
the broker's own SYSTEM account and its existing COM/MI security policy.
The BFD token retains its existing two-entry privilege allowlist and restricted
service SID policy. See [RPC authentication](rpc-authentication.md).

Binding and the status call each have a two-second native asynchronous deadline.
The supervisor imposes an eight-second monitoring budget. A stalled worker
quarantines telemetry until broker restart. Invalid replies and transient
failures clear the cache to `Unavailable` and retry after 1, 2, 4, 8, 16, then
30 seconds; a valid reply restores one-second polling. Stop interrupts backoff.
These query failures do not kill the provider host; fatal native faults remain
outside the recoverable RPC handler.

See [RPC session-status query](rpc-session-status-design.md) for response fields,
accepted ranges, freshness, quarantine policy, and validation results. For
operator queries, see [Monitor service status and BFD events](monitoring.md).

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

## BGP behavior

BGP control runs only when `BgpPeerName` is configured for classical BFD or an
S-BFD initiator. Reflectors reject BGP control. Plain BFD still has the installed
SCM dependency on the broker, but starts no BGP worker and makes no BGP RPC connection check.

Startup reads BGP status without changing the peer. Entering Up requests Start
if needed; Down after the session has established requests Stop. Peer AdminDown
or an administrative service stop withdraws the controller's own latest Stop
with Start when needed. Crashes and RPC disconnections do not themselves stop
the BGP peer.

The final RRAS-to-remote-peer link represents Windows-managed BGP behavior.
This repository invokes the local management provider; it does not implement
the BGP connection or configure its wire authentication. The actual RRAS
process token and deployed provider/channel ACLs require host inspection.

For implementation locations, see the [security source map](security.md#source-map).
