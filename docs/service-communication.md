# Service communication

Cowabunga, developers and Windows admins! Let's trace the service lineup, dude.
This page maps the installed services' network endpoints, private local RPC
interfaces, and BGP actions. See
[Security, authentication, and build hardening](security.md) for identities,
permissions, and authentication boundaries.

The key receipt, no cap: the packet engine drives BGP actions. The broker's
status cache is for observation, and an SCM `Running` status doesn't mean the
session is Up.

BFD hosts an authenticated local RPC interface for the broker. The broker calls
it from a worker thread inside its existing process. BGP control uses a separate
authenticated local RPC interface; the Windows provider COM/MI API retains its
own contract.

For service identities, binding settings, and authorization, use the
[RPC authentication guide](rpc-authentication.md). Both service channels use
Windows local RPC (`ncalrpc`), with separate contracts and call initiators.

Each interface keeps call initiation in one direction, dude:

| Call initiator | RPC server | Endpoint (`ncalrpc`) | Operations |
| --- | --- | --- | --- |
| Broker's telemetry worker | BFD service | `BfdWinService.Local.v2` | `GetSessionStatusV1` |
| BFD's BGP worker | BGP broker | `BfdWinService.Bgp.v2` | `Get`, `Start`, `Stop` |

Diagram arrows show **call initiation**, from client to server. BFD returns
status replies to the broker; the broker returns control results to BFD
on their respective calls. These replies do not initiate reverse RPC calls.
Mermaid RPC arrows attach to process boundaries; the named client and server
cards identify the workers inside them.
Neither interface defines RPC callback operations, and fast bindings reject
server-initiated RPC callbacks. Local authorization callbacks only check access
inside the receiving process. See [Windows fast-binding restrictions](https://learn.microsoft.com/en-us/windows/win32/api/rpcasync/nf-rpcasync-rpcbindingbind).

The runtime and lifecycle diagrams each have separate PNG and Mermaid sections.
Use the PNG versions in GitHub mobile and select an image to open it at full size.
The [RPC authentication diagram](rpc-authentication.md#rpc-authentication-flow)
shows the client, Windows RPC, and server checks in both formats. Their matching
[editable draw.io source](service-communication.drawio) has three pages.

The `V1` in `GetSessionStatusV1` names the status-record schema; the telemetry
endpoint and RPC interface use version 2. See the
[status contract](rpc-session-status-design.md#native-interface-contract) for
the wire definition and deployment requirements.

## Runtime flow

Here's how to read the lineup, buddy: the boxes group work by process. Blue
represents BFD, purple represents the broker, amber marks authentication gates,
green marks checked telemetry, and gray represents Windows or a network peer.
RPC arrows show call initiation; responses return on the same call. The dashed
BGP link is Windows-managed. Classical multihop BGP control requires meticulous
keyed authentication.

### Runtime diagram (PNG)

[![Runtime boundaries showing BFD packet processing, broker status queries, and BFD-initiated BGP control.](images/service-communication-runtime-v2-hardened.png)](images/service-communication-runtime-v2-hardened.png)

### Runtime diagram (Mermaid)

```mermaid
---
config:
  layout: elk
  look: classic
  theme: base
  fontFamily: Segoe UI, Arial, sans-serif
  themeVariables:
    fontSize: 15px
    primaryTextColor: '#1C2B43'
    lineColor: '#526987'
    clusterBkg: '#FFFFFF'
    edgeLabelBackground: '#FFFFFF'
  flowchart:
    wrappingWidth: 330
    padding: 16
    nodeSpacing: 26
    rankSpacing: 50
    curve: stepBefore
---
flowchart LR
    accTitle: Runtime boundaries: BfdWinService.Local.v2 and BfdLocal 2.0
    accDescr: The broker initiates authenticated local session-status RPC to BFD. BFD initiates a separate BGP control RPC to the broker. The packet engine drives BGP actions; the telemetry cache is observational. Both services retain only SeChangeNotifyPrivilege.
    %% Mirrors service-communication.drawio, page 1.

    subgraph rt_bfd["BfdWinService | bfd-winservice.exe"]
        direction TB
        rt_bfd_token["<b>BFD process identity</b><br/>LocalService + restricted service SID<br/>Only SeChangeNotifyPrivilege retained"]:::bfd
        rt_engine["<b>[A] BFD / S-BFD packet engine</b><br/>Owns session state and timers<br/>Validates packets; drives BGP actions"]:::bfd
        rt_publisher["<b>Immutable status publication</b><br/>Coherent ArcSwap snapshot<br/>100 ms change spacing / 1 s refresh target"]:::bfd
        rt_rpc["<b>[F] Authenticated local RPC server</b><br/>BfdWinService.Local.v2 / BfdLocal 2.0<br/>GetSessionStatusV1; broker identity required"]:::gate
        rt_bgp_client["<b>[B] Optional BGP client worker</b><br/>Get / Start / Stop from engine state<br/>Pins SYSTEM and broker service SID"]:::bfd
    end

    subgraph rt_broker["BfdBgpBroker | bfd-bgp-broker.exe"]
        direction TB
        rt_broker_token["<b>Broker process identity</b><br/>SYSTEM + broker service SID<br/>Only SeChangeNotifyPrivilege retained"]:::broker
        rt_monitor["<b>Status supervisor</b><br/>One RPC worker inside this process<br/>Provider work remains independent"]:::broker
        rt_cache["<b>Checked telemetry cache</b><br/>Validate the whole reply and its freshness<br/>Cache state never requests BGP actions"]:::cache
        rt_client["<b>[F] Session-status RPC client</b><br/>Initiates GetSessionStatusV1<br/>Pins LocalService and BFD service SID"]:::gate
        rt_control["<b>[C / D] BGP server and provider worker</b><br/>BfdWinService.Bgp.v2 / BgpControl 2.0<br/>Authorizes BFD; serialized native MI"]:::broker
    end

    rt_remote["<b>Remote BFD peer</b><br/>UDP BFD / S-BFD<br/>Firewall and path checks<br/>Wire auth defaults to none"]:::external
    subgraph rt_external["Windows-managed BGP"]
        direction TB
        rt_provider["<b>[D] Windows BGP provider / RRAS</b><br/>PS_BgpPeer through COM / MI"]:::external
        rt_bgp_peer["<b>Remote BGP peer</b><br/>Connection managed by Windows RRAS"]:::external
    end

    rt_remote <-->|"UDP"| rt_bfd
    rt_engine -->|"scheduled publication"| rt_publisher
    rt_publisher -->|"one immutable view"| rt_rpc
    rt_broker -->|"Session status / ncalrpc"| rt_bfd
    rt_client -->|"validate result"| rt_cache
    rt_bfd -->|"BGP control / ncalrpc"| rt_broker
    rt_broker -->|"COM / MI"| rt_external
    rt_provider -.->|"BGP"| rt_bgp_peer

    %% Invisible links align independent sections; they do not represent calls.
    rt_bfd_token ~~~ rt_engine
    rt_rpc ~~~ rt_bgp_client
    rt_broker_token ~~~ rt_monitor
    rt_monitor ~~~ rt_client
    rt_cache ~~~ rt_control

    classDef bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef gate fill:#FFF4D9,stroke:#B98521,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef cache fill:#EAF5EC,stroke:#558563,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef external fill:#F1F3F6,stroke:#778397,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef note fill:#FFFFFF,stroke:#B8C2D0,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    style rt_bfd fill:#FFFFFF,stroke:#3A69A6,color:#1C2B43,stroke-width:2px,rx:12,ry:12
    style rt_broker fill:#FFFFFF,stroke:#7957A2,color:#1C2B43,stroke-width:2px,rx:12,ry:12

    style rt_external fill:#FFFFFF,stroke:#778397,color:#1C2B43,rx:12,ry:12
```

### Runtime behavior

Cowabunga, runtime crew. Follow which process initiates each operation. The two
installed services roll through these paths:

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
   `Start`, or `Stop` on the `ncalrpc` endpoint `BfdWinService.Bgp.v2`. The client
   pins SYSTEM and the broker SID; the broker checks BFD through Authz without
   impersonation.
6. The broker invokes native Management Infrastructure (MI) against the local
   `PS_BgpPeer` provider for its configured target. Windows RRAS manages the BGP
   connection to the remote peer.

Telemetry vibe check: the status cache is, like, observational. Invalid,
unavailable, or stale telemetry does not request a BGP action or become a
fabricated BFD state. The provider worker remains independent of telemetry and
uses the broker's reduced SYSTEM token and configured COM/MI security.

## Service lifecycle

SCM starts each service independently. Only the broker depends on `RpcSs` for
native MI; neither service waits for its counterpart to report Running. The
broker's telemetry worker retries while BFD is unavailable.

### Lifecycle diagram (PNG)

[![Service lifecycle showing SCM startup order, concurrent telemetry fetching, stalled-worker quarantine, and administrative shutdown.](images/service-communication-lifecycle-v2-hardened.png)](images/service-communication-lifecycle-v2-hardened.png)

### Lifecycle diagram (Mermaid)

```mermaid
---
config:
  layout: elk
  look: classic
  theme: base
  fontFamily: Segoe UI, Arial, sans-serif
  themeVariables:
    fontSize: 15px
    primaryTextColor: '#1C2B43'
    lineColor: '#526987'
    clusterBkg: '#FFFFFF'
    edgeLabelBackground: '#FFFFFF'
  flowchart:
    wrappingWidth: 330
    padding: 16
    nodeSpacing: 26
    rankSpacing: 50
    curve: stepBefore
---
flowchart LR
    accTitle: Service lifecycle: startup, status fetching, and administrative shutdown
    accDescr: SCM starts BFD and the broker independently; only the broker depends on RpcSs. Each service validates and reduces its own token before accepting work. The status supervisor retries while BFD is unavailable and quarantines stalled telemetry while the provider continues. Shutdown preserves native ownership.
    %% Mirrors service-communication.drawio, page 2.

    lc_scm["<b>[E] Windows SCM</b><br/>RpcSs → broker; BFD starts separately<br/>Applies installed token policy"]:::external
    subgraph lc_broker["Broker service process"]
        direction TB
        lc_broker_init["<b>1. Verify broker; initialize provider</b><br/>SYSTEM + enabled broker service SID<br/>Retain SeChangeNotifyPrivilege<br/>Initialize COM / MI; load fixed target"]:::broker
        lc_broker_running["<b>2. Secure BGP RPC; report Running</b><br/>BFD-SID ACL and per-call Authz<br/>Deny runtime management"]:::broker
        lc_monitor["<b>3. Start status supervisor and worker</b><br/>Both are threads inside the broker<br/>Provider work remains independent"]:::broker
        lc_call["<b>Authenticated bind and status query</b><br/>BfdWinService.Local.v2 / BfdLocal 2.0<br/>Fixed BFD identity policy<br/>2 s bind / 2 s call / 8 s supervision"]:::gate
        lc_cache["<b>Maintain the checked telemetry cache</b><br/>Validate the whole reply and freshness<br/>Failed / invalid reply: clear and retry<br/>No fabricated BFD state"]:::cache
        lc_broker_stop["<b>Broker shutdown</b><br/>Join the supervisor; retain any unfinished<br/>native worker and its call storage"]:::note
        lc_quarantine["<b>Stuck worker: quarantine telemetry</b><br/>Retain native storage; log Error 301<br/>No new fetches until broker restart<br/>Provider continues; no BGP action"]:::gate
    end

    subgraph lc_bfd["BFD service | LocalService + restricted SID"]
        direction TB
        lc_bfd_start["<b>1. SCM starts BFD independently</b><br/>Advance StartPending checkpoints"]:::bfd
        lc_bfd_guard["<b>2. Verify and reduce the BFD token</b><br/>LocalService + enabled BFD service SID<br/>BFD SID + S-1-5-33 restricting entries<br/>Remove unused privileges"]:::gate
        lc_engine["<b>3. Create engine and status observer</b><br/>Initial immutable snapshot exists<br/>BGP control begins on the first Up"]:::bfd
        lc_listener["<b>4. Register the private RPC interface</b><br/>Deny management; protect endpoint<br/>Authorize each call; copy one snapshot<br/>No packet-loop queries or lock"]:::gate
        lc_bfd_stop["<b>BFD shutdown</b><br/>Close observer; announce AdminDown<br/>Release BFD-owned BGP Stop; finish action<br/>Unregister and drain the RPC interface"]:::note
        lc_bfd_running["<b>5. Report Running; run packet engine</b><br/>Lifecycle and BFD state are separate<br/>Publish changes and refresh snapshots"]:::bfd
    end

    lc_scm -->|"start broker"| lc_broker
    lc_broker_init -->|"initialized"| lc_broker_running
    lc_broker_running -->|"background"| lc_monitor
    lc_monitor -->|"supervise"| lc_cache
    lc_cache <-->|"request / result"| lc_call
    lc_call -->|"stalled"| lc_quarantine
    lc_scm -->|"start BFD"| lc_bfd
    lc_bfd_start -->|"validate"| lc_bfd_guard
    lc_bfd_guard -->|"reduced token"| lc_engine
    lc_engine -->|"observer"| lc_listener
    lc_listener -->|"ready"| lc_bfd_running
    lc_broker -->|"Session status / ncalrpc"| lc_bfd

    %% Invisible links align independent sections; they do not represent calls.
    lc_bfd_running ~~~ lc_bfd_stop
    lc_quarantine ~~~ lc_broker_stop

    classDef bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef gate fill:#FFF4D9,stroke:#B98521,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef cache fill:#EAF5EC,stroke:#558563,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef external fill:#F1F3F6,stroke:#778397,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef note fill:#FFFFFF,stroke:#B8C2D0,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    style lc_broker fill:#FFFFFF,stroke:#7957A2,color:#1C2B43,stroke-width:2px,rx:12,ry:12
    style lc_bfd fill:#FFFFFF,stroke:#3A69A6,color:#1C2B43,stroke-width:2px,rx:12,ry:12
```

### Startup and shutdown behavior

Keep the turtle team in formation through startup and cleanup. Either service
can start first; only `BfdBgpBroker` requires `RpcSs`. The broker
secures its BGP control RPC interface before reporting Running, then starts the
telemetry monitor and retries while BFD is unavailable. BFD gives RPC a read-only
observer before moving the engine to its packet worker. Neither SCM Running nor
RPC success implies a session is Up.

BFD closes its observer as soon as packet processing ends, before announcements
and BGP cleanup. After cleanup, it unregisters and drains its interface before
releasing the security descriptor. The broker stops its supervisor without
joining an unfinished native RPC worker. That single owned worker retains its
native call storage until completion or process exit; it is never forcibly
terminated or replaced repeatedly. A native ownership wipeout isn't an
acceptable cleanup strategy.

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

Donatello follows the immutable snapshot from engine publication to an RPC
worker, then through checked conversion into the broker cache. Queries never
ask the packet loop for work. The [status contract](rpc-session-status-design.md)
owns fields, cadence, freshness, recovery, and native lifetimes; use
[monitoring](monitoring.md) for installed-host queries.

## UDP inputs and outputs

Match the wire path before the packet crew kicks shell. The
[protocol reference](protocol.md) owns per-role ports, source policy, and
TTL/hop-limit checks. The [installation inventory](reference/installation.md#installed-firewall-rules)
lists the executable-specific firewall rules. Packet validation and kernel
firewall filtering are separate gates.

## BGP behavior

Turtle power follows engine state and the configured control policy. BGP control
runs only when `BgpPeerName` is configured for classical BFD or an S-BFD
initiator. Reflectors reject BGP control. Plain BFD starts no BGP worker and makes
no BGP control calls. Both services start independently even with BGP configured;
functional control calls require the broker to be available.

The packet engine owns state-driven actions. Read the [BGP action rules](bgp.md#verify-state-changes-and-actions)
for startup, failure, recovery, and administrative disablement. The broker's
telemetry cache never supplies these decisions.

The final RRAS-to-remote-peer link represents Windows-managed BGP behavior.
This repository invokes the local management provider; it does not implement
the BGP connection or configure its wire authentication. The actual RRAS
process token and deployed provider/channel ACLs require host inspection.

For implementation locations, see the [security source map](security.md#source-map).
