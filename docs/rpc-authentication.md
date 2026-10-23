# Local RPC authentication and authorization

Cowabunga, identity crew. Check the account and service together. This guide
explains the trust gates between BFD and the BGP broker. For native API settings,
ASCII call flows, and resource ownership, use [Local RPC security](security/local-rpc.md).
For the process topology, see [Service communication](service-communication.md).

## BGP control over local RPC

Both private interfaces use Windows local RPC (`ncalrpc`, called LRPC in native
constants), WINNT packet privacy, and shared service-specific authorization.
Deploy both executables from the same build, dude.

| Caller → server | Endpoint / interface | Operation |
| --- | --- | --- |
| Broker → BFD | `BfdWinService.Local.v2` / `BfdLocal 2.0` | Read-only `GetSessionStatusV1` |
| BFD → broker | `BfdWinService.Bgp.v2` / `BgpControl 2.0` | Fixed-target `Get`, `Start`, `Stop` |

Arrows show call initiation. Replies return on the same calls; neither interface
defines server-initiated RPC callbacks. A familiar endpoint name doesn't pass
the identity vibe check. Both account and service SID must match.

Each protected discretionary access control list (DACL) and identity guard
applies these requirements:

| Gate | Broker querying BFD telemetry | BFD controlling BGP |
| --- | --- | --- |
| Expected server | LocalService and BFD service SID | LocalSystem and broker service SID |
| Interface DACL | Broker service SID | BFD service SID |
| Exact caller user | LocalSystem | LocalService |
| Enabled, non-deny-only caller group | Broker service SID | BFD service SID |
| Restricted caller check | Also require broker SID in any nonempty restricting list | Also require BFD SID in any nonempty restricting list |

Authenticated users, local administrators, and domain administrators have no
direct access to either private interface. Neither DACL grants access to
Authenticated Users, Administrators, or the service account alone. Each caller
must satisfy both the exact account and enabled service-SID checks in the table.
Remote callers are rejected regardless of their credentials or administrator
membership. Host administrators remain trusted because they can reconfigure or
replace the services; RPC authorization does not contain a compromised host
administrator.

## Interface and process boundaries

The telemetry worker runs inside the existing broker process. Status queries
copy an immutable snapshot; they carry no configuration commands or keys and
never drive BGP actions. The BFD packet engine independently requests BGP
actions through the broker's bounded control queue. The broker invokes the
Windows provider for its protected configured target.

The diagram follows the telemetry direction. BGP control uses the same gates
with the identities reversed, including the restricted-caller check in the table.

## RPC authentication flow

The PNG and Mermaid diagrams mirror the authentication page in the
[draw.io source](service-communication.drawio). Use the PNG version in GitHub
mobile and select the image to open it at full size. Both versions group checks
by the broker client, Windows RPC, and BFD server. Blue represents BFD, purple
represents the broker, amber marks security gates, green marks checked replies,
and gray represents Windows.

### Authentication diagram (PNG)

[![RPC authentication showing broker checks of BFD identity, Windows RPC security gates, BFD authorization of the broker, and native resource cleanup.](images/service-communication-authentication-v2-hardened.png)](images/service-communication-authentication-v2-hardened.png)

### Authentication diagram (Mermaid)

```mermaid
---
config:
  layout: elk
  elk:
    cycleBreakingStrategy: MODEL_ORDER
    considerModelOrder: NODES_AND_EDGES
    forceNodeModelOrder: true
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
flowchart RL
    accTitle: RPC authentication: GetSessionStatusV1 on BfdWinService.Local.v2
    accDescr: The broker pins the actual BFD server account and service SID. Windows checks the interface ACL before the per-call callback. BFD checks call attributes and authenticated SYSTEM account plus enabled broker service SID without impersonation. Native storage remains owned until completion.
    %% Cross-process edges attach to boundaries to preserve process columns.
    %% Mirrors service-communication.drawio, page 3.

    subgraph auth_client["Broker RPC worker | SYSTEM + broker SID"]
        direction TB
        auth_token["<b>Verify the broker process token</b><br/>Exact SYSTEM user + enabled broker SID<br/>Require enabled SeChangeNotifyPrivilege"]:::broker
        auth_qos["<b>[F] Bind with the fixed BFD policy</b><br/>ncalrpc / WINNT / packet privacy<br/>QOS V5: LocalService AND BFD service SID<br/>Static / Identify / effective-only<br/>Create binding, bind, then query status"]:::gate
        auth_result["<b>Accept a complete, checked reply</b><br/>MIDL ranges → one Rust conversion<br/>Invalid reply: clear cache and retry<br/>Check freshness; never drive BGP"]:::cache
        auth_release["<b>Complete before releasing storage</b><br/>Cancel → complete → unbind → free<br/>Retain unresolved native ownership<br/>Quarantine a stalled telemetry worker"]:::broker
    end

    subgraph auth_windows["Windows RPC + kernel | logical security gates"]
        direction TB
        auth_pin["<b>[F] Authenticate the BFD server</b><br/>Evaluate QOS V5 server descriptor<br/>One conditional ACE requires both SIDs<br/>Endpoint name and flags alone do not prove identity"]:::gate
        auth_reject["<b>Any failed gate rejects the request</b><br/>ACL denial blocks callback and manager<br/>Attribute / Authz / SID failure denies<br/>Release any acquired Authz context"]:::note
        auth_ownership["<b>Trust and ownership limits</b><br/>Account + service SID identify the service<br/>Windows enforces ACL and token rules<br/>Identify + Authz(FALSE) keep BFD at LocalService"]:::external
    end

    subgraph auth_server["BFD server | LocalService + restricted BFD SID"]
        direction TB
        auth_start["<b>Verify BFD token; deny management</b><br/>LocalService + enabled BFD service SID<br/>Verify restricting entries before opening RPC"]:::bfd
        auth_acl["<b>[F] Register endpoint and interface</b><br/>Explicit broker-SID endpoint / interface ACLs<br/>WINNT; local-only / secure-only / no-cache<br/>Windows checks the interface ACL first"]:::gate
        auth_attributes["<b>[F] Check actual call attributes</b><br/>LRPC + local + WINNT + packet privacy<br/>Reject null sessions and query failures"]:::gate
        auth_authz["<b>[F] Authorize the authenticated caller</b><br/>RpcGetAuthorizationContextForClient(FALSE)<br/>Validate buffers before comparing SIDs<br/>Exact SYSTEM + enabled, non-deny-only broker SID<br/>If restricted: broker SID also in restricting list<br/>Release context; never impersonate"]:::gate
        auth_manager["<b>Manager repeats authorization</b><br/>Repeat attributes and Authz identity checks<br/>Four nonblocking admission permits<br/>Copy one immutable snapshot"]:::bfd
        auth_management["<b>Separate runtime management surface</b><br/>Deny enumeration, queries, and listener control<br/>Broker COM / MI policy stays independent"]:::note
    end


    auth_token -->|"broker credentials"| auth_qos
    auth_start -->|"register"| auth_acl
    auth_client -->|"bind / status"| auth_windows
    auth_windows -->|"server accepted"| auth_server
    auth_pin -->|"reject"| auth_reject
    auth_acl -->|"ACL passed"| auth_attributes
    auth_attributes -->|"attributes passed"| auth_authz
    auth_authz -->|"caller authorized"| auth_manager
    auth_server -->|"packet-private status reply"| auth_client
    auth_qos ~~~ auth_result
    auth_result -->|"cleanup"| auth_release

    %% Invisible links align independent sections; they do not represent calls.
    auth_reject ~~~ auth_ownership
    auth_manager ~~~ auth_management

    classDef bfd fill:#EAF2FF,stroke:#3A69A6,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef broker fill:#F0EAF8,stroke:#7957A2,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef gate fill:#FFF4D9,stroke:#B98521,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef cache fill:#EAF5EC,stroke:#558563,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef external fill:#F1F3F6,stroke:#778397,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    classDef note fill:#FFFFFF,stroke:#B8C2D0,color:#1C2B43,stroke-width:1.5px,rx:10,ry:10
    style auth_client fill:#FFFFFF,stroke:#7957A2,color:#1C2B43,stroke-width:2px,rx:12,ry:12
    style auth_windows fill:#FFFFFF,stroke:#778397,color:#1C2B43,stroke-width:2px,rx:12,ry:12
    style auth_server fill:#FFFFFF,stroke:#3A69A6,color:#1C2B43,stroke-width:2px,rx:12,ry:12
```

### Authentication diagram scope

For the matching ASCII diagrams, API responsibilities, and security assessment, see
[private local RPC authentication](security/local-rpc.md#broker-authenticates-bfd-telemetry).

The Windows RPC group represents runtime and kernel checks, not an additional
service process. Windows obtains identities from native tokens. The protocol
does not accept caller-supplied SIDs, process IDs, roles, passwords, or identity
metadata as authentication evidence.

## Implementation and verification

Use these references for implementation details and checks:

| Topic | Reference |
| --- | --- |
| Accounts, privileges, ACLs, and COM/MI policy | [Service isolation](security/service-isolation.md) |
| Fixed server identity policy, interface ACLs, and per-call Authz checks without impersonation | [Local RPC security](security/local-rpc.md#binding-and-server-setup) |
| Status fields, checked conversion, freshness, and native cancellation ownership | [RPC status contract](rpc-session-status-design.md) |
| BGP dispatch and provider cleanup budgets | [BGP provider](reference/bgp-provider.md) |
| Native rejection, recovery, and installed-token tests | [RPC verification](security/local-rpc.md#verify-the-implementation) |
| Installed-host authentication events | [Monitoring](monitoring.md#verify-broker-to-bfd-authentication) |
