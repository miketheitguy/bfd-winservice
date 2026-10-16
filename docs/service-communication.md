# Service communication

For developers and Windows administrators, this page maps the installed
services' network endpoints, private local RPC interface, and BGP actions. See
[Security, authentication, and build hardening](security.md) for identities,
permissions, and authentication boundaries.

The key receipt: the packet engine drives BGP actions. The broker's status cache
is for observation, and an SCM `Running` status doesn't mean the session is Up.

BFD hosts an authenticated local RPC interface for the broker. The broker calls
it from a worker thread inside its existing process. The existing BGP control
pipe and Windows provider COM/MI API retain their separate contracts.

The [editable draw.io source](service-communication.drawio) has three pages:
runtime boundaries, service lifecycle, and RPC authentication. Each exported
image embeds its editable page.

## Runtime flow

![Runtime: the LocalService BFD engine publishes immutable snapshots; the SYSTEM broker's in-process RPC worker reads session status over authenticated local RPC, validates it, and caches it. The separate BGP control pipe and Windows COM/MI provider path remain.](images/service-communication-runtime.png)

The two installed services use these paths:

1. `BfdWinService` receives and validates UDP packets and executes BFD/S-BFD
   timers as LocalService. Its mutable session has one engine owner.
2. The engine coalesces telemetry into an immutable `ArcSwap` snapshot, normally
   at most every 100 milliseconds, with a one-second unchanged refresh.
3. BFD's private `ncalrpc` interface, `BfdWinService.Local.v1`, exposes `Probe`
   and `GetSessionStatusV1`. An RPC worker authorizes the broker, loads one
   snapshot, and copies a fixed record without requesting packet-loop work.
4. The broker's RPC worker runs inside `bfd-bgp-broker.exe`. It authenticates BFD
   and converts the reply into checked Rust types before publishing its cache.
   There is no helper executable instance, stdout transport, or additional pipe.
5. When `BgpPeerName` is configured, BFD's separate BGP worker sends `Get`,
   `Start`, or `Stop` on `\\.\pipe\BfdWinService.Bgp.v1`. The client verifies the
   broker's SCM process ID; the broker checks the BFD client's Windows token.
6. The broker invokes native Management Infrastructure (MI) against the local
   `PS_BgpPeer` provider for its configured target. Windows RRAS manages the BGP
   connection to the remote peer.

The status cache is observational. Invalid, unavailable, or stale telemetry does
not request a BGP action or become a fabricated BFD state. The provider worker
continues under its existing token and COM/MI security.

## Service lifecycle

![Lifecycle: SCM starts the broker first; its status monitor runs after Running. BFD validates its token and registers RPC before Running. Shutdown closes observation before announcements and final BGP cleanup, then drains RPC. Broker shutdown does not wait on an unfinished native RPC worker.](images/service-communication-lifecycle.png)

SCM starts `RpcSs`, then `BfdBgpBroker`, then its dependent `BfdWinService`.
The broker reports Running before starting the monitor and retries while BFD
initializes. BFD gives RPC a read-only observer before moving the engine to its
packet worker. Neither SCM Running nor RPC success implies a session is Up.

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
privileges. The broker's provider process token and COM/MI policy are unchanged.
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

For implementation locations, see the [security source map](security.md#source-map).
