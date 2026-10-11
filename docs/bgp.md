# Control a Windows BGP peer

This guide is for Windows Server network administrators connecting Bidirectional Forwarding Detection (BFD) state changes to a configured Border Gateway Protocol (BGP) peer. Provision the BFD session using [Set up a BFD session](setup.md) first.

## Before you begin

The peer must already exist on a Windows Server with Remote Access/BGP configured.
Install the MSI: BGP control requires the installed service identities and is
unavailable with `--console`. Without `BgpPeerName`, no BGP control worker or
native MI query is started. The broker still starts as a service dependency and
answers a read-only startup authorization probe when BGP control is configured.

## Service identities and authorization

`BfdWinService` handles UDP as **LocalService**. `BfdBgpBroker` runs as
**LocalSystem** and hosts the native Management Infrastructure (MI) client.
The broker's private COM initialization supports native MI and grants local
execute rights only to SYSTEM and administrators, with packet integrity. It
excludes Authenticated Users and the generic Service group. Outgoing proxies
default to identification; the local MI destination explicitly requests
impersonation so Windows providers can use the broker's LocalSystem identity.
RRAS management requires administrative access; the broker retains that access
while the packet-processing service does not.
See [Microsoft's router management requirements](https://learn.microsoft.com/en-us/windows/win32/rras/understanding-router-management-functions).

The local pipe `\\.\pipe\BfdWinService.Bgp.v1` accepts only the enabled
`NT SERVICE\BfdWinService` SID. For each request, the broker verifies that SID
and the LocalService account using an identification-only token, then reverts
before calling MI. Unrelated LocalService processes and administrator clients
are denied. Remote clients are rejected. The client checks the pipe server's
Windows-reported process ID against the broker's running SCM process ID; the
broker checks its own LocalSystem account and enabled service SID at startup.

The MSI separately protects Windows service control: authenticated users can
query either service's status, while SYSTEM and elevated Administrators can
Start/Stop or reconfigure the services. This SCM permission does not authorize a
caller to submit BGP pipe requests. Event/file log reads remain available to
non-administrators under the existing log permissions.

Only Get, Start, and Stop operations are accepted, in fixed-size messages with
strictly increasing connection sequence numbers. Requests contain no peer name,
routing domain, path, command, or registry key. The broker loads its one allowed
target from the administrator-controlled Parameters key at startup. Pipe clients
cannot create another server instance or alter the pipe ACL. If another process
holds the pipe name, the broker stays Running, logs Error event 301 at most once a
minute, and retries each second; BFD with `BgpPeerName` rejects the impostor
through the process ID check and fails startup until the name is released. BFD
without `BgpPeerName` doesn't contact the broker.

BGP control works with classical BFD and S-BFD initiators. Reflectors don't
monitor peer state and reject `BgpPeerName`.

## Configure the peer

Set `BgpPeerName` to the **configured BGP peer name**, such as `Site17`. This is separate from the BFD peer IP address. Set `BgpRoutingDomain` for a named domain.

In PowerShell as Administrator, configure the peer name:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name BgpPeerName `
    -PropertyType String -Value 'BGP_PEER_NAME' -Force
```

Replace `BGP_PEER_NAME` with the existing peer's name before running the command.
PowerShell displays the `BgpPeerName` value. Restart **both** services after
changing `BgpPeerName` or `BgpRoutingDomain`:

```powershell
Stop-Service BfdWinService
Stop-Service BfdBgpBroker
Start-Service BfdWinService
```

Starting BFD starts its broker dependency. Do not stop the broker while BFD is
running except during coordinated maintenance.

## Verify state changes and actions

Watch the BFD logs and BGP peer status. The worker applies these actions:

| BFD condition | BGP action |
| --- | --- |
| Startup and handshake before the first Up | Read status; leave BGP unchanged |
| Enter Up, including recovery | Check status; Start if the peer is stopped and the action is still current |
| Enter Down after BFD has been Up | Stop |
| Peer signals AdminDown, for example because its BFD service stopped | Never Stop; if BFD's latest action was a Stop, Start the peer |
| BFD service stop or OS shutdown | Never Stop; if BFD's latest action was a Stop, Start the peer; announce AdminDown for a Detection Time |
| Fatal (non-transient) receive/wait error or crash | Leave BGP unchanged |

A running BGP peer continues during the initial BFD handshake. A stopped peer waits for BFD to reach Up. Failed or ambiguous status checks never trigger a speculative Start. Init does not cancel a previously queued Stop.

Stopping BFD is administrative, not a path failure, so it never stops BGP. Local
AdminDown, set only when the service stops, never stops the peer. Following
[RFC 5882 section 3.2](https://www.rfc-editor.org/rfc/rfc5882.html#section-3.2),
a session that goes Down because the peer signalled AdminDown also leaves BGP
running, so stopping BFD at either end of the session keeps BGP running. BGP
relies on its own hold timer until BFD returns; reaching Up again finds the peer
running and leaves it unchanged. An S-BFD reflector in maintenance is treated
the same way.

[RFC 5882 section 4.1](https://www.rfc-editor.org/rfc/rfc5882.html#section-4.1)
requires that BGP adjacencies be allowed while BFD is administratively disabled
at either end. This service blocks an adjacency by stopping the peer after a
detected failure. So when the local service stops, or the peer reports AdminDown,
the worker withdraws its own Stop: if its latest action was a Stop, it starts the
peer. A peer that BFD never stopped, for example one an operator stopped, is left
unchanged. A failure or crash closes the broker connection without an
administrative signal; the broker never changes the peer on disconnection or on
its own shutdown.

A dedicated worker handles provider calls while BFD continues running. Failed actions retry after one second unless replaced by a newer action or shutdown. At most a Stop/Start pair remains queued; Down discards queued Starts. An already issued call finishes before the next action runs, unless shutdown queues a newer final action, which cancels it.

SCM restarts a crashed broker after five seconds; once it restarts, the BFD
worker reconciles the latest requested action. A normal broker Stop does not trigger automatic restart.
The broker supervises provider requests while Running as well as during Stop.
If a request, including schema lookup and cleanup, remains active for 20 seconds,
the watchdog exits the broker process and SCM recovery restarts it. The check
runs once per second; idle pipe waits do not count as stalled provider work.
If Stop was requested, the broker reports Stopped before exiting, preventing an
automatic restart. A client that disconnects before pipe acceptance is discarded
without stopping the broker.
The BFD worker checks the connection once per idle second and reconnects after
broker failure, reapplying the latest requested action. It does not invent an
action before the session first establishes. The broker uses one client
connection at a time. Its response I/O has a 30-second timeout and observes SCM
Stop requests; pending native I/O is cancelled and drained before releasing its
buffers. MI calls remain synchronous and can delay broker cleanup.

The BFD worker shares the engine's background log writer. The broker has its own
ETW/text diagnostic writer and does not open the BFD file log. Slow log output
does not delay provider calls; the [logging queue limits](logging.md#log-destinations)
apply to both processes.

Each Management Infrastructure (MI) operation requests a five-second timeout, which is **not a hard shutdown deadline** ([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Shutdown never queues a Stop. The latest queued action still runs, such as a Start that withdraws BFD's Stop or one queued by a recent Up. When an action is queued, an older in-flight call is cancelled, and each call of the final action runs within 20 seconds, including any wait for the broker to finish the cancelled call. If the final action fails, it is recorded as event 3; because the stop was requested, the SCM exit code stays `0` and recovery doesn't restart BFD. Final calls are not retried indefinitely. If the broker's cleanup still runs 60 seconds after a Stop request, or BFD's still runs 60 seconds plus its AdminDown announcement period, the service reports Stopped and ends its process, leaving the BGP peer unchanged.

BFD accepts the SCM preshutdown notification instead of the shutdown notification.
During Windows shutdown it announces AdminDown and completes any final BGP action
while the broker, which stops in the later shutdown phase, is still running.
The installer sets the service's preshutdown timeout to 125 seconds, covering
the maximum 60-second announcement period, 60 seconds of cleanup, and final
logs. `MaxShutdownAnnounceMs` defaults to 30 seconds and limits shutdown delay
from a peer advertising very long timers. Truncating a Detection Time produces
a warning because the peer might classify the administrative stop as a failure.

<details>
<summary>Native provider details</summary>

The broker calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

At startup, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. English enum metadata maps `Stopped` to stopped and `Connected`/`Connecting`/`Disconnected` to started. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. Success requires MI completion success and Common Information Model (CIM) `ReturnValue=0`. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.

</details>

For event meanings and logging options, see [Logs and events](logging.md).
