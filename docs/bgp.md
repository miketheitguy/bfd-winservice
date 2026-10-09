# Control a Windows BGP peer

This guide is for Windows Server network administrators connecting Bidirectional Forwarding Detection (BFD) state changes to a configured Border Gateway Protocol (BGP) peer. Provision the BFD session using [Set up a BFD session](setup.md) first.

## Before you begin

The peer must already exist on a Windows Server with Remote Access/BGP configured.
Install the MSI: BGP control requires the installed service identities and is
unavailable with `--console`. Without `BgpPeerName`, no BGP control worker or
native MI query is started. The broker still starts as a service dependency and
answers the BFD service's read-only startup authorization probe.

## Service identities and authorization

`BfdWinService` handles UDP and the read-only COM interface as **LocalService**.
`BfdBgpBroker` runs as **LocalSystem** and hosts the native MI client. It has no
UDP listener or public COM class. RRAS management requires administrative access;
the broker retains that access while the packet-processing service does not.
See [Microsoft's router management requirements](https://learn.microsoft.com/en-us/windows/win32/rras/understanding-router-management-functions).

The local pipe `\\.\pipe\BfdWinService.Bgp.v1` accepts only the enabled
`NT SERVICE\BfdWinService` SID. For each request, the broker verifies that SID
and the LocalService account using an identification-only token, then reverts
before calling MI. Unrelated LocalService processes and administrator clients
are denied. Remote clients are rejected. The client checks the pipe server's
Windows-reported process ID against the broker's running SCM process ID; the
broker checks its own LocalSystem account and enabled service SID at startup.

Only Get, Start, and Stop operations are accepted, in fixed-size messages with
strictly increasing connection sequence numbers. Requests contain no peer name,
routing domain, path, command, or registry key. The broker loads its one allowed
target from the administrator-controlled Parameters key at startup. Pipe clients
cannot create another server instance or alter the pipe ACL. An occupied pipe
name causes broker startup to fail.

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
| Engine shutdown or fatal receive/wait error | Set AdminDown and queue Stop, even if BFD never reached Up |

A running BGP peer continues during the initial BFD handshake. A stopped peer waits for BFD to reach Up. Failed or ambiguous status checks never trigger a speculative Start. Init does not cancel a previously queued Stop.

At Up, an already running peer is claimed by the broker connection without
restarting it. A failed or abandoned connection that attempted a mutation causes
a Stop attempt; query-only startup probes never stop a peer on disconnect. If
that cleanup fails, the broker retries it before accepting another client. A
broker shutdown makes a final cleanup attempt and reports failure if it fails.

A dedicated worker handles provider calls while BFD continues running. Failed actions retry after one second unless replaced by a newer action or shutdown. At most a Stop/Start pair remains queued; Down/AdminDown discard queued Starts. An already issued call finishes before the next action runs.

SCM restarts a crashed broker after five seconds. An abrupt broker termination
cannot run its disconnect cleanup; once it restarts, the BFD worker reconciles
the latest requested action. A normal broker Stop does not trigger automatic restart.
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

Each Management Infrastructure (MI) operation requests a five-second timeout, which is **not a hard shutdown deadline** ([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Shutdown discards queued Starts, attempts pending Stops, and waits for the worker. A failed final Stop produces a nonzero exit status; final shutdown calls are not retried indefinitely.

<details>
<summary>Native provider details</summary>

The broker calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

At startup, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. English enum metadata maps `Stopped` to stopped and `Connected`/`Connecting`/`Disconnected` to started. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. Success requires MI completion success and Common Information Model (CIM) `ReturnValue=0`. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.

</details>

For event meanings and logging options, see [Logs and events](logging.md).
