# Control a Windows BGP peer

Cowabunga, BGP crew. Connect the state changes with care. Windows Server network
admins, let's connect Bidirectional Forwarding Detection (BFD) state changes to
your configured Border Gateway Protocol (BGP) peer. First, get the BFD session
dialed in with [Set up a BFD session](setup.md).

The BGP vibe check is separate from BFD readiness: `Up` requests a Start, but
provider errors can leave the BGP peer stopped. No victory lap yet, dude: verify
the peer and event logs.

Use [Configure the peer](#configure-the-peer) and [Verify state changes and
actions](#verify-state-changes-and-actions) for setup. For operational details,
see [Worker retries and broker recovery](#worker-retries-and-broker-recovery)
and [Service identities and authorization](#service-identities-and-authorization).

## Before you begin

Get the mission prerequisites lined up, turtle crew. Preflight check, buddy: the
peer must already exist on a Windows Server with Remote Access/BGP configured.
Install the MSI: BGP control requires the installed service identities and is
unavailable with `--console`. Without `BgpPeerName`, no BGP control worker or
native MI query is started. The broker still starts as a service dependency and
answers a read-only startup connection check when BGP control is configured.

BGP control works with classical BFD and S-BFD initiators. Reflectors don't
monitor peer state and reject `BgpPeerName`.

For classical multihop BFD, configure `Auth=meticulous-sha1`
and a valid matching key on both peers before enabling BGP control. Startup
rejects other authentication modes even with `MinTtl` configured. See
[Configure authentication](configuration.md#authentication). Single-hop BGP
without authentication warns that it relies on a trusted link.

The broker-to-BFD local RPC status query is a separate channel and runs
even without a BGP target. It authenticates the two services and reads published
session telemetry without performing a provider operation. See
[RPC authentication](rpc-authentication.md) and the
[runtime diagram](service-communication.md#runtime-flow) for both directions.

## Configure the peer

Channel Donatello and double-check the target configuration. Time to lock in.
Configure the existing peer in PowerShell as Administrator, then restart both
services to load the target.

### 1. Set the peer name

Set `BgpPeerName` to the **configured BGP peer name**, such as `Site17`. This is separate from the BFD peer IP address.

In PowerShell as Administrator, configure the peer name:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name BgpPeerName `
    -PropertyType String -Value 'BGP_PEER_NAME' -Force
```

Replace `BGP_PEER_NAME` with the existing peer's name before running the command.
PowerShell displays the `BgpPeerName` value.

### 2. Optional: Set the routing domain

For a named routing domain, set the optional value:

```powershell
New-ItemProperty -Path $parameters -Name BgpRoutingDomain `
    -PropertyType String -Value 'BGP_ROUTING_DOMAIN' -Force
```

Replace `BGP_ROUTING_DOMAIN` with the peer's existing routing domain. Omit this
value for the default domain; remove an earlier value when returning to the
default. Both names must contain a non-whitespace character.

### 3. Restart both services

Keep the turtle team in sync for the restart. After changing `BgpPeerName` or
`BgpRoutingDomain`, restart **both** services. Apply the configuration with a
coordinated restart:

```powershell
Stop-Service BfdWinService
Stop-Service BfdBgpBroker
Start-Service BfdWinService
```

Starting BFD starts its broker dependency. Do not stop the broker while BFD is
running except during coordinated maintenance.

The startup connection check validates the broker's identity and client
authorization without querying the provider. A missing or unreadable BGP peer
doesn't prevent BFD startup. Check the initial status-query log and
later broker results to confirm the configured target is usable.

## Verify state changes and actions

Bodacious results need both state and provider receipts. Check the receipts in
the BFD logs and BGP peer status. The worker applies these actions:

| BFD condition | BGP action |
| --- | --- |
| Startup and handshake before the first Up | Read status; leave BGP unchanged |
| Enter Up, including recovery | Check status; Start if the peer is stopped and the action is still current |
| Enter Down after BFD has been Up | Stop |
| Peer signals AdminDown, for example because its BFD service stopped | Never Stop; if BFD's latest action was a Stop, Start the peer |
| BFD service stop or OS shutdown | Never Stop; if BFD's latest action was a Stop, Start the peer; announce AdminDown for a Detection Time |
| Fatal (non-transient) receive/wait error that returns through engine cleanup | Enter local AdminDown; if BFD's latest action was a Stop, attempt a Start; no negotiated announcement grace |
| Crash or abrupt process termination | No cleanup action; the broker leaves BGP unchanged on disconnection |

A running BGP peer cruises through the initial BFD handshake. A stopped peer
waits for BFD to reach Up. Failed or ambiguous status checks never trigger a
speculative Start; guessing would be, like, majorly bogus. Init does not cancel
a previously queued Stop.

On the installed server, inspect BFD transitions and broker results:

```powershell
$eventFilter = @{
    LogName = 'BFD-Service/Operational'
    Id = 102, 103, 106, 110, 300, 301
}
Get-WinEvent -FilterHashtable $eventFilter -MaxEvents 30 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

Confirm event 102 when BFD reaches Up and broker event 300 for successful BGP
operations. An already running peer needs no mutation, so Up needn't produce a
Start result. Event 301 identifies broker authorization or provider failures.
For an end-to-end check in a maintenance window, test a peer that
starts stopped, a peer that starts running, BFD failure/recovery, and AdminDown.
Compare the actual peer state with the action table after each transition.

### Administrative disablement and failures

Ninja discipline means keeping an administrative stop distinct from a path
failure. Stopping BFD is administrative, not a path failure, so it never stops
BGP. Local AdminDown, set only when the service stops, never stops the peer.
Following
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
unchanged. A fatal receive/wait error that returns through engine cleanup also
sets local AdminDown and attempts this release, with no negotiated announcement
grace. A crash or abrupt termination skips that cleanup. The broker never
changes the peer merely because the RPC caller disconnects or because the broker stops.

## Worker retries and broker recovery

Keep the retry story totally tubular, including its limits. A dedicated worker
handles provider calls while BFD continues running. Failed actions retry after
one second unless replaced by a newer action or shutdown. At most a Stop/Start
pair remains queued; Down discards queued Starts. An already issued call
finishes before the next action runs, unless shutdown queues a newer final
action, which cancels it.

SCM restarts a crashed broker after five seconds; once it restarts, the BFD
worker reconciles the latest requested action. A normal broker Stop does not trigger automatic restart.
The broker supervises provider requests while Running as well as during Stop.
If a request, including schema lookup and cleanup, remains active for 20 seconds,
the watchdog exits the broker process and SCM recovery restarts it. The check
runs once per second; idle RPC waits do not count as stalled provider work.
If Stop was requested, the broker reports Stopped before exiting, preventing an
automatic restart.

The BFD worker checks its broker connection once per idle second and compares
the returned instance nonce to detect a restart. Recovery reapplies the latest
requested action without inventing an action before the session establishes.

BGP control uses authenticated `ncalrpc` with a two-second bind deadline and a
30-second total call budget. A cancellation signal interrupts an in-flight call;
the native bridge retains its state, event, binding, and reply storage until
completion. If ownership cannot be established, BFD fails closed instead of
releasing pending storage. The broker admits one control manager and at most
one queued provider request. Cancelled or expired queued requests are discarded.
An MI operation already running can still finish after its RPC caller cancels;
cancellation does not roll it back. MI calls remain synchronous and can delay
broker cleanup.

The BFD worker shares the engine's background log writer. The broker has its own
ETW/text diagnostic writer and does not open the BFD file log. Slow log output
does not delay provider calls; the [logging queue limits](logging.md#log-destinations)
apply to both processes.

### Provider timeouts and final cleanup

No pizza break until you understand the cleanup ownership, dude. Each Management
Infrastructure (MI) operation requests a five-second timeout, which is **not a
hard shutdown deadline**
([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)).

Shutdown never queues a Stop. The latest queued action still runs, such as a Start that withdraws BFD's Stop or one queued by a recent Up. When an action is queued, an older in-flight call is cancelled, and each call of the final action runs within 20 seconds, including any wait for the broker to finish the cancelled call. If the final action fails, it is recorded as event 3; because the stop was requested, the SCM exit code stays `0` and recovery doesn't restart BFD. Final calls are not retried indefinitely.

If the broker's cleanup still runs 60 seconds after a Stop request, or BFD's still runs 60 seconds plus its AdminDown announcement period, the service reports Stopped and ends its process, leaving the BGP peer unchanged.

### Windows shutdown

Turtle power includes an orderly exit during Windows shutdown. BFD accepts the
SCM preshutdown notification instead of the shutdown notification. During
Windows shutdown it announces AdminDown and completes any final BGP action while
the broker, which stops in the later shutdown phase, is still running. The
installer sets the service's preshutdown timeout to 125 seconds, covering the
maximum 60-second announcement period, 60 seconds of cleanup, and final logs.
`MaxShutdownAnnounceMs` defaults to 30 seconds and limits shutdown delay from a
peer advertising very long timers. Truncating a Detection Time produces a
warning because the peer might classify the administrative stop as a failure.

## Service identities and authorization

Check the service identities before anyone gets to kick shell. `BfdWinService`
handles UDP as **LocalService**. `BfdBgpBroker` runs as **LocalSystem** and
hosts the native Management Infrastructure (MI) client. BFD uses restricted
service SID type `3`; the broker keeps unrestricted type `1`. The BFD service
SID is an enabled normal group and a restricting SID, so the RPC interface's
explicit service-SID grant supports its restricted identity. The broker's
private COM initialization supports native MI and grants local execute rights
only to SYSTEM, with packet integrity. It sets strong unmarshaling and disables
COM exception handling before opening MI. Outgoing proxies default to
identification; the local MI destination explicitly requests impersonation so
Windows providers can use the broker's LocalSystem identity. RRAS management
requires administrative access; the broker retains that access while the
packet-processing service does not. See
[Microsoft's router management requirements](https://learn.microsoft.com/en-us/windows/win32/rras/understanding-router-management-functions).

The `BgpControl` version `1.0` interface at `BfdWinService.Bgp.v1` uses
`ncalrpc`. BFD initiates every call on this control interface; the broker
returns control results on those calls without RPC callbacks. The broker's
separate session-status calls run in the other direction, to BFD.

The control interface shares the telemetry interface's security implementation:
WINNT authentication, packet privacy, V5 server identity descriptors, static
identification credentials, and effective-only privileges. BFD pins LocalSystem
and the broker service SID together. The broker's protected interface DACL
admits the BFD service SID, and every call requires the exact LocalService user
and enabled, non-deny-only BFD service group. A restricted caller must also carry
the BFD SID in its restricting list. Authorization uses Authz without
impersonating the caller. Remote, anonymous, unrelated LocalService, and
ordinary administrator callers are rejected. Runtime management is denied.
See [RPC authentication](rpc-authentication.md#bgp-control-over-local-rpc).

Different permissions lane, dude: the MSI separately protects service control.
Authenticated users can query service status, while SYSTEM and elevated
Administrators can Start/Stop or reconfigure services. SCM permissions do not
authorize BGP RPC requests. Event/file log reads remain available under the
existing log permissions.

The MIDL contract accepts a connection check and only Get, Start, and Stop provider
operations. Requests contain no peer name, routing domain, path, command, or
registry key. The broker loads its allowed target from protected Parameters at
startup. The client authenticates the server account and service SID through
Windows RPC rather than a pipe PID/SCM comparison. A fixed endpoint collision
fails broker startup; there is no fallback. Without `BgpPeerName`, BFD makes no
BGP control connection check. The independent broker-to-BFD telemetry monitor still runs.

Native fixtures cover restricted-token authorization, server identity,
cancellation, and serialized dispatch. The MSI harness tests rejection of an
unrelated RPC caller and broker recovery. It does not mutate a live RRAS peer;
verify configured BGP behavior on your target server before the pizza party
victory lap.

<details>
<summary>Native provider details</summary>

The broker calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

At startup, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. English enum metadata maps `Stopped` to stopped and `Connected`/`Connecting`/`Disconnected` to started. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. Success requires MI completion success and Common Information Model (CIM) `ReturnValue=0`. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.

</details>

For event meanings and logging options, see [Logs and events](logging.md).
