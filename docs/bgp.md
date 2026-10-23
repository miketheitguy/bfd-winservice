# Control a Windows BGP peer

Cowabunga, Windows Server network admins. Use this guide to connect
Bidirectional Forwarding Detection (BFD) state changes to your configured
Border Gateway Protocol (BGP) peer. First, configure and verify BFD with
[Set up a BFD session](setup.md).

BFD `Up` triggers a peer-status check. The worker requests Start only if the
peer is stopped and the action is still current. Provider errors can leave BGP
stopped even when BFD is Up, so verify both peer status and event logs.

## Before you begin

Before enabling control, confirm that the peer exists on a Windows Server
with Remote Access/BGP configured.
Install the setup bundle: BGP control requires the installed service identities.
Without `BgpPeerName`, BFD starts no BGP control worker and makes no provider
queries. BFD and the broker start independently; enable both services when you
need BGP control or broker telemetry.

BGP control works with classical BFD and S-BFD initiators. Reflectors don't
monitor peer state and reject `BgpPeerName`.

For classical multihop BFD, configure `Auth=meticulous-sha1` or
`Auth=meticulous-md5` and a valid matching key on both peers before enabling BGP
control. Startup rejects other authentication modes even with `MinTtl` configured. See
[Configure authentication](configuration.md#authentication). Single-hop BGP
without authentication warns that it relies on a trusted link.

## Configure the peer

In **PowerShell as Administrator**, configure the existing peer and restart
both services to load the target. Use the same window for all three steps so
`$parameters` remains available.

### 1. Set the peer name

Set `BgpPeerName` to the **configured BGP peer name**, such as `Site17`.
This is separate from the BFD peer IP address.

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

After changing either BGP setting, restart **both** services:

```powershell
Stop-Service BfdWinService
Stop-Service BfdBgpBroker
Start-Service BfdBgpBroker
Start-Service BfdWinService
```

Either service can start first or run while the other is stopped. Starting one
doesn't start the other. Keep the broker running when BFD needs to control BGP;
pending failed actions retry when it becomes available.

BFD startup and the initial handshake send no BGP control requests. The first
BFD Up triggers a status query; check its result and subsequent broker events
to confirm the configured target is usable. Every functional RPC call checks
the broker's identity and authorizes BFD.

## Verify state changes and actions

Check both BFD events and BGP peer status against these actions:

| BFD condition | BGP action |
| --- | --- |
| Startup and handshake before the first Up | No BGP control calls; leave BGP unchanged |
| Enter Up, including recovery | Check status; Start if the peer is stopped and the action is still current |
| Enter Down after BFD has been Up | Stop |
| Peer signals AdminDown, for example because its BFD service stopped | Never Stop; if BFD's latest action was a Stop, Start the peer |
| BFD service stop or OS shutdown | Never Stop; if BFD's latest action was a Stop, Start the peer; announce AdminDown for a Detection Time |
| Fatal (non-transient) receive/wait error that returns through engine cleanup | Enter local AdminDown; if BFD's latest action was a Stop, attempt a Start; no negotiated announcement grace |
| Crash or abrupt process termination | No cleanup action; the broker leaves BGP unchanged on disconnection |

A running BGP peer cruises through the initial BFD handshake. A stopped peer
waits for BFD to reach Up. Failed or ambiguous status checks never trigger a
speculative Start. Init does not cancel a previously queued Stop.

On the installed server, inspect BFD transitions and broker results:

```powershell
$eventFilter = @{
    LogName = 'BFD-Service/Operational'
    Id = 102, 103, 106, 110, 300, 301, 302, 303
}
Get-WinEvent -FilterHashtable $eventFilter -MaxEvents 30 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

Confirm event 102 when BFD reaches Up and broker event 300 for successful BGP
operations. An already running peer needs no mutation, so Up needn't produce a
Start result. Event 301 identifies broker authorization or provider failures.
Event 302 identifies a failed BFD-side control request, including an unavailable
broker; event 303 marks successful control requests after a failure. These
client diagnostics remain available with file logging disabled. See
[BGP control events](logging.md#bgp-control-broker-and-rpc-telemetry-events)
for reporting limits and recovery semantics.
For an end-to-end check in a maintenance window, test a peer that
starts stopped, a peer that starts running, BFD failure/recovery, and AdminDown.
Compare the actual peer state with the action table after each transition.

### Administrative disablement and failures

Local AdminDown, including engine cleanup after a fatal transport error, never
stops BGP. Following
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

The BFD worker retries a failed action while packet processing continues. After
a broker crash, SCM restarts the broker. A pending failed action can then retry;
a completed action stays completed. The worker sends no idle probes and doesn't
detect broker restarts or replay completed actions. The next BFD transition
requests its normal action. An RPC disconnect alone doesn't stop BGP. A normal
administrator Stop doesn't trigger automatic restart.

Watch the peer state and events together after restoring a failed path. For
queue behavior, retry intervals, provider watchdogs, and native cancellation,
see the [BGP provider reference](reference/bgp-provider.md).

### Provider timeouts and final cleanup

Shutdown releases BFD's own Stop with Start when needed and finishes its latest
queued action. Final actions have bounded calls; a failure is recorded as
event 3. Provider work can outlive an RPC cancellation. See
[provider timeouts and final cleanup](reference/bgp-provider.md#provider-timeouts-and-final-cleanup)
for the budgets and ownership rules.

### Windows shutdown

BFD uses Windows preshutdown to announce `AdminDown` and complete its final
action before the broker stops. See the
[Windows shutdown sequence](reference/bgp-provider.md#windows-shutdown) for timing.

## Service identities and authorization

Turtle power keeps privileged management in the broker. The packet engine runs
as LocalService; the LocalSystem broker manages only the configured peer and
routing domain. BFD authenticates the broker and the broker authorizes BFD on
every control call. Requests cannot select another target.

For the identity gates, see [BGP control over local RPC](rpc-authentication.md#bgp-control-over-local-rpc).
For installed accounts, permissions, and COM security, see
[service isolation](security/service-isolation.md). SCM permission to administer
a service does not grant access to its private RPC interfaces.

Native fixtures and the installer harness don't mutate a live RRAS peer. Verify
actual withdrawal and recovery on your target server, dude. For event meanings, see
[Logs and events](logging.md).
