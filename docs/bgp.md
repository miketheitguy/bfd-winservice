# Control a Windows BGP peer

This guide is for Windows Server network administrators connecting Bidirectional Forwarding Detection (BFD) state changes to a configured Border Gateway Protocol (BGP) peer. Provision the BFD session using [Set up a BFD session](setup.md) first.

## Before you begin

The peer must already exist on a Windows Server with Remote Access/BGP configured. The execution account needs permission to manage it. Without `BgpPeerName`, no BGP worker or query is started.

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
PowerShell displays the `BgpPeerName` value. Restart execution to apply the
setting. Control works in both console mode and Windows Service Control Manager
(SCM) mode.

## Verify state changes and actions

Watch the BFD logs and BGP peer status. The worker applies these actions:

| BFD condition | BGP action |
| --- | --- |
| Startup and handshake before the first Up | Read status; leave BGP unchanged |
| Enter Up, including recovery | Check status; Start if the peer is stopped and the action is still current |
| Enter Down after BFD has been Up | Stop |
| Engine shutdown, Ctrl+C, or fatal receive/wait error | Set AdminDown and queue Stop, even if BFD never reached Up |

A running BGP peer continues during the initial BFD handshake. A stopped peer waits for BFD to reach Up. Failed or ambiguous status checks never trigger a speculative Start. Init does not cancel a previously queued Stop.

A dedicated worker handles provider calls while BFD continues running. Failed actions retry after one second unless replaced by a newer action or shutdown. At most a Stop/Start pair remains queued; Down/AdminDown discard queued Starts. An already issued call finishes before the next action runs.

The BGP worker shares the engine's background log writer. Slow log output does
not delay provider calls; the [logging queue limits](logging.md#log-destinations)
apply to both sources.

Each Management Infrastructure (MI) operation requests a five-second timeout, which is **not a hard shutdown deadline** ([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Shutdown discards queued Starts, attempts pending Stops, and waits for the worker. A failed final Stop produces a nonzero exit status; final shutdown calls are not retried indefinitely.

<details>
<summary>Native provider details</summary>

The client calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

At startup, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. English enum metadata maps `Stopped` to stopped and `Connected`/`Connecting`/`Disconnected` to started. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. Success requires MI completion success and Common Information Model (CIM) `ReturnValue=0`. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.

</details>

For event meanings and logging options, see [Logs and events](logging.md).
