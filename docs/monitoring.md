# Monitor service status and BFD events

This guide is for Windows operators checking service lifecycle and Bidirectional
Forwarding Detection (BFD) session state. Use the administrative COM endpoint for
a session snapshot, Windows service status for process lifecycle, and the
Operational event log for transitions over time.

## Query a session snapshot

Use a local, 64-bit PowerShell session with an elevated Administrator token or
run as SYSTEM. The MSI registers `BfdWinService.Status.1` for the COM endpoint
inside the `BfdWinService` service process. COM activation can start the configured
service if it is stopped. Standard users, unelevated Administrator tokens, and
remote callers cannot query the endpoint.

Create the endpoint and select the status properties you need:

```powershell
$bfd = New-Object -ComObject BfdWinService.Status.1
$snapshot = $bfd.GetSnapshot()
$snapshot | Select-Object PeerAddress, LocalState, RemoteState,
    DetectionTimeMicroseconds
```

An established session can produce this output (addresses and values are examples):

```text
PeerAddress LocalState RemoteState DetectionTimeMicroseconds
----------- ---------- ----------- -------------------------
192.0.2.11  Up         Up                             300000
```

`GetSnapshot()` returns one immutable object. The engine replaces its published
snapshot at most once per second; scheduling delays can extend that interval.
Repeat `GetSnapshot()` to obtain a later observation. Reading or retaining an
object does not hold a lock on the packet loop. A snapshot can lag protocol state,
and the `RemoteState` property preserves the peer's last accepted report after
detection expires. Use the timestamps and event log when diagnosing a failure.
`GetSnapshot()` returns `$null` if the engine has already stopped; a disconnected
COM proxy can instead raise an RPC error during service shutdown.

Inspect all properties with:

```powershell
$snapshot | Format-List *
```

The Automation object exposes strings, Boolean values, UInt32 identifiers/ports,
UInt64 counters/intervals, DateTime timestamps, and an array of address strings.
Absent or inapplicable fields return `$null`. Timestamps ending in `Utc` represent
UTC; COM's DateTime representation has no timezone metadata. Interval properties
ending in `Microseconds` use integer microseconds; divide by 1,000 for milliseconds.
Counters start with each engine instance and saturate at UInt64's maximum value.
Authentication keys and packet contents are not exposed.

The properties describe these observations:

| Properties | Meaning |
| --- | --- |
| `LocalAddress`, `PeerAddress`, `LastAcceptedSource` | Configured local/peer IP addresses and the last accepted packet's source address and UDP port. `PeerAddress` is absent for a reflector. |
| `InterfaceIndex`, `LocalSourcePort`, `ControlPort` | Configured interface index and actual socket ports. |
| `SessionType`, `TransportMode`, `Passive`, `PointToPoint` | Configured role, hop mode, and passive/point-to-point settings. |
| `AllowedPeers`, `MinTtl` | Configured reflector source allowlist and optional minimum hop limit. |
| `LocalDiscriminator`, `RemoteDiscriminator` | Local session/entity identifier and current learned or configured remote identifier. Classical expiry clears the learned identifier; an S-BFD initiator retains its configured target. |
| `LocalState`, `RemoteState`, `LocalDiagnostic`, `RemoteDiagnostic` | Local protocol state/diagnostic and last accepted remote state/diagnostic. `RemoteDiagnostic` retains the numeric wire value. |
| `Communicating` | Whether the stateful session has unexpired accepted communication. Absent for a stateless reflector. |
| `StateSinceUtc`, `LastUpUtc`, `LastDownUtc`, `LastDownReason` | Time entered the local state and last Up/Down transition details. |
| `LastValidReceiveUtc`, `LastSuccessfulSendUtc` | Last accepted receive and successful send. Rejected packets do not refresh valid-receive time. |
| `ConfiguredMinTxIntervalMicroseconds`, `ConfiguredMinRxIntervalMicroseconds`, `StartupTxIntervalMicroseconds` | Active configured transmit, receive, and startup timing. |
| `LocalDetectMultiplier`, `RemoteDetectMultiplier` | Active local and last accepted peer detection multipliers. |
| `RemoteMinTxIntervalMicroseconds`, `RemoteMinRxIntervalMicroseconds` | Last accepted peer timing parameters. |
| `EffectiveTxIntervalMicroseconds`, `DetectionTimeMicroseconds` | Effective session transmit and detection timing. Absent where a session does not apply. |
| `PeriodicTransmitEnabled`, `PollPending` | Whether periodic transmission is enabled and a Poll sequence is pending. |
| `PacketsReceivedAccepted`, `PacketsSentSuccessfully`, `PacketsRejected` | Accepted receives, successful sends, and rejected datagrams. |
| `AuthenticationFailures`, `MalformedPackets`, `ProtocolRejections`, `TransportValidationFailures` | Rejection categories, including authentication, packet shape, protocol rules, and transport/path checks. |
| `SocketErrors`, `DetectionTimeouts`, `UpTransitions`, `RepliesWithheld` | Socket failures, detection expiries, transitions to Up, and reflector replies withheld by policy. |
| `LastRejectionReason`, `LastRejectionUtc`, `LastSocketErrorCode`, `LastSocketErrorUtc` | Last rejection reason/time and socket error code/time. |
| `AuthenticationType`, `AuthenticationKeyId` | Configured authentication mode and non-secret key identifier. |
| `LastConfigurationReloadUtc`, `LastConfigurationReloadSucceeded` | Last configuration reload attempt time and outcome, if one occurred. |

For S-BFD reflectors, the local state describes entity availability. Peer session
state, negotiated timing, and detection multipliers are absent because the
reflector is stateless. Request/reply counters remain available.

The endpoint provides protocol observations only. Windows reports service
lifecycle separately. It does not expose `SnapshotAge`, `ReceiveAgeAtCapture`,
`PublishInterval`, `BgpControlEnabled`, `CapturedAtUtc`, or `SchemaVersion`.
It offers no configuration or BGP control methods. For access checks, see
[Administrative COM status access](security.md#administrative-com-status-access).

## Monitor lifecycle and state transitions

Use a PowerShell session on the installed host; these monitoring queries do not
require elevation. Query the service's lifecycle status with:

```powershell
Get-Service BfdWinService, BfdBgpBroker
```

`Running` means the engine started; it does not mean the BFD session reached `Up`.
Read recent local state-transition events with:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'BFD-Service/Operational'
    Id = 102, 103, 104, 106
} -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Event 102 reports `Up`, 103 reports `Down`, 104 reports `Init`, and 106 reports
`AdminDown`. Event 1 confirms engine startup. The event log is historical, can
contain records from an earlier service run, and can suppress repeated transitions
under load. A latest event is not a guaranteed current-state snapshot. See
[Logs and events](logging.md) for event payloads and logging limits.

The MSI applies protected Windows Service Control Manager (SCM) permissions to
both services:

| Operation | Allowed principals |
| --- | --- |
| Query service configuration/status, enumerate dependents, interrogate status, or read its ACL | Authenticated users, SYSTEM, and Administrators |
| Start/Stop, pause, change configuration, delete, change the ACL, or send custom service controls | SYSTEM and elevated Administrators |
| Read event/file logs | Non-administrators under the existing Event Log and filesystem permissions |
| Change BFD registry settings | SYSTEM and elevated Administrators; the BFD service SID has read access |

A service-status query returns Windows lifecycle state, such as `Running` or
`Stopped`. It does not return BFD protocol state, such as `Up` or `Down`.
Log-reading permissions are unchanged. The default installed log folder grants
Users read access and the BFD service SID Modify access; a custom log path uses
its administrator-provisioned filesystem permissions. The Operational channel
uses Windows Event Log permissions without a custom channel ACL.

## Broker communication

Border Gateway Protocol (BGP) requests pass through the authenticated service
pipe. The caller must
carry both the enabled BFD service SID and the LocalService identity; an ordinary
administrator process cannot submit broker requests. This service-to-service
permission is required for BGP control. See [Control a Windows BGP peer](bgp.md)
for the pipe protocol, broker identity checks, and native provider calls.
