# Monitor service status and BFD events

Cowabunga, monitoring crew. Check the evidence before the victory lap. Windows
operators, let's check the receipts for service lifecycle and Bidirectional
Forwarding Detection (BFD) session transitions. Use Windows service queries for
process lifecycle and the Operational event log for transitions over time.

Save the Cowabunga for the evidence, dude. `Running` alone doesn't earn an
Up-session flex: check the transition events and their timestamps before drawing
conclusions about peer health.

## Before you begin

Gather the host access needed for the ninja mission. Use a PowerShell session on
the installed host. Authenticated local users can query service lifecycle
without elevation. Event queries also require permission to read the Operational
channel under the host's Windows Event Log policy.

For access rights by operation, see [Access permissions](#access-permissions).

## Available monitoring interfaces

Turtle power starts with using the interface meant for the job. The BFD service
exposes private read-only session telemetry to the broker over mutually
authenticated local RPC. The broker uses an in-process worker and a validated
cache; there is no administrative RPC client or public status endpoint. See
[RPC session-status query](rpc-session-status-design.md) for fields and
freshness. Use the lifecycle and event queries here for operator monitoring. RPC
success authenticates the exchange but does not by itself establish a fresh
snapshot or an Up session.

## Monitor lifecycle and state transitions

Keep these observations in formation, turtle crew: query Windows lifecycle
and recorded BFD transitions separately.

### Query service lifecycle

Query the service's lifecycle status with:

```powershell
Get-Service BfdWinService, BfdBgpBroker
```

For BFD, `Running` means engine initialization completed; it does not mean the
BFD session reached `Up`.

### Read recent BFD transitions

Channel Donatello and read the event history carefully. Read recent local
state-transition events with:

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

## Verify broker-to-BFD authentication

Bodacious telemetry needs verified service identities. Like, hello: for the RPC
vibe check, use event messages to distinguish authenticated replies from
connection, validation, and worker failures.

### Query authentication events

On the installed host, query the broker's informational events:

```powershell
$since = (Get-Date).AddMinutes(-10)
Get-WinEvent -FilterHashtable @{
    LogName = 'BFD-Service/Operational'
    Id = 300
    StartTime = $since
} | Where-Object {
    $_.Message -like '*BFD local RPC*' -or
    $_.Message -like '*BFD session*'
} | Select-Object TimeCreated, Id, Message
```

`BFD local RPC mutual service identity verified` means an authenticated status
fetch returned a record that passed conversion. Event 300 also carries BGP
readiness/results, so the event ID alone is insufficient evidence. Success is
logged on first connection or recovery, not after every one-second query.

### Investigate RPC status failures

A missing reply is a bummer, dude. Choose the response that fits the message:

| Message | What to check or do |
| --- | --- |
| `BFD session status unavailable` | Check BFD startup and connectivity; completed failures retry automatically. |
| `BFD session telemetry stale` | Check BFD scheduling and query delays; stale telemetry is not a synthetic Down event. |
| `BFD status rejected` | Inspect the rejection category and matching binary versions; a clean rejection retries without a broker restart. |
| `BFD status worker stalled` | Investigate the stuck native call, then restart the broker through normal administration; telemetry remains quarantined until restart. |

Provider work continues independently of telemetry failures. For exact cache,
freshness, retry, and reporting rules, see the
[status contract](rpc-session-status-design.md#secure-response-to-invalid-data).

Query rejection and quarantine events on the installed host:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'BFD-Service/Operational'
    Id = 301
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Message -like '*BFD status rejected*' -or
    $_.Message -like '*BFD status worker stalled*'
} | Select-Object TimeCreated, Id, Message
```

When the errors keep rolling in, investigate mismatched binaries, BFD startup
errors, clock validity, and the record rejection category. Rejected replies
recover automatically; a stuck-worker quarantine requires investigation and a
restart through the normal service administration workflow. Do not broaden an
ACL or treat an old successful event as current telemetry. Old receipts don't
get a freshness glow-up, buddy. Matching executables, installed accounts,
service SIDs, and privilege policy remain required.

For packet communication and session readiness, use events 100–112 separately.
The private RPC endpoint needs no firewall rule or public client configuration.

## Access permissions

A ninja mission still needs the required access rights. Permissions check, no
cap: the MSI applies protected Windows Service Control Manager (SCM) permissions
to both services:

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

SCM permissions and private RPC permissions are separate, dude. Only the
authenticated BFD service identity can request BGP operations. For the complete
gate matrix, see [RPC authentication](rpc-authentication.md#bgp-control-over-local-rpc).
For peer setup and actions, use [Control a Windows BGP peer](bgp.md).
