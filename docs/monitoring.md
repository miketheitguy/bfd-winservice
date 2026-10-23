# Monitor service status and BFD events

Cowabunga, monitoring crew. Use Windows service queries for process lifecycle
and the Operational log for Bidirectional Forwarding Detection (BFD)
transitions. Windows `Running` confirms startup, not an `Up` session.

## Before you begin

Use PowerShell on the installed host. Authenticated users can query service
lifecycle without elevation; reading events requires Operational-channel access.

For access rights by operation, see [Access permissions](#access-permissions).

## Available monitoring interfaces

Use the service and event queries on this page for operator monitoring. Session
telemetry is private to the broker; it has no public status endpoint or
administrative RPC client. Maintainers can find its fields and freshness rules
in the [RPC status contract](rpc-session-status-design.md).

## Monitor lifecycle and state transitions

### Query service lifecycle

Query the service's lifecycle status with:

```powershell
Get-Service BfdWinService, BfdBgpBroker
```

Each service starts independently. Start the broker as well as BFD when you need
telemetry or BGP control; a stopped counterpart
doesn't prevent the other service from reporting `Running`.

### Read recent BFD transitions

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

## Verify broker-to-BFD authentication

Use broker messages to distinguish authenticated status replies from connection,
validation, and worker failures.

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

Choose the response that fits the message:

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

For packet communication and session readiness, use events 100–113 separately.
The private RPC endpoint needs no firewall rule or public client configuration.

## Inspect the installed version

Read the BFD executable's Windows version metadata with:

```powershell
(Get-Item 'C:\Program Files\BfdWinService\bfd-winservice.exe').VersionInfo |
    Select-Object FileVersion, ProductVersion
```

Adjust the installation path if needed. Deploy the BFD engine and broker from
the same build.

## Access permissions

Authenticated users can query service status; SYSTEM and elevated administrators
can control services and change configuration. Log access follows the channel
and filesystem permissions. See the
[permission matrix](security/service-isolation.md#service-control-configuration-and-diagnostic-access)
for exact rights.

Service-control permissions don't authorize private RPC calls. See the
[RPC identity matrix](rpc-authentication.md#bgp-control-over-local-rpc) for
service authentication and the [BGP guide](bgp.md) for peer setup and actions.
