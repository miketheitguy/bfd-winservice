# Monitor service status and BFD events

This guide is for Windows operators checking service lifecycle and Bidirectional
Forwarding Detection (BFD) state transitions. Use Windows service status and the
Operational event log to monitor the installed services. Service status reports
process lifecycle; event records describe BFD transitions over time.

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
