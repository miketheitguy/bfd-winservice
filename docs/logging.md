# Logs and events

Cowabunga, log crew. Follow the events to the evidence. Windows operators and
admins, let's read the receipts. Use this guide to read Bidirectional Forwarding
Detection (BFD) events and configure log destinations. Use
[Set up a BFD session](setup.md) to provision a fresh installation.

Log vibe check, dude: event 1 means the engine started; event 102 means BFD
reached `Up`. Broker event 300 for mutual RPC authentication proves a separate
service identity check, even when BFD is `Down`.

## Log destinations

Pick where the turtle team gets its diagnostic receipts. In Windows Service
Control Manager (SCM) mode, the service uses Event Tracing for Windows (ETW) to
publish Operational events. In console mode, it writes to standard output
(STDOUT). The service supports these destinations:

| Destination | When used | Content |
| --- | --- | --- |
| `BFD-Service/Operational` | SCM mode, with manifest installed and channel enabled | Lifecycle, peer communication, local and remote BFD states, diagnostics, authentication failures, and broker readiness/provider/status messages |
| STDOUT | `--console` | BFD log messages; no ETW registration |
| `LogFilePath` | Either mode, with `LogToFile=1` | The same state and diagnostic event records, plus text messages, with ISO-8601 Coordinated Universal Time (UTC) timestamps |

### Console and packet text

Keep the noise mellow: ordinary send errors are logged at most once per second.
Generic discard reasons require `Verbose=1` and have a separate one-second
limit. These messages go to STDOUT or the configured file; they do not produce
Operational events.

If a STDOUT write fails, the shared writer disables further console writes and attempts one standard error (STDERR) diagnostic. File logging, BFD execution, and Border Gateway Protocol (BGP) control continue. A failed diagnostic write is ignored.

### Output queue and loss

Even a bodacious log pipeline has queue limits. One background writer handles
the text and ETW workload for the engine and its BGP worker. Slow output does
not delay BFD timers or Stop processing. The queue holds up to 256 records; when
it fills, additional records are dropped instead of delaying protocol execution.
Text messages are limited to 16 KiB on UTF-8 character boundaries. When output
resumes, the writer reports how many records were dropped to STDOUT or the
enabled file log. This diagnostic does not produce an Operational event.

### File rotation and buffering

Keep the log stash totally tubular and check rotation behavior. File output
rotates before a complete line would exceed 64 MiB. The writer renames the
active file to `LogFilePath` with `.1` appended, replacing the earlier backup,
and creates a new file. Each file stays within 64 MiB, including buffered bytes
and timestamps. Existing oversized files are rotated without extending them; the
logger does not shrink their existing contents.

If a reader denies delete sharing, rotation can fail. Lines that need rotation
are dropped from file output until rotation succeeds, with retries at most once
every 30 seconds as new lines arrive. If the rename succeeds but creating the
new file fails, file output stays paused and retries only creation; it never
appends to the backup. Operational ETW events and console output continue
independently. Rotation failures produce a diagnostic at each retry.

File output uses an 8 KiB buffer to group writes. While output is responsive,
the writer flushes pending bytes within 100 milliseconds, when the buffer
fills, before replacing the output file, and on normal shutdown. Library
callers can use `Logger::flush(timeout)` to wait for queued output and buffered
file bytes. In console mode, the writer flushes the file before writing to
STDOUT.

### Shutdown and timestamps

Ninja discipline includes knowing when an entry was written. Before reporting
Stopped, each service explicitly waits up to two seconds for queued output to
flush. Releasing the last logger then allows up to another 500 milliseconds for
the writer to drain; console shutdown uses this final-drop wait. If output
remains blocked, execution ends without waiting for that writer. Queued events
can be lost in this case; abrupt termination can also lose buffered file
entries. File timestamps record when the writer formats each entry. Slow output
can delay that timestamp relative to the underlying BFD state change, and
buffering can delay when the entry becomes visible.

## Read logs without service-control privileges

Non-administrators can read logs without permission to Start/Stop the services.
The MSI keeps Users read access to the default ProgramData log folder and grants
Modify access only to the BFD service SID, alongside SYSTEM/Administrator full
control. A custom `LogFilePath` uses the permissions provisioned for that location.
The Operational channel retains Windows Event Log access control; the manifest
does not install a custom channel ACL.

Authenticated users can also run `Get-Service` to query Windows lifecycle status.
`Running` does not mean the BFD session is `Up`. An elevated Administrator is
required to Start/Stop either installed service or change BFD settings; SYSTEM
retains Windows lifecycle access. See [Monitor service status and BFD
events](monitoring.md).

## Configure file logging

Get the log destination ready before pizza time. Time to lock in: run the
commands in **PowerShell as Administrator**. Provision the session and copy the
logging script using [Set up a BFD session](setup.md) first. For a custom
destination, review
[File paths, permissions, and timestamps](#file-paths-permissions-and-timestamps)
before enabling output.

<a id="1-provision-the-defaults"></a>

### 1. Optional: Provision the defaults

The MSI already provisions the log folder and default registry values. For a
loose-file console deployment, the [logging setup
script](../scripts/Initialize-Logging.ps1) creates
`C:\ProgramData\BfdWinService` and sets the defaults without creating or writing
`trace.log`. To initialize or deliberately reset those settings, run:

```powershell
$installDirectory = 'C:\Program Files\BfdWinService'
& (Join-Path $installDirectory 'Initialize-Logging.ps1')
```

Adjust `$installDirectory` if you installed the service elsewhere. The script
displays the folder and registry objects, replaces any existing `LogFilePath`,
disables file output, and prints this
settings summary:

```text
LogFilePath (REG_SZ): C:\ProgramData\BfdWinService\trace.log
LogToFile (REG_DWORD): 0
```

### 2. Enable file output

Dial in the output path and enable file logging:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name LogFilePath `
    -PropertyType String `
    -Value 'C:\ProgramData\BfdWinService\trace.log' -Force
New-ItemProperty -Path $parameters -Name LogToFile `
    -PropertyType DWord -Value 1 -Force
```

PowerShell displays the `LogFilePath` and `LogToFile` values. To use a different
location, replace the path with an absolute file path.

### 3. Verify file output

Start the service or console process, or restart it if already running, to load the settings. Inspect the default file after startup:

```powershell
Get-Content 'C:\ProgramData\BfdWinService\trace.log' -Tail 20
```

Timestamp vibe check, turtle crew: each line needs a UTC timestamp ending in
`Z`. Console output uses Unix milliseconds; redirecting STDOUT to a file
preserves that console format.

To disable file output, set `LogToFile` to DWORD `0` and restart execution. See the [configuration reference](configuration.md#logging-and-bgp) for the setting types and defaults.

## File paths, permissions, and timestamps

Give the log path the Donatello treatment: check access and timestamps. At
startup, the process reads `LogFilePath` and `LogToFile` from the Parameters
key. If `LogFilePath` is absent, it uses
`C:\ProgramData\BfdWinService\trace.log`.

The script and executable fallback use that literal path. The MSI instead
provisions the path under the machine's ProgramData location, which can differ.
The script doesn't install the MSI's service-specific folder ACLs.

If `LogToFile` is absent or `0`, file output is disabled: the logger does not open, create, or write the configured file, or create its parent folders. The other [log destinations](#log-destinations) remain available.

With `LogToFile=1`, the logger creates missing parent folders, including `C:\ProgramData\BfdWinService` for the default path, and appends to the file. Existing contents are preserved. The execution account needs permission to create the folders and write the file. Failure to create a folder or open the file fails startup.

The MSI grants Modify on its ProgramData log folder to
`NT SERVICE\BfdWinService`. The BFD service runs as LocalService; custom log
locations need a corresponding service SID grant. Grant access to the specific
service rather than the shared LocalService account. The broker writes its own
diagnostics through ETW and does not open `LogFilePath`.

The installed BFD token uses restricted service SID type `3`. Write checks use
both its ordinary token and restricting SIDs, so custom paths must grant the
BFD service SID the rights needed to create folders and write, rename, or replace
the active and rotated log files. An account-only LocalService write grant does
not satisfy this restriction. This leaves ordinary log-read ACLs unchanged.
The [MSI installation harness](../scripts/Test-MsiInstall.ps1) checks rendered ETW
events and file writes from the installed BFD token on a disposable runner.
Verify file output on your host after changing its location or ACLs.

Each file line starts with the current UTC time in `YYYY-MM-DDTHH:mm:ss.sssZ` format. The trailing `Z` identifies UTC, and the fractional seconds provide millisecond precision. Multiline messages include the same entry timestamp on every line. For example:

```text
2026-10-08T12:34:56.789Z service started mode=service
```

## Operational events

Cowabunga, event crew. Check the event meaning and severity together. In Event
Viewer, open **Applications and Services Logs → BFD-Service → Operational**. The
provider uses one Operational channel. State events and diagnostic events are
separate records, with independent severity levels.

### BGP broker and RPC telemetry events

Turtle power means telling provider results from telemetry results. The BGP
broker uses this channel for event **300** (Information: readiness and
management results) and **301** (Error: startup, authorization, or provider
failure). These messages include the configured peer and operation when
available.

Event 300 also records `BFD local RPC mutual service identity verified`,
`BFD session status unavailable`, and `BFD session telemetry stale`. The broker
normally queries once per second and logs success on connection/recovery.
Completed failures clear the cache and back off through 1, 2, 4, 8, 16, then
30 seconds; a valid reply resets polling. Error 301 `BFD status rejected` discards
the reply and retries. Ordinary failure and rejected-data reports are each
limited to once per minute, including across successful replies. Only Error 301
`BFD status worker stalled` quarantines telemetry until broker restart, stopping
further fetches while retaining the single worker's native storage. Provider
work continues without a BGP action from these query failures. See
[Verify broker-to-BFD authentication](monitoring.md#verify-broker-to-bfd-authentication).

The monitor has an eight-second wall-clock query budget and treats telemetry
older than two seconds as stale. Age includes the reported snapshot age, fetch
duration, and time since receipt; it doesn't use wall-clock subtraction.
Neither stale data nor quarantine replaces the BFD worker's state-driven BGP
actions.

### Lifecycle, communication, and state events

These events bring the receipts for execution, communication, and state changes:

| ID | Level | Meaning |
| --- | --- | --- |
| 1 | Information | Engine initialized and SCM Running reported |
| 2 | Information | Execution and cleanup ended; ExitCode 0 means success, 1 means failure |
| 3 | Error | Configuration, initialization, or execution failed |
| 4 | Warning | Weak but valid security configuration, a transient socket fault, or suppressed output (see [Service warnings](#service-warnings)) |
| 100 | Information | Valid peer communication started or resumed |
| 101 | Warning | No valid peer packet arrived within the detection interval |
| 102 | Information | Local session or reflector entity entered Up |
| 103 | Warning | Local session entered Down after a timeout or peer-reported Down/AdminDown |
| 104 | Information | Local session entered Init |
| 105 | Warning | Authentication verification failed |
| 106 | Information | Local session or reflector entity entered AdminDown |
| 110 | Information | Peer reported AdminDown |
| 111 | Warning | Peer reported Down |
| 112 | Information | Peer reported Init |
| 113 | Information | Peer reported Up |

Events 100–104 and 106 include endpoint addresses, discriminators, previous and
current local states, the local diagnostic, and transmit/detection intervals in
microseconds. Events 110–113 carry the peer's previous and current states and
diagnostic instead. State values follow
[RFC 5880 section 4.1](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.1):
`0` is AdminDown, `1` is Down, `2` is Init, and `3` is Up.

Event 101 retains the last known remote discriminator. Events 100/101 track
valid reception separately from Up: a peer sending Down or AdminDown packets
is still communicating. Loss of valid reception produces warning 101. If the
local session was Init or Up, detection expiry also produces warning 103 and
diagnostic warning 201.

The first accepted peer report and subsequent peer state changes produce
events 110–113, even when the local state doesn't change. Repeated identical
reports don't duplicate these events. Logging starts a fresh peer observation
after communication expires or the peer discriminator changes. Rejected
packets never update the recorded peer state or diagnostic.

Events 100–104, 110–113, and 201–208 share a budget of 32 records per second,
so a flapping peer or spoofed packets cannot flood the log. Records beyond the
budget are suppressed, and Warning event 4 reports the suppressed count at most
once a minute and at shutdown. Local AdminDown records (106 and 207) bypass this
event-rate budget. The output queue and delivery limits still apply.
Suppression affects logging only; BFD state and BGP actions are unchanged.

### Diagnostic events

A radical-looking event still needs its diagnostic context. The diagnostic names
follow
[RFC 5880 section 4.1](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.1).
The following severity levels are the service's logging policy:

| Diagnostic code | RFC meaning | Event ID | Level |
| --- | --- | --- | --- |
| 0 | No Diagnostic | No diagnostic event | None |
| 1 | Control Detection Time Expired | 201 | Warning |
| 2 | Echo Function Failed | 202 | Error |
| 3 | Neighbor Signaled Session Down | 203 | Warning |
| 4 | Forwarding Plane Reset | 204 | Error |
| 5 | Path Down | 205 | Error |
| 6 | Concatenated Path Down | 206 | Error |
| 7 | Administratively Down | 207 | Warning |
| 8 | Reverse Concatenated Path Down | 208 | Error |

Diagnostic events include the state-event fields and an `Origin` field:
`0` means Local session; `1` means Remote peer. States and diagnostics describe
that origin. `PreviousState` is the preceding state, or the reported state
when there is no preceding peer observation or only the diagnostic changed.

Entering local Down or AdminDown emits its nonzero diagnostic as a separate
event. For example, administrative shutdown emits Informational state event
106 and Warning diagnostic event 207. Up state events remain Informational.
Classical recovery retains the earlier local failure diagnostic in the Up
event payload, but doesn't re-emit that historical diagnostic as another
Warning or Error.

An accepted peer diagnostic produces an event on its first observation or
when its code changes, even if the local or peer state stays unchanged. A
peer's transition into Down or AdminDown also reports its nonzero diagnostic
again for that incident. Repeated identical reports are suppressed. Diagnostic
`0` and reserved codes `9`–`31` produce no standalone diagnostic event; state
and communication events still occur and can include those diagnostic values.

The diagnostic is the local reason: `0` initially, `1` when Init/Up detection
expires, `3` for a peer-signaled failure, and `7` for local shutdown or reflector
maintenance. Peer diagnostics don't replace this local reason. The service
reports peer codes 2, 4, 5, 6, and 8 without implementing local Echo or external
forwarding-plane/path notifications.
See [States and diagnostics](protocol.md#states-and-diagnostics)
for the transition rules.

### Service and console output

In SCM mode, the output worker submits each state or diagnostic record to ETW
and writes its text representation to the file when `LogToFile=1`. Both outputs
use the same event ID and severity. File entries include `event_id`, `level`,
and `scope=Local` or `scope=Remote`, followed by the state or diagnostic context.
Each entry starts with the writer's UTC timestamp.

With `--console`, the same event text goes to STDOUT and the enabled file.
Console mode doesn't register or write to ETW. With `LogToFile=0`, neither mode
opens or writes `LogFilePath`.

S-BFD initiators use these events for valid responses, Up, and detection expiry.
An AdminDown response keeps communication active while the target entity is in
maintenance. Reflectors log local entity transitions into AdminDown and Up,
and administrative shutdown, alongside lifecycle and authentication events.
They remain stateless for peers and don't emit per-peer communication, state,
or diagnostic events. A reflector's unused `PeerAddress` is the unspecified
address for its IP family. Live-setting reload errors appear in text logs and
leave the preceding settings active.

### Service warnings

Check these warnings before the turtle team rolls on. Heads up, buddy: Warning
event 4 carries a text message in these cases:

- At startup, for valid settings that let spoofed or replayed packets change
  BFD state, and where supported BGP: multihop without authentication, including
  with `MinTtl`; single-hop BGP without authentication;
  `simple-password`, `keyed-md5`, or `keyed-sha1` on a classical session; an
  S-BFD initiator without keyed authentication; or a reflector without
  `AllowedPeers`.
- When a transient network fault, such as an adapter reset, makes a socket
  operation fail. The engine retries with a backoff of 10–250 milliseconds while
  BFD timers continue, so an unusable path still expires the session. The warning
  repeats at most once a minute; recovery is noted in the text log.
- When session events or S-BFD replies are suppressed. A reflector answers at
  most 1,000 requests per second from any one source address, which bounds the
  traffic that spoofed requests can reflect toward a victim.
- When `MaxShutdownAnnounceMs` truncates the classical AdminDown announcement
  period at shutdown. The peer might detect a failure before learning that BFD
  was administratively stopped.

### Authentication events and provider identity

Event 105 includes the packet source address/port, configured authentication type/key ID, local discriminator, and rejection reason. It is limited to once per second per process, independently of verbose logging. Keys, passwords, digests, and packet payloads are omitted. Malformed headers, wrong-session discriminators, and invalid transport metadata are rejected before authentication verification and do not generate this event.

The provider GUID is `{8F2A4F61-4D6C-4F2F-9C3E-2B73AB4D62E1}`. The [manifest](../events/BFD-Service.man) follows Microsoft's [instrumentation manifest format](https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest). Lifecycle Mode `0` renders as `Windows service`; console startup text uses `mode=console`.

## Logging failures

Keep your shell together and inspect the failed output path. A logging failure
is, like, a major bummer. ETW registration failures are reported to STDERR
before the optional file log is open. ETW write failures go to the optional text
log. Neither stops BFD. For each queued state or diagnostic record, the worker
attempts ETW output before file output. An ETW failure doesn't suppress the file
entry; a file failure doesn't disable later ETW writes. Queue loss, blocked
output, and shutdown drain limits still apply to both destinations.

The logger starts before configuration is read. Its output worker registers the provider before processing queued events, allowing registry and file-log startup failures to emit event 3. Dispatcher/control-handler failures, registration failures, blocked output, queue overflow, or abrupt process termination can prevent lifecycle events. A successful ETW write does not guarantee Event Log delivery; install the manifest and keep the channel enabled.

For operator queries, see [Monitor service status and BFD events](monitoring.md).
