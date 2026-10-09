# Logs and events

This guide is for Windows administrators choosing a log destination and interpreting Bidirectional Forwarding Detection (BFD) events. Use [Set up a BFD session](setup.md) to provision a fresh installation.

## Log destinations

In Windows Service Control Manager (SCM) mode, the service uses Event Tracing for Windows (ETW) to publish Operational events. In console mode, it writes to standard output (STDOUT). The service supports these destinations:

| Destination | When used | Content |
| --- | --- | --- |
| `BFD-Service/Operational` | SCM mode, with manifest installed and channel enabled | Lifecycle, peer communication, BFD state, and authentication failures |
| STDOUT | `--console` | BFD log messages; no ETW registration |
| `LogFilePath` | Either mode, with `LogToFile=1` | Append log with ISO-8601 Coordinated Universal Time (UTC) timestamps, including additional diagnostics |

Ordinary send errors are logged at most once per second. Generic discard reasons require `Verbose=1` and have a separate one-second limit. These messages go to STDOUT or the configured file; they do not produce Operational events.

If a STDOUT write fails, the affected logger disables further console writes and attempts one standard error (STDERR) diagnostic. File logging, BFD execution, and Border Gateway Protocol (BGP) control continue. A failed diagnostic write is ignored.

## Configure file logging

Run the commands in **PowerShell as Administrator**. Provision the session and
copy the logging script using [Set up a BFD session](setup.md) first.

### 1. Provision the defaults

The [logging setup script](../scripts/Initialize-Logging.ps1) sets the default registry values and creates `C:\ProgramData\BfdWinService` without creating or writing `trace.log`. Run the script:

```powershell
$installDirectory = 'C:\Program Files\BfdWinService'
& (Join-Path $installDirectory 'Initialize-Logging.ps1')
```

Adjust `$installDirectory` if you installed the service elsewhere. The script
displays the folder and registry objects, disables file output, and prints this
settings summary:

```text
LogFilePath (REG_SZ): C:\ProgramData\BfdWinService\trace.log
LogToFile (REG_DWORD): 0
```

At startup, the process reads `LogFilePath` and `LogToFile` from the Parameters key. If `LogFilePath` is absent, it uses `C:\ProgramData\BfdWinService\trace.log`.

If `LogToFile` is absent or `0`, file output is disabled: the logger does not open, create, or write the configured file, or create its parent folders. The other [log destinations](#log-destinations) remain available.

With `LogToFile=1`, the logger creates missing parent folders, including `C:\ProgramData\BfdWinService` for the default path, and appends to the file. Existing contents are preserved. The execution account needs permission to create the folders and write the file. Failure to create a folder or open the file fails startup.

Each file line starts with the current UTC time in `YYYY-MM-DDTHH:mm:ss.sssZ` format. The trailing `Z` identifies UTC, and the fractional seconds provide millisecond precision. Multiline messages include the same entry timestamp on every line. For example:

```text
2026-10-08T12:34:56.789Z service started mode=service
```

### 2. Enable file output

Set the output path and enable file logging:

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

Confirm that each line has a UTC timestamp ending in `Z`. Console output uses Unix milliseconds; redirecting STDOUT to a file preserves that console format.

To disable file output, set `LogToFile` to DWORD `0` and restart execution. See the [configuration reference](configuration.md#logging-and-bgp) for the setting types and defaults.

## Operational events

In Event Viewer, open **Applications and Services Logs → BFD-Service → Operational**. The provider emits these events:

| ID | Level | Meaning |
| --- | --- | --- |
| 1 | Information | Engine initialized and SCM Running reported |
| 2 | Information | Execution and cleanup ended; ExitCode 0 means success, 1 means failure |
| 3 | Error | Configuration, initialization, or execution failed |
| 100 | Information | Valid peer communication started or resumed |
| 101 | Warning | No valid peer packet arrived within the detection interval |
| 102 | Information | BFD entered Up |
| 103 | Warning | BFD entered Down after a timeout or peer-reported Down/AdminDown |
| 104 | Information | BFD entered Init or local AdminDown |
| 105 | Warning | Authentication verification failed |

Events 100–104 include endpoint addresses, discriminators, previous/current states, diagnostic, and transmit/detection intervals in microseconds. Event 101 retains the last known remote discriminator. Events 100/101 track valid reception separately from Up: a peer sending Down or AdminDown packets is still communicating. Repeated packets or timeout checks do not duplicate these events.

The diagnostic is the local reason: `0` for startup or establishment,
`1` for detection expiry, `3` for peer-signaled Down/AdminDown, and `7`
for local shutdown. See [States and diagnostics](protocol.md#states-and-diagnostics)
for the transition rules.

S-BFD initiators use these events for valid responses, Up, and detection expiry.
An AdminDown response keeps communication active while the target entity is in
maintenance. Reflectors emit lifecycle and authentication events without
maintaining per-peer state. Live-setting reload errors appear in text logs and
leave the preceding settings active.

Event 105 includes the packet source address/port, configured authentication type/key ID, local discriminator, and rejection reason. It is limited to once per second per process, independently of verbose logging. Keys, passwords, digests, and packet payloads are omitted. Malformed headers, wrong-session discriminators, and invalid transport metadata are rejected before authentication verification and do not generate this event.

The provider GUID is `{8F2A4F61-4D6C-4F2F-9C3E-2B73AB4D62E1}`. The [manifest](../events/BFD-Service.man) follows Microsoft's [instrumentation manifest format](https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest). Lifecycle Mode `0` renders as `Windows service`; console startup text uses `mode=console`.

## Logging failures

ETW registration failures are reported to STDERR before the optional file log is open. ETW write failures go to the optional text log. Neither stops BFD.

The provider registers before configuration is read, allowing registry and file-log startup failures to emit event 3. Dispatcher/control-handler failures, registration failures, or abrupt process termination can prevent lifecycle events. A successful ETW write does not guarantee Event Log delivery; install the manifest and keep the channel enabled.
