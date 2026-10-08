# BFD Windows service

Monitor a remote peer with Bidirectional Forwarding Detection (BFD) over IPv4 or IPv6. Run one configured session as a Windows service or in a console. Optionally use BFD state changes to stop and start a local Windows BGP peer.

| Name | Value |
| --- | --- |
| Windows service | `BfdWinService` |
| Event provider | `BFD-Service` |
| Event Log channel | `BFD-Service/Operational` |

Both execution modes read configuration from the registry. `--console` runs in the foreground and writes events to STDOUT; `--help` and `--version` are also available.

- [Build](#build)
- [Run in a console](#run-in-a-console)
- [Install and run as a service](#install-and-run-as-a-service)
- [Configuration reference](#configuration-reference)
- [Logs and events](#logs-and-events)
- [Optional BGP control](#optional-bgp-control)
- [Network and protocol behavior](#network-and-protocol-behavior)
- [Development and testing](#development-and-testing)

## Build

You need:

- Windows 10 or later, or a corresponding Windows Server release.
- Rust with a `windows-msvc` target.
- Visual Studio's **Desktop development with C++** workload, including the MSVC toolchain and Windows SDK.

From the repository root:

```powershell
cargo build --release
.\target\release\bfd-winservice.exe --help
```

The executable is `target\release\bfd-winservice.exe`. Its ETW metadata and English messages are embedded during the build using the SDK's `mc.exe` and `rc.exe`.

Use Developer PowerShell if the MSVC linker is unavailable on `PATH`. The build finds the manifest tools on `PATH` or in the installed Windows 10/11 SDK. For a custom SDK location, set `BFD_MC_PATH` and `BFD_RC_PATH` to the absolute tool paths.

## Run in a console

### 1. Configure the session

Open **PowerShell as Administrator** to write the registry settings. Replace the example addresses and interface index with your own. Find the interface index with:

```powershell
Get-NetIPInterface | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily
```

The default single-hop session needs `Local`, `Peer`, and `InterfaceIndex`. This example also sets the default log file path and disables file output:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-Item -Path $parameters -Force | Out-Null
New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '192.0.2.10' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '192.0.2.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name InterfaceIndex -PropertyType DWord -Value 12 -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value 'C:\ProgramData\BfdWinService\trace.log' -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 0 -Force | Out-Null
```

Configure the remote peer separately with the local and peer addresses reversed. BFD has no peer discovery. Both addresses must be distinct unicast IP literals of the same address family.

For SCM execution, use the [service setup](#install-and-run-as-a-service) below, which creates the service before provisioning its settings.

### 2. Start and stop

```powershell
.\target\release\bfd-winservice.exe --console
```

Messages, including configuration failures, go to **STDOUT**. Console mode does not register or write the ETW provider. To save the output:

```powershell
.\target\release\bfd-winservice.exe --console > .\bfd-console.log
```

Press **Ctrl+C** to stop. The engine sets AdminDown, attempts one shutdown packet when transmission is permitted, and waits for any configured BGP cleanup.

Settings are read once at startup. Stop the process, edit the registry, and restart to apply changes.

## Install and run as a service

Use **PowerShell as Administrator**. Keep the executable at a permanent installation path. The commands below use the build output and the default log file path; adjust `$exe` and `$manifest` if you deploy the files elsewhere.

### 1. Create the service and configure it

Replace the example addresses and interface index before running these commands:

```powershell
$exe = (Resolve-Path .\target\release\bfd-winservice.exe).Path
$manifest = (Resolve-Path .\events\BFD-Service.man).Path
$binaryPath = '"' + $exe + '"'
$log = 'C:\ProgramData\BfdWinService\trace.log'

New-Service -Name BfdWinService -BinaryPathName $binaryPath -DisplayName 'BFD Windows Service' -StartupType Manual

$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-Item -Path $parameters -Force | Out-Null
New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '192.0.2.10' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '192.0.2.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name InterfaceIndex -PropertyType DWord -Value 12 -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value $log -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 0 -Force | Out-Null
```

The service's executable path contains only the quoted path to the binary. Configure all session settings through the Parameters registry values.

File output is disabled in this example. To enable it, see [file logging](#file-logging).

### 2. Register the Operational log

Register the manifest once on each target machine, before starting the service:

```powershell
wevtutil.exe im $manifest "/rf:$exe" "/mf:$exe"
if ($LASTEXITCODE -ne 0) { throw 'BFD-Service manifest registration failed' }
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

Use the **final installed executable path**: Event Viewer loads messages and metadata from it. The manifest can come from the repository or a deployed copy. Building or running the binary does not install the manifest.

### 3. Start, inspect, and stop

```powershell
Start-Service BfdWinService
Get-Service BfdWinService
Get-WinEvent -FilterHashtable @{ LogName = 'BFD-Service/Operational' } -MaxEvents 20 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
Stop-Service BfdWinService
```

SCM **Running** means configuration is valid, sockets are open, and any configured BGP worker has started. BFD reaches **Up** separately; the initial BGP status query may also still be pending.

Configuration, file-log, and engine failures report a nonzero SCM service-specific exit status. Stop and Shutdown immediately report StopPending, with advancing checkpoints while cleanup runs. Shutdown attempts one AdminDown packet when the session's active/passive role permits, then waits for BGP cleanup.

### Remove the service and manifest

After stopping the service, resolve the installed manifest path and remove its registration:

```powershell
$manifest = (Resolve-Path .\events\BFD-Service.man).Path
wevtutil.exe um $manifest
if ($LASTEXITCODE -ne 0) { throw 'BFD-Service manifest removal failed' }
sc.exe delete BfdWinService
```

Manifest registration and removal use Microsoft's [wevtutil commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

## Configuration reference

Both console and SCM execution read:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters
```

The program reads this key without creating or modifying it. Missing optional values use defaults. Missing required values, incorrect types, or invalid combinations fail startup and identify the affected setting.

- **Strings:** `REG_SZ`. `REG_EXPAND_SZ` and environment-variable expansion are unsupported.
- **Numbers and flags:** `REG_DWORD`. Boolean flags must be `0` or `1`.
- **Apply changes:** stop execution, edit the registry, and restart to reload settings.

Types are enforced through [RegGetValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew).

### Addresses and transport

Use `Multihop` to select the transport. If you omit this value or set it to `0`,
the service uses single-hop. Set it to `1` for multihop. The following values
configure the addresses and transport:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `Local`, `Peer` | `REG_SZ` | Required | Distinct unicast IPv4 or IPv6 literals of the same family |
| `Multihop` | `REG_DWORD` | `0` | `0` = single-hop; `1` = multihop |
| `InterfaceIndex` | `REG_DWORD` | Required for single-hop or link-local IPv6 | Nonzero incoming/outgoing interface index |
| `PointToPoint` | `REG_DWORD` | `0` | Single-hop only: accept peer source-address changes on the configured interface |
| `SourcePort` | `REG_DWORD` | Random available port | Stable session UDP source port, 49152–65535 |
| `Discriminator` | `REG_DWORD` | Random nonzero value | Local session identifier |
| `Passive` | `REG_DWORD` | `0` | Multihop only: wait for a valid peer packet before sending |
| `MinTtl` | `REG_DWORD` | No multihop threshold | Multihop only: minimum received TTL/hop limit, 1–255 |

`Multihop` must be a `REG_DWORD` with value `0` or `1`. Any other value or
registry type fails startup.

IPv6 addresses must be literals such as `2001:db8::10`. Link-local addresses require `InterfaceIndex`; do not add a `%scope` suffix.

With `PointToPoint=1`, outgoing packets still go to the configured `Peer`. Incoming packets must pass the destination, interface, TTL, source-port, discriminator, and authentication checks.

### Timing

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `MinTxUs` | `REG_DWORD` | `300000` | Desired transmit interval while Up, 1–4294967295 microseconds |
| `MinRxUs` | `REG_DWORD` | `300000` | Required receive interval, 1–4294967295 microseconds |
| `StartupTxUs` | `REG_DWORD` | `1000000` | Desired transmit interval outside Up; at least one second, clamped to `MinTxUs` |
| `DetectMult` | `REG_DWORD` | `3` | Advertised detection multiplier, 1–255 |

Intervals are **microseconds** before jitter:

```text
Transmit interval = max(local desired TX, peer required RX)
Detection time    = peer multiplier × max(local required RX, peer desired TX)
```

Periodic transmit intervals are randomly reduced by 0–25%, or 10–25% when the local multiplier is 1. With matching 300000-microsecond intervals and multiplier 3, detection time is 900 ms. Windows scheduling adds latency; the service does not guarantee microsecond timing.

### Authentication

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `Auth` | `REG_SZ` | `none` | `none`, `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, or `meticulous-sha1` |
| `AuthKeyId` | `REG_DWORD` | `0` | Key ID, 0–255 |
| `AuthKey` | `REG_SZ` | None | ASCII key |
| `AuthKeyHex` | `REG_SZ` | None | Hexadecimal encoding of a binary key |

Configure the same authentication type, key ID, and key at both ends. Set exactly one of `AuthKey` and `AuthKeyHex` when authentication is enabled. Password/MD5 keys are 1–16 bytes; SHA1 keys are 1–20 bytes. One key is active at a time.

For example, after setting `Local` and `Peer`, configure an authenticated multihop session:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '198.51.100.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Multihop `
    -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $parameters -Name Auth -PropertyType String -Value 'meticulous-sha1' -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKeyId -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKey -PropertyType String -Value 'replace-this-key' -Force | Out-Null
```

Unauthenticated packets cannot establish an authenticated session, refresh its detection timer, or trigger a reply. All outgoing packets use the configured authentication. Keyed modes check digests and sequence windows, including wraparound and restart resynchronization. Authentication failures are logged regardless of `Verbose`; see [event 105](#operational-events).

These algorithms support RFC 5880 interoperability. The RFC discourages MD5, and RFC 5883 recommends cryptographic authentication for multihop. Registry key contents are unencrypted: restrict Parameters access to administrators and accounts that need it, including the service account. Authentication keys never appear in logs or configuration errors.

### Logging and BGP

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `LogFilePath` | `REG_SZ` | `C:\ProgramData\BfdWinService\trace.log` | Append log path; use an absolute path under SCM |
| `LogToFile` | `REG_DWORD` | `0` | `0` = disable file output; `1` = enable file output |
| `Verbose` | `REG_DWORD` | `0` | Log generic packet discard reasons, at most once per second |
| `BgpPeerName` | `REG_SZ` | None | Enable control of this configured Windows BGP peer |
| `BgpRoutingDomain` | `REG_SZ` | Default routing domain | Optional domain; requires `BgpPeerName` |

## Logs and events

| Destination | When used | Content |
| --- | --- | --- |
| `BFD-Service/Operational` | SCM mode, with manifest installed and channel enabled | Lifecycle, peer communication, BFD state, and authentication failures |
| STDOUT | `--console` | BFD log messages; no ETW registration |
| `LogFilePath` | Either mode, with `LogToFile=1` | Append log with ISO-8601 UTC timestamps, including additional diagnostics |

Ordinary send errors are logged at most once per second. Generic discard reasons require `Verbose=1` and have a separate one-second limit. These messages go to STDOUT or the configured file; they do not produce Operational events.

If a STDOUT write fails, the affected logger disables further console writes and attempts one STDERR diagnostic. File logging and BFD/BGP execution continue. A failed diagnostic write is ignored.

### File logging

The [logging setup script](scripts/Initialize-Logging.ps1) provisions the default registry values and creates `C:\ProgramData\BfdWinService` without creating or writing `trace.log`. After creating the service or console Parameters key, run it from the repository root in **PowerShell as Administrator**:

```powershell
.\scripts\Initialize-Logging.ps1
```

The script sets `LogFilePath` to `C:\ProgramData\BfdWinService\trace.log` and `LogToFile` to DWORD `0`.

At startup, the process reads `LogFilePath` and `LogToFile` from the Parameters key. If `LogFilePath` is absent, it uses `C:\ProgramData\BfdWinService\trace.log`.

If `LogToFile` is absent or `0`, file output is disabled: the logger does not open, create, or write the configured file, or create its parent folders. Operational events and console output continue as described above.

With `LogToFile=1`, the logger creates missing parent folders, including `C:\ProgramData\BfdWinService` for the default path, and appends to the file. Existing contents are preserved. The execution account needs permission to create the folders and write the file. Failure to create a folder or open the file fails startup.

Each file line starts with the current UTC time in `YYYY-MM-DDTHH:mm:ss.sssZ` format. The trailing `Z` identifies UTC, and the fractional seconds provide millisecond precision. Multiline messages include the same entry timestamp on every line. For example:

```text
2026-10-08T12:34:56.789Z service started mode=service
```

To enable file output, run these commands in **PowerShell as Administrator** after creating the Parameters key:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value 'C:\ProgramData\BfdWinService\trace.log' -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 1 -Force | Out-Null
```

Start execution after setting the values, or restart it if already running. To inspect the default file output after startup:

```powershell
Get-Content 'C:\ProgramData\BfdWinService\trace.log' -Tail 20
```

### Operational events

In Event Viewer, open **Applications and Services Logs → BFD-Service → Operational**.

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

Event 105 includes the packet source address/port, configured authentication type/key ID, local discriminator, and rejection reason. It is limited to once per second per process, independently of verbose logging. Keys, passwords, digests, and packet payloads are omitted. Malformed headers, wrong-session discriminators, and invalid transport metadata are rejected before authentication verification and do not generate this event.

The provider GUID is `{8F2A4F61-4D6C-4F2F-9C3E-2B73AB4D62E1}`. The [manifest](events/BFD-Service.man) follows Microsoft's [instrumentation manifest format](https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest). Lifecycle Mode `0` renders as `Windows service`; console startup text uses `mode=console`.

### Logging failures

ETW registration failures are reported to STDERR before the optional file log is open. ETW write failures go to the optional text log. Neither stops BFD.

The provider registers before configuration is read, allowing registry and file-log startup failures to emit event 3. Dispatcher/control-handler failures, registration failures, or abrupt process termination can prevent lifecycle events. A successful ETW write does not guarantee Event Log delivery; install the manifest and keep the channel enabled.

## Optional BGP control

Set `BgpPeerName` to the **configured BGP peer name**, such as `Site17`. This is separate from the BFD peer IP address. Set `BgpRoutingDomain` for a named domain.

The peer must already exist on a Windows Server with Remote Access/BGP configured. The execution account needs permission to manage it. Without `BgpPeerName`, no BGP worker or query is started.

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name BgpPeerName -PropertyType String -Value 'Site17' -Force | Out-Null
```

Restart execution to apply the setting. Control works in both console and SCM modes.

### State changes and actions

| BFD condition | BGP action |
| --- | --- |
| Startup and handshake before the first Up | Read status; leave BGP unchanged |
| Enter Up, including recovery | Check status; Start if the peer is stopped and the action is still current |
| Enter Down after BFD has been Up | Stop |
| Engine shutdown, Ctrl+C, or fatal receive/wait error | Set AdminDown and queue Stop, even if BFD never reached Up |

A running BGP peer continues during the initial BFD handshake. A stopped peer waits for BFD to reach Up. Failed or ambiguous status checks never trigger a speculative Start. Init does not cancel a previously queued Stop.

A dedicated worker handles provider calls while BFD continues running. Failed actions retry after one second unless replaced by a newer action or shutdown. At most a Stop/Start pair remains queued; Down/AdminDown discard queued Starts. An already issued call finishes before the next action runs.

Each MI operation requests a five-second timeout, which is **not a hard shutdown deadline** ([timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Shutdown discards queued Starts, attempts pending Stops, and waits for the worker. A failed final Stop produces a nonzero exit status; final shutdown calls are not retried indefinitely.

<details>
<summary>Native provider details</summary>

The client calls [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` through Rust bindings to `mi.dll` and the [MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke).

At startup, [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer) reads the selected peer. English enum metadata maps `Stopped` to stopped and `Connected`/`Connecting`/`Disconnected` to started. The BFD handshake runs independently.

Each method receives a one-element `Name` string array and, when configured, `RoutingDomain`. [`Stop`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer) also receives `Force=true`. Success requires MI completion success and CIM `ReturnValue=0`. Start checks for supersession before and after its status query; provider calls are not atomic with BFD state changes.

</details>

## Network and protocol behavior

The implementation follows [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html), [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881.html) for single-hop UDP, and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html) for multihop.

| Mode | Control destination port | Received TTL/hop limit |
| --- | --- | --- |
| Single-hop | UDP 3784 | Must be 255, including authenticated traffic |
| Multihop | UDP 4784 | Must meet `MinTtl` when configured |

All outgoing packets use TTL/hop limit 255 and a stable source port in 49152–65535. Allow traffic from that source range to the control destination port in both directions. Firewall rules must be configured separately.

### Session behavior

- One process runs one local/peer session. The receive address/port is exclusively bound; multiple peers sharing it are unsupported. Another process can use a different local address or transport profile.
- Incoming packets must pass peer/path metadata, discriminator, and authentication checks before affecting the session. Point-to-point mode permits source-address changes on the configured single-hop interface. Missing required receive metadata is discarded.
- Outside Up, desired TX is `max(StartupTxUs, MinTxUs)`. Entering Up starts a Poll sequence when this interval changes. Valid peer timer changes are honored; timeouts move Init/Up to Down.
- Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Passive transmission stops when the learned discriminator expires.

### Supported modes and limits

The service originates **asynchronous BFD mode**. Local Demand initiation, Echo, out-of-band discriminator signaling, and live configuration APIs are unsupported.

Periodic transmission stops when the peer advertises a zero required RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is pending. A timeout retains the peer's last timer parameters. Accepted Polls receive immediate Final replies unless local state is AdminDown; replies do not postpone periodic transmissions.

Shutdown attempts one packet when transmission is permitted. Passive sessions with no learned remote discriminator send none. This differs from the recommendation to transmit for a detection period in [RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16).

## Development and testing

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks
cargo fmt --check
$env:RUSTDOCFLAGS = '-D warnings'
cargo doc --locked --no-deps
```

Configuration validation and protocol modules are portable. Registry loading, UDP transport, ETW, native MI, and SCM integration require Windows. IPv4 TTL metadata requires `IP_RECVTTL` support.

Native tests use temporary HKCU registry keys, local MI fixtures, and loopback UDP sockets. They do not change installed service settings or BGP peers. The read-only CIM schema test requires namespace access and is opt-in:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

With nightly Rust and Miri installed:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
cargo +nightly miri test --locked --lib -- --test-threads=1
```

Miri checks the portable logic and synthetic ancillary-data parser. Native Winsock, MI, registry, ETW, and subprocess tests are excluded. For a focused parser check, set `MIRIFLAGS` to `-Zmiri-strict-provenance -Zmiri-tree-borrows` and run `cargo +nightly miri test --locked --lib ancillary_metadata`.

Validate SCM lifecycle, Event Viewer delivery, and actual BGP Start/Stop on the target server. For BGP testing, cover initially stopped and running peers, then disconnect and restore BFD while watching the logs and BGP state.

See the [validation guide](RUST_SKILLS_VALIDATION.md) and [code review](CODE_REVIEW.md) for recorded results and test limits.
