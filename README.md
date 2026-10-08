# BFD Windows service

A provisioned, asynchronous BFD session over IPv4 or IPv6, running under the Windows Service Control Manager (SCM) or in a console.

The implementation is based on [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html), with [RFC 5881 single-hop UDP encapsulation](https://www.rfc-editor.org/rfc/rfc5881.html) and [RFC 5883 multihop encapsulation](https://www.rfc-editor.org/rfc/rfc5883.html). Implemented features and limits are described below.

## Build and check

Install Rust for Windows and the Visual Studio **Desktop development with C++** workload, including the MSVC toolchain and Windows SDK. Use the `windows-msvc` Rust target. The build compiles the ETW manifest with the SDK's `mc.exe` and `rc.exe` and embeds its metadata and English messages in `bfd-winservice.exe`. The build finds these tools on `PATH` or in the installed Windows 10/11 SDK; use Developer PowerShell if the MSVC linker is not on `PATH`. For custom SDK locations, set `BFD_MC_PATH` and `BFD_RC_PATH` to the absolute tool paths. Use Windows 10 or later (or a corresponding Windows Server release); IPv4 receive TTL metadata requires `IP_RECVTTL` support.

```powershell
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
.\target\release\bfd-winservice.exe --help
```

The protocol and configuration validation modules are portable; registry loading, the UDP transport, native MI client, and service integration are Windows-specific. BGP control uses Rust bindings to `mi.dll`; no PowerShell process or C++ helper is required. See the [validation guide](RUST_SKILLS_VALIDATION.md) and [correctness review](CODE_REVIEW.md) for recorded checks and their limits.

With nightly Rust and the Miri component installed, check the library tests with strict pointer provenance:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
cargo +nightly miri test --locked --lib -- --test-threads=1
```

The library tests include synthetic IPv4/IPv6 ancillary-data records to exercise the unsafe parser without opening sockets. Miri cannot execute Winsock's `WSAStartup`, native MI calls, registry calls, ETW registration, or subprocesses; those native tests are excluded under Miri. Run the UDP integration and native tests with `cargo test`. Registry tests create and remove unique temporary HKCU keys; they do not change the installed service's HKLM settings. For an additional parser check, set `MIRIFLAGS` to `-Zmiri-strict-provenance -Zmiri-tree-borrows` and run `cargo +nightly miri test --locked --lib ancillary_metadata`.

## Registry configuration

Both SCM and console execution read settings at startup from:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters
```

All former command-line settings are registry values. `--console` is the only application command-line option; `--help` and `--version` are also available. There are no command-line configuration overrides. The program reads this key without creating or modifying it. Missing optional values use the defaults below; missing required values, incorrect types, or invalid combinations fail startup and identify the affected setting. Strings must be `REG_SZ`; environment-variable expansion through `REG_EXPAND_SZ` is not supported. Numeric settings and Boolean flags use `REG_DWORD`, with flags restricted to `0` (off) or `1` (on). These types are enforced through the [Windows registry API](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew).

Use Administrator PowerShell to provision a single-hop session. For SCM execution, create the service first as described below. Provision the remote peer separately with the reverse local/peer addresses; BFD has no peer discovery. Obtain the local interface index with `Get-NetIPInterface` and replace the example addresses/index:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-Item -Path $parameters -Force | Out-Null
New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '192.0.2.10' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '192.0.2.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name InterfaceIndex -PropertyType DWord -Value 12 -Force | Out-Null
```

| Registry value | Type | Default when absent | Purpose |
| --- | --- | --- | --- |
| `Local`, `Peer` | `REG_SZ` | Required | Specific unicast IP literals of the same family; IPv4 or IPv6 |
| `Mode` | `REG_SZ` | `single-hop` | `single-hop` or `multihop` |
| `Multihop` | `REG_DWORD` | `0` | `1` selects multihop; omit `Mode` when using this shortcut |
| `PointToPoint` | `REG_DWORD` | `0` | Single-hop point-to-point link; accept any peer source address on the configured interface |
| `InterfaceIndex` | `REG_DWORD` | Required for single-hop/link-local | Nonzero outgoing/incoming interface index |
| `MinTxUs` | `REG_DWORD` | `300000` | Desired TX interval while Up, 1..4294967295 microseconds |
| `MinRxUs` | `REG_DWORD` | `300000` | Required RX interval, 1..4294967295 microseconds |
| `StartupTxUs` | `REG_DWORD` | `1000000` | Desired TX interval outside Up; at least one second; effective value is `max(StartupTxUs, MinTxUs)` |
| `DetectMult` | `REG_DWORD` | `3` | Advertised multiplier, 1..255 |
| `Discriminator` | `REG_DWORD` | Random | Nonzero local session identifier |
| `SourcePort` | `REG_DWORD` | Random available port | Fixed session UDP source port, 49152..65535 |
| `Passive` | `REG_DWORD` | `0` | Wait for a validated peer control packet; multihop only |
| `MinTtl` | `REG_DWORD` | No multihop threshold | Reject multihop packets below this received TTL/hop limit, 1..255 |
| `Auth` | `REG_SZ` | `none` | `none`, `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, `meticulous-sha1` |
| `AuthKeyId` | `REG_DWORD` | `0` | Authentication key ID, 0..255 |
| `AuthKey` | `REG_SZ` | None | ASCII key; authentication requires this or `AuthKeyHex` |
| `AuthKeyHex` | `REG_SZ` | None | Binary key encoded as hexadecimal text, instead of `AuthKey` |
| `LogFile` | `REG_SZ` | None | Path to an append log; use an absolute path for SCM execution; timestamps are Unix milliseconds |
| `BgpPeerName` | `REG_SZ` | None | Enable native MI Start/Stop control for this configured BGP peer name |
| `BgpRoutingDomain` | `REG_SZ` | Default routing domain | Optional routing domain; requires `BgpPeerName` |
| `Verbose` | `REG_DWORD` | `0` | Log discarded packet reasons, at most one per second |

For a point-to-point single-hop link, set `PointToPoint=1` and `InterfaceIndex`. The peer may send from any source address on that link, including changing its source during a session. Outgoing packets continue to use the configured `Peer` destination. For IPv6 use literal addresses such as `2001:db8::10`; link-local addresses require `InterfaceIndex` and must not have a `%scope` suffix.

Multihop example, after provisioning `Local` and `Peer` (configure the same authentication type, key ID, and key at the peer):

```powershell
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '198.51.100.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Mode -PropertyType String -Value 'multihop' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Auth -PropertyType String -Value 'meticulous-sha1' -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKeyId -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKey -PropertyType String -Value 'replace-this-key' -Force | Out-Null
```

Password and MD5 keys are 1–16 bytes; SHA1 keys are 1–20 bytes. Only one authentication key is active at a time. Keyed modes verify digests and sequence windows, including wraparound and restart resynchronization. SHA1 is included for compatibility with RFC 5880; MD5 use is discouraged by that RFC. RFC 5883 recommends cryptographic authentication over multihop paths. Registry keys are not encrypted: restrict read access to the Parameters key to the administrators and accounts that need it, including the service account. Authentication keys are never included in logs or configuration errors.

When authentication is configured, unauthenticated packets cannot establish a session or refresh its detection timer. They are discarded without a network reply, including any Poll/Final flags, as required by [RFC 5880 section 6.8.6](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.6). Authentication verification failures emit Operational Warning event 105 in service mode and a text message on console STDOUT or in the optional file log, at most once per second per process, regardless of `Verbose`. Every outgoing packet uses the configured authentication, including startup, Down, and Final packets. Passive sessions wait for a valid authenticated peer packet, and periodic transmission remains subject to the suppression rules below. If an established peer stops sending valid authenticated packets, the session times out to Down with the Control Detection Time Expired diagnostic.

All intervals are **microseconds**, before jitter. The actual periodic transmit interval is negotiated as `max(local desired TX, peer required RX)`, then randomly reduced by 0–25% (10–25% when the local multiplier is 1). The local detection time is `peer multiplier * max(local required RX, peer desired TX)`. With matching 300000-microsecond intervals and multiplier 3, detection time is 900 ms. Windows scheduling adds latency; this is a user-space service and does not promise microsecond timing.

## Run in a console

After provisioning the registry, start foreground execution:

```powershell
.\target\release\bfd-winservice.exe --console
```

BFD log messages, including configuration failures, go directly to **STDOUT** in this mode. Console mode does not register or write the ETW provider. To capture STDOUT, use `> .\bfd-console.log`; `LogFile` can also be configured for an append log. Both execution modes read the same registry settings once at startup, so stop the process before editing settings and restart afterward.

Ctrl+C sets AdminDown, attempts a shutdown packet when transmission is permitted, and waits for any BGP cleanup before exiting. Passive sessions with no learned remote discriminator do not send a shutdown packet; send failures are logged. Shutdown attempts one packet rather than continuing transmission for the detection period recommended by [RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16).

If a STDOUT write fails, for example when a downstream pipe reader closes, that logger disables further console writes and attempts one diagnostic on STDERR. BFD execution, shutdown cleanup, and any configured `LogFile` continue. A failed diagnostic write is ignored. Console mode continues to use no ETW provider after an output failure.

## Control a Windows BGP peer with BFD

Set `BgpPeerName` to the **configured BGP peer name**, which is separate from the BFD `Peer` IP address. Set `BgpRoutingDomain` for a peer in a named routing domain. Both values are strings. The BGP peer must already exist on the local Windows Server with Remote Access/BGP configured, and the console or service account must have permission to manage it. These settings apply equally to console and SCM execution.

```powershell
New-ItemProperty -Path $parameters -Name BgpPeerName -PropertyType String -Value 'Site17' -Force | Out-Null
.\target\release\bfd-winservice.exe --console
```

At service/console startup the worker reads the selected peer through [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer). It interprets `BgpPeerConfig.ConnectivityStatus` using the provider's enum metadata, requesting English labels. `Stopped` means the peer needs Start; `Connected`, `Connecting`, and `Disconnected` mean it has already been started. BFD begins its configured handshake independently of this read-only query.

The client invokes the static methods of [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` using the [Windows MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke):

- Entering **Up**, including the first completed handshake and later recovery, queues a status check and calls `Start` only if the peer is stopped and the queued action is still current. A peer already running is left unchanged.
- Until BFD first reaches **Up**, unsuccessful handshake attempts leave BGP unchanged, allowing a running BGP peer to continue while BFD establishes.
- After BFD has reached **Up**, entering **Down** after a timeout or peer-reported Down/AdminDown queues `Stop`.
- Once the engine is running, service shutdown, Ctrl+C, and fatal receive/wait errors set AdminDown and queue `Stop`, even if BFD never reached Up.

The initial Down state and Down-to-Init transition cause no BGP mutation. A stopped BGP peer waits for BFD to establish before it is started. Failed or ambiguous status checks are logged; they never trigger a speculative Start. The worker retries a failed action unless a newer queued action or shutdown supersedes it. An Init transition does not cancel a Stop queued by an earlier Down. Each method receives a one-element string array `Name`; `RoutingDomain` is supplied when configured. `Stop` also receives `Force=true` for unattended execution, as defined by its [method signature](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer).

A dedicated worker serializes calls while BFD continues sending and receiving packets. Each MI operation requests a five-second timeout; this is not a fixed end-to-end or shutdown deadline ([MI timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Success requires both MI completion success and a zero CIM `ReturnValue`; errors are logged and retried after one second unless superseded. During sustained flapping behind a slow provider, at most a Stop/Start pair remains queued. A newer Down or AdminDown discards queued Starts, and Start checks for supersession again after its status query. These checks do not make provider calls atomic with BFD state changes: an already issued MI call finishes before the next action runs. Shutdown discards queued Starts, attempts pending Stops, and waits for the worker. A failed final Stop produces a nonzero console exit code or SCM service-specific exit status; shutdown calls are not retried indefinitely. Without `BgpPeerName`, no BGP worker or MI query is started.

Native tests exercise parameter copying, Unicode, `Force`, embedded status results, CIM return codes, and an error response from a nonexistent class in `root/cimv2`. They do not change any BGP peers. The read-only class-schema test requires CIM namespace access and is opt-in: run `cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored` outside a restricted sandbox. Validate actual startup and Stop/Start behavior on the target server with both a stopped and a running BGP peer, then disconnect and restore BFD while watching the BFD log and BGP state.

## Install and run as a service

Open PowerShell as Administrator. Keep the executable at the installed path and use absolute log paths. The service name is `BfdWinService`. Its **BinaryPathName** contains only the quoted executable path; all settings belong in its Parameters registry key. Arguments passed via `Start-Service` are not used.

```powershell
$exe = (Resolve-Path .\target\release\bfd-winservice.exe).Path
$log = Join-Path (Split-Path $exe) 'bfd.log'
$binaryPath = '"' + $exe + '"'
New-Service -Name BfdWinService -BinaryPathName $binaryPath -DisplayName 'BFD Windows Service' -StartupType Manual
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-Item -Path $parameters -Force | Out-Null
New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '192.0.2.10' -Force | Out-Null
New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '192.0.2.20' -Force | Out-Null
New-ItemProperty -Path $parameters -Name InterfaceIndex -PropertyType DWord -Value 12 -Force | Out-Null
New-ItemProperty -Path $parameters -Name LogFile -PropertyType String -Value $log -Force | Out-Null
# Register the ETW manifest as shown below before starting the service.
Start-Service BfdWinService
Get-Service BfdWinService
Get-Content $log -Tail 20
Stop-Service BfdWinService
```

For an existing installation, stop it, provision the registry values above (and any other settings formerly supplied on the command line), and remove old arguments from its executable path before restarting:

```powershell
Stop-Service BfdWinService
# Provision or update the Parameters values while stopped.
sc.exe config BfdWinService binPath= $binaryPath
Start-Service BfdWinService
```

To remove the stopped service:

```powershell
sc.exe delete BfdWinService
```

SCM Running means registry configuration was validated, engine initialization succeeded, sockets are open, and any configured BGP worker has started; it does not mean BFD is Up or the initial BGP status query succeeded. Session Up/Down and diagnostic reasons are recorded in the log. Registry, file-log, and socket/engine initialization failures report a nonzero SCM service-specific exit status. SCM Stop and Shutdown report StopPending immediately; the engine sets AdminDown and attempts a shutdown packet when the active/passive role permits transmission before finishing BGP cleanup. Shutdown checkpoints advance while cleanup is pending after a stop request. Register the Operational channel below for service and communication events, and set `LogFile` for additional diagnostics; SCM has no console.

## Windows Event Log / ETW

The manifest-based provider is **BFD-Service**, GUID `{8F2A4F61-4D6C-4F2F-9C3E-2B73AB4D62E1}`, with one enabled channel: **BFD-Service/Operational**. Its source is [events/BFD-Service.man](events/BFD-Service.man), following Microsoft's [instrumentation manifest documentation](https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest). SCM execution emits these events; `--console` writes the corresponding messages directly to STDOUT. Lifecycle events use numeric Mode `0`, rendered as `Windows service` by the manifest, for SCM execution. The console text startup message uses `mode=console`.

After building, register the manifest **once on each target machine**, from Administrator PowerShell, before starting the service. Use the final installed executable path because Event Viewer loads the embedded resources from it. Deploy the `.man` file alongside the executable, or resolve its source path as shown here:

```powershell
$exe = (Resolve-Path .\target\release\bfd-winservice.exe).Path
$manifest = (Resolve-Path .\events\BFD-Service.man).Path
wevtutil.exe im $manifest "/rf:$exe" "/mf:$exe"
if ($LASTEXITCODE -ne 0) { throw 'BFD-Service manifest registration failed' }
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

View events in Event Viewer under **Applications and Services Logs → BFD-Service → Operational**, or query recent events:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'BFD-Service/Operational' } -MaxEvents 20 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

| Event ID | Level | Meaning |
| --- | --- | --- |
| 1 | Information | Engine initialization completed and SCM Running was reported |
| 2 | Information | Execution ended after shutdown/cleanup; ExitCode is 0 for success or 1 for failure |
| 3 | Error | Registry configuration, log/engine initialization, or execution failed |
| 100 | Information | First valid control packet arrived, including after a communication timeout |
| 101 | Warning | No valid control packet arrived within the detection interval; includes the last known remote discriminator |
| 102 | Information | Session entered Up, including recovery |
| 103 | Warning | Session entered Down due to detection expiry or peer-reported Down/AdminDown |
| 104 | Information | Session entered Init or local AdminDown |
| 105 | Warning | Authentication verification failed; includes packet source, configured authentication type/key ID, and reason |

Events 100–104 record the local/peer addresses, local/remote discriminators, previous/current BFD states, diagnostic, transmit interval, and detection time in microseconds. Events 100/101 track reception independently of session establishment: a peer can keep sending Down or AdminDown packets without being Up. Invalid transport metadata, authentication, or session identifiers never count as communication. Repeated valid packets and repeated timeout checks do not emit duplicate communication events. Other packet discard reasons are logged only with `Verbose=1`, at most once per second. Ordinary send errors are also limited to once per second. These messages go to console STDOUT or `LogFile` when configured; they do not produce Operational events.

Authentication Warning event 105 records the local/peer addresses, actual packet source address/port, local discriminator, configured authentication type/key ID, and a static rejection reason. Reasons cover missing/unexpected authentication, type/key ID/length mismatches, password/digest failures, and invalid sequence windows. No password, key bytes, digest, or packet payload is logged. Warnings are limited to one per second per process independently of the verbose discard limit, and are enabled regardless of `Verbose`. Generic malformed headers, wrong-session discriminators, and invalid transport metadata are rejected before authentication verification and do not generate event 105.

ETW registration failures are reported to stderr before the optional file log is available; ETW write failures are reported in the optional text log. Neither stops BFD. A successful ETW write does not guarantee Event Log delivery: install the manifest and keep the channel enabled. The service registers its ETW provider before reading registry settings or opening `LogFile`, so failures in those steps can emit event 3. Dispatcher/control-handler failures, failed ETW registration, and abrupt process termination can occur before lifecycle events are written.

When changing the executable location or manifest, stop the service, uninstall the old manifest, and register the new one with the new absolute resource paths. To uninstall after stopping the service:

```powershell
wevtutil.exe um $manifest
if ($LASTEXITCODE -ne 0) { throw 'BFD-Service manifest removal failed' }
```

Provider registration/removal uses Microsoft's [wevtutil manifest commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil). Building and running the binary do not install the manifest automatically.

## Network behavior and scope

- Single-hop listens/sends to UDP **3784**; multihop listens/sends to UDP **4784**. Transmissions use a separate socket with a stable source port in **49152–65535**, never the control destination port. Configure firewalls for peer-to-local UDP 3784 or 4784 from that source range and the reverse direction. This program does not change firewall rules.
- All outgoing packets have TTL/hop limit **255**. Single-hop validates received TTL/hop limit 255, even when authenticated. Multihop accepts routed packets, optionally enforcing `MinTtl`. Received address and interface metadata is checked with `WSARecvMsg`; missing required metadata is discarded.
- `PointToPoint=1` uses the configured single-hop interface to identify initial packets and the receiver discriminator afterward, as required by RFC 5881 section 6. TTL, destination, source port, discriminator, and configured authentication checks still apply. Other profiles require the configured peer source address.
- Outside Up, the desired TX interval is the greater of `StartupTxUs` and `MinTxUs`. Entering Up starts a Poll sequence if the desired TX interval changes. Peer timer changes are honored, malformed/wrong-session/unauthenticated packets do not refresh detection, and timeouts move Init/Up to Down. Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Passive transmission stops again when the learned discriminator expires.
- There is one session per process, with one local/peer pair (RFC 5883 section 4.1). The receive address/port is exclusively bound. Another process can use a different local address or the other transport profile. Multiple peers sharing the same local address and control port and out-of-band discriminator signaling are not implemented.
- The implementation originates **asynchronous mode** only. Periodic transmission is suppressed when the peer advertises a zero required RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is pending. A timeout retains the peer's last timer parameters, including a zero required RX interval. Accepted Poll packets receive immediate Final replies unless the local state is AdminDown, without postponing scheduled periodic transmissions. Local Demand initiation and Echo are not implemented; the outgoing Demand bit and required Echo RX interval are zero. Echo must not be used over multihop.
- Tunables are registry startup settings; stop execution, edit them, and restart. Optional native MI integration controls the configured BGP peer. No live management API or other external state notifications are provided beyond the logs.
