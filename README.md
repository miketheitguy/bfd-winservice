# BFD Windows service

A provisioned, asynchronous BFD session over IPv4 or IPv6, running under the Windows Service Control Manager (SCM) or in a console.

The implementation is based on [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html), with [RFC 5881 single-hop UDP encapsulation](https://www.rfc-editor.org/rfc/rfc5881.html) and [RFC 5883 multihop encapsulation](https://www.rfc-editor.org/rfc/rfc5883.html). Implemented features and limits are described below.

## Build and check

Install Rust for Windows and the Visual Studio **Desktop development with C++** workload, including the MSVC toolchain and Windows SDK. Use Windows 10 or later (or a corresponding Windows Server release); IPv4 receive TTL metadata requires `IP_RECVTTL` support.

```powershell
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
.\target\release\bfd-winservice.exe --help
```

The protocol and configuration modules are portable; the UDP transport, native MI client, and service integration are Windows-specific. BGP control uses Rust bindings to `mi.dll`; no PowerShell process or C++ helper is required. See the [validation guide](RUST_SKILLS_VALIDATION.md) and [correctness review](CODE_REVIEW.md) for recorded checks and their limits.

With nightly Rust and the Miri component installed, check the library tests with strict pointer provenance:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
cargo +nightly miri test --locked --lib -- --test-threads=1
```

The library tests include synthetic IPv4/IPv6 ancillary-data records to exercise the unsafe parser without opening sockets. Miri cannot execute Winsock's `WSAStartup` or native MI calls; the native MI smoke tests are excluded under Miri. Run the UDP integration and native MI tests with `cargo test`. For an additional parser check, set `MIRIFLAGS` to `-Zmiri-strict-provenance -Zmiri-tree-borrows` and run `cargo +nightly miri test --locked --lib ancillary_metadata`.

## Run in a console

Provision the peer separately with the reverse local/peer addresses. BFD has no peer discovery. Obtain the interface index with `Get-NetIPInterface`.

For a point-to-point single-hop link, add `--point-to-point` and its `--interface-index`. The peer may send from any source address on that link, including changing its source during a session. Outgoing packets continue to use the configured `--peer` destination.

Single-hop example:

```powershell
.\target\release\bfd-winservice.exe --console `
    --local 192.0.2.10 --peer 192.0.2.20 --interface-index 12 `
    --min-tx-us 300000 --min-rx-us 300000 --detect-mult 3
```

Multihop example (configure the same authentication type, key ID, and key at the peer):

```powershell
.\target\release\bfd-winservice.exe --console `
    --local 192.0.2.10 --peer 198.51.100.20 --multihop `
    --min-tx-us 300000 --min-rx-us 300000 --detect-mult 3 `
    --auth meticulous-sha1 --auth-key-id 1 --auth-key 'replace-this-key'
```

For IPv6 use literal addresses, such as `--local 2001:db8::10 --peer 2001:db8::20`. Link-local addresses require `--interface-index`; supply the addresses without a `%scope` suffix. Ctrl+C sets AdminDown, attempts a shutdown packet when transmission is permitted, and waits for any BGP cleanup before exiting. Passive sessions with no learned remote discriminator do not send a shutdown packet; send failures are logged. Shutdown attempts one packet rather than continuing transmission for the detection period recommended by [RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16).

All intervals are **microseconds**, before jitter. The actual periodic transmit interval is negotiated as `max(local desired TX, peer required RX)`, then randomly reduced by 0–25% (10–25% when the local multiplier is 1). The local detection time is `peer multiplier * max(local required RX, peer desired TX)`. With matching 300000-microsecond intervals and multiplier 3, detection time is 900 ms. Windows scheduling adds latency; this is a user-space service and does not promise microsecond timing.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--local`, `--peer` | Required | Specific unicast IPs of the same family |
| `--mode single-hop\|multihop` | `single-hop` | Select transport profile |
| `--multihop` | Off | Shortcut for `--mode multihop` |
| `--point-to-point` | Off | Single-hop point-to-point link; accept any peer source address on the configured interface |
| `--interface-index` | Required for single-hop/link-local | Select outgoing interface and validate incoming interface |
| `--min-tx-us` | `300000` | Desired TX interval while Up, 1..4294967295 |
| `--min-rx-us` | `300000` | Required RX interval, 1..4294967295 |
| `--startup-tx-us` | `1000000` | Desired TX interval outside Up; must be at least one second; effective value is `max(startup-tx-us, min-tx-us)` |
| `--detect-mult` | `3` | Advertised multiplier, 1..255 |
| `--discriminator` | Random | Nonzero local session identifier |
| `--source-port` | Random available port | Fixed session UDP source port, 49152..65535 |
| `--passive` | Off | Wait for a validated peer control packet; multihop only |
| `--min-ttl` | No multihop threshold | Reject multihop packets below this received TTL/hop limit |
| `--auth` | `none` | `none`, `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, `meticulous-sha1` |
| `--auth-key-id` | `0` | Authentication key ID, 0..255 |
| `--auth-key` | None | ASCII key; authentication requires this or `--auth-key-hex` |
| `--auth-key-hex` | None | Binary key encoded as hex, instead of `--auth-key` |
| `--console` | Off | Foreground mode instead of SCM |
| `--log-file` | None | Append state changes and errors; timestamps are Unix milliseconds |
| `--bgp-peer-name` | None | Enable native MI Start/Stop control for this configured BGP peer name |
| `--bgp-routing-domain` | Default routing domain | Optional routing domain; requires `--bgp-peer-name` |
| `--verbose` | Off | Log discarded packet reasons, at most one per second |

Password and MD5 keys are 1–16 bytes; SHA1 keys are 1–20 bytes. Only one authentication key is active at a time. Keyed modes verify digests and sequence windows, including wraparound and restart resynchronization. SHA1 is included for compatibility with RFC 5880; MD5 use is discouraged by that RFC. RFC 5883 recommends cryptographic authentication over multihop paths. Command-line keys are visible in process/service configuration, so restrict access to it.

When authentication is configured, unauthenticated packets cannot establish a session or refresh its detection timer. They are discarded without a network reply, including any Poll/Final flags, as required by [RFC 5880 section 6.8.6](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.6); `--verbose` may log the reason. Every outgoing packet uses the configured authentication, including startup, Down, and Final packets. Passive sessions wait for a valid authenticated peer packet, and periodic transmission remains subject to the suppression rules below. If an established peer stops sending valid authenticated packets, the session times out to Down with the Control Detection Time Expired diagnostic.

## Control a Windows BGP peer with BFD

Add `--bgp-peer-name` with the **configured BGP peer name**, which is separate from the BFD `--peer` IP address. Add `--bgp-routing-domain` for a peer in a named routing domain. The BGP peer must already exist on the local Windows Server with Remote Access/BGP configured, and the console or service account must have permission to manage it. These options apply equally to console and SCM execution.

```text
bfd-winservice.exe --console --local 192.0.2.10 --peer 192.0.2.20 --interface-index 12 --bgp-peer-name Site17
```

At service/console startup the worker reads the selected peer through [`PS_BgpPeer.Get`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/get-ps-bgppeer). It interprets `BgpPeerConfig.ConnectivityStatus` using the provider's enum metadata, requesting English labels. `Stopped` means the peer needs Start; `Connected`, `Connecting`, and `Disconnected` mean it has already been started. BFD begins its configured handshake independently of this read-only query.

The client invokes the static methods of [`PS_BgpPeer`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/ps-bgppeer) in `root\Microsoft\Windows\RemoteAccess` using the [Windows MI client API](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke):

- Entering **Up**, including the first completed handshake and later recovery, queues a status check and calls `Start` only if the peer is stopped and the queued action is still current. A peer already running is left unchanged.
- Until BFD first reaches **Up**, unsuccessful handshake attempts leave BGP unchanged, allowing a running BGP peer to continue while BFD establishes.
- After BFD has reached **Up**, entering **Down** after a timeout or peer-reported Down/AdminDown queues `Stop`.
- Once the engine is running, service shutdown, Ctrl+C, and fatal receive/wait errors set AdminDown and queue `Stop`, even if BFD never reached Up.

The initial Down state and Down-to-Init transition cause no BGP mutation. A stopped BGP peer waits for BFD to establish before it is started. Failed or ambiguous status checks are logged; they never trigger a speculative Start. The worker retries a failed action unless a newer queued action or shutdown supersedes it. An Init transition does not cancel a Stop queued by an earlier Down. Each method receives a one-element string array `Name`; `RoutingDomain` is supplied when configured. `Stop` also receives `Force=true` for unattended execution, as defined by its [method signature](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ramgmtpsprov/stop-ps-bgppeer).

A dedicated worker serializes calls while BFD continues sending and receiving packets. Each MI operation requests a five-second timeout; this is not a fixed end-to-end or shutdown deadline ([MI timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). Success requires both MI completion success and a zero CIM `ReturnValue`; errors are logged and retried after one second unless superseded. During sustained flapping behind a slow provider, at most a Stop/Start pair remains queued. A newer Down or AdminDown discards queued Starts, and Start checks for supersession again after its status query. These checks do not make provider calls atomic with BFD state changes: an already issued MI call finishes before the next action runs. Shutdown discards queued Starts, attempts pending Stops, and waits for the worker. A failed final Stop produces a nonzero console exit code or SCM service-specific exit status; shutdown calls are not retried indefinitely. Without `--bgp-peer-name`, no BGP worker or MI query is started.

Native tests exercise parameter copying, Unicode, `Force`, embedded status results, CIM return codes, and an error response from a nonexistent class in `root/cimv2`. They do not change any BGP peers. The read-only class-schema test requires CIM namespace access and is opt-in: run `cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored` outside a restricted sandbox. Validate actual startup and Stop/Start behavior on the target server with both a stopped and a running BGP peer, then disconnect and restore BFD while watching the BFD log and BGP state.

## Install and run as a service

Open PowerShell as Administrator. Keep the executable at the installed path and use absolute log paths. Set BFD options in the service's **BinaryPathName**; arguments passed via `Start-Service` are not used. The service name is `BfdWinService`.

```powershell
$exe = (Resolve-Path .\target\release\bfd-winservice.exe).Path
$log = Join-Path (Split-Path $exe) 'bfd.log'
$binaryPath = '"' + $exe + '" --local 192.0.2.10 --peer 192.0.2.20 --interface-index 12 --min-tx-us 300000 --min-rx-us 300000 --detect-mult 3 --log-file "' + $log + '"'
New-Service -Name BfdWinService -BinaryPathName $binaryPath -DisplayName 'BFD Windows Service' -StartupType Manual
Start-Service BfdWinService
Get-Service BfdWinService
Get-Content $log -Tail 20
Stop-Service BfdWinService
```

For an existing installation, stop it and update its options:

```powershell
Stop-Service BfdWinService
sc.exe config BfdWinService binPath= $binaryPath
Start-Service BfdWinService
```

To remove the stopped service:

```powershell
sc.exe delete BfdWinService
```

SCM Running means engine initialization succeeded, sockets are open, and any configured BGP worker has started; it does not mean BFD is Up or the initial BGP status query succeeded. Session Up/Down and diagnostic reasons are recorded in the log. Socket/engine initialization failures report a nonzero SCM service-specific exit status. SCM Stop and Shutdown report StopPending immediately; the engine sets AdminDown and attempts a shutdown packet when the active/passive role permits transmission before finishing BGP cleanup. Shutdown checkpoints advance while cleanup is pending after a stop request. Use `--log-file` for service diagnostics; SCM has no console.

## Network behavior and scope

- Single-hop listens/sends to UDP **3784**; multihop listens/sends to UDP **4784**. Transmissions use a separate socket with a stable source port in **49152–65535**, never the control destination port. Configure firewalls for peer-to-local UDP 3784 or 4784 from that source range and the reverse direction. This program does not change firewall rules.
- All outgoing packets have TTL/hop limit **255**. Single-hop validates received TTL/hop limit 255, even when authenticated. Multihop accepts routed packets, optionally enforcing `--min-ttl`. Received address and interface metadata is checked with `WSARecvMsg`; missing required metadata is discarded.
- `--point-to-point` uses the configured single-hop interface to identify initial packets and the receiver discriminator afterward, as required by RFC 5881 section 6. TTL, destination, source port, discriminator, and configured authentication checks still apply. Other profiles require the configured peer source address.
- Outside Up, the desired TX interval is the greater of `--startup-tx-us` and `--min-tx-us`. Entering Up starts a Poll sequence if the desired TX interval changes. Peer timer changes are honored, malformed/wrong-session/unauthenticated packets do not refresh detection, and timeouts move Init/Up to Down. Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Passive transmission stops again when the learned discriminator expires.
- There is one session per process, with one local/peer pair (RFC 5883 section 4.1). The receive address/port is exclusively bound. Another process can use a different local address or the other transport profile. Multiple peers sharing the same local address and control port and out-of-band discriminator signaling are not implemented.
- The implementation originates **asynchronous mode** only. Periodic transmission is suppressed when the peer advertises a zero required RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is pending. A timeout retains the peer's last timer parameters, including a zero required RX interval. Accepted Poll packets receive immediate Final replies unless the local state is AdminDown, without postponing scheduled periodic transmissions. Local Demand initiation and Echo are not implemented; the outgoing Demand bit and required Echo RX interval are zero. Echo must not be used over multihop.
- Tunables are startup options; change them by restarting. Optional native MI integration controls the configured BGP peer. No live management API or other external state notifications are provided beyond the logs.
