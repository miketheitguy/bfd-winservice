# Registry configuration reference

This reference is for Windows network administrators selecting settings for one Bidirectional Forwarding Detection (BFD) session. For initial provisioning, see [Set up a BFD session](setup.md).

Both console execution and execution through the Windows Service Control Manager (SCM) read this registry key:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters
```

The program reads this key without creating or modifying it. Missing optional values use defaults. Missing required values, incorrect types, or invalid combinations fail startup and identify the affected setting. Registry values use these types:

- **Strings:** `REG_SZ`. `REG_EXPAND_SZ` and environment-variable expansion are unsupported.
- **Numbers and flags:** `REG_DWORD`. Boolean flags must be `0` or `1`.
- **Apply changes:** stop execution, edit the registry, and restart to reload settings.

Types are enforced through [RegGetValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew).

## Addresses and transport

Control traffic uses User Datagram Protocol (UDP). Receive validation checks the IPv4 time-to-live (TTL) or IPv6 hop limit.

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

## Timing

Transmit (TX) and receive (RX) intervals use microseconds. These values control session timing:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `MinTxUs` | `REG_DWORD` | `300000` | Desired transmit interval while Up, 1–4294967295 microseconds |
| `MinRxUs` | `REG_DWORD` | `300000` | Required receive interval, 1–4294967295 microseconds |
| `StartupTxUs` | `REG_DWORD` | `1000000` | Startup interval, at least one second; outside Up, the desired interval is `max(StartupTxUs, MinTxUs)` |
| `DetectMult` | `REG_DWORD` | `3` | Advertised detection multiplier, 1–255 |

Intervals are **microseconds** before jitter:

```text
Transmit interval = max(local desired TX, peer required RX)
Detection time    = peer multiplier × max(local required RX, peer desired TX)
```

Periodic transmit intervals are randomly reduced by 0–25%, or 10–25% when the local multiplier is 1. With matching 300000-microsecond intervals and multiplier 3, detection time is 900 ms. Windows scheduling adds latency; the service does not guarantee microsecond timing.

## Authentication

These values select the authentication algorithm and key:

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
New-ItemProperty -Path $parameters -Name Multihop `
    -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $parameters -Name Auth `
    -PropertyType String -Value 'meticulous-sha1' -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKeyId `
    -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $parameters -Name AuthKey `
    -PropertyType String -Value 'AUTH_KEY' -Force | Out-Null
```

Replace `AUTH_KEY` with a 1–20-byte ASCII key before running the commands in PowerShell as Administrator. Configure the same key, ID, and algorithm on the remote peer. Successful commands produce no output. Restart execution to load the values, then [verify peer communication](setup.md#6-verify-peer-communication).

Unauthenticated packets cannot establish an authenticated session, refresh its detection timer, or trigger a reply. All outgoing packets use the configured authentication. Keyed modes check digests and sequence windows, including wraparound and restart resynchronization. Authentication failures are logged regardless of `Verbose`; see [event 105](logging.md#operational-events).

These algorithms support [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html) interoperability. The RFC discourages MD5, and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html) recommends cryptographic authentication for multihop. Registry key contents are unencrypted: restrict Parameters access to administrators and accounts that need it, including the service account. Authentication keys never appear in logs or configuration errors.

## Logging and BGP

These values control text logging and integration with a Windows Border Gateway Protocol (BGP) peer:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `LogFilePath` | `REG_SZ` | `C:\ProgramData\BfdWinService\trace.log` | Append log path; use an absolute path under SCM |
| `LogToFile` | `REG_DWORD` | `0` | `0` = disable file output; `1` = enable file output |
| `Verbose` | `REG_DWORD` | `0` | Log generic packet discard reasons, at most once per second |
| `BgpPeerName` | `REG_SZ` | None | Enable control of this configured Windows BGP peer |
| `BgpRoutingDomain` | `REG_SZ` | Default routing domain | Optional domain; requires `BgpPeerName` |

For provisioning and verification, see [Logs and events](logging.md) and [Control a Windows BGP peer](bgp.md).
