# Registry configuration reference

Cowabunga, configuration crew. Check every setting before rolling out. Windows
network admins, this is your settings playbook for one Bidirectional Forwarding
Detection (BFD) session. Let's get it, like, totally dialed in, dude. For
initial provisioning, see [Set up a BFD session](setup.md).

Configuration vibe check, no cap: the registry is the source of truth. The
executable accepts `--console`, `--help`, and `--version`; session settings
aren't CLI flags.

Both console execution and execution through the Windows Service Control Manager (SCM) read this registry key:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters
```

The program reads this key without creating or modifying it. Omit an optional
value and its default takes over. A missing required value, wrong type, or
invalid combination stops startup and names the affected setting. Keep it
tubular and check the types: registry values use these types:

- **Strings:** `REG_SZ`. `REG_EXPAND_SZ` and environment-variable expansion are unsupported.
- **Numbers and flags:** `REG_DWORD`. Boolean flags must be `0` or `1`.

Types are enforced through [RegGetValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew).

## Apply changes and access settings

Turtle power still follows the reload and permission rules. Restart to reload
startup settings. S-BFD timing and maintenance settings reload when the
Parameters key changes; see
[Change timing and entity availability](seamless.md#change-timing-and-entity-availability).

The MSI protects this key: SYSTEM and administrators have full control, and the
enabled BFD service SID has read access. Console execution and configuration
therefore require an elevated Administrator session. The BGP broker reads only
the configured BGP target; restart both services after changing either BGP value.
Service configuration changes and Start/Stop require elevation. Non-administrators
can still query service status and read logs; see [Monitor service status and BFD
events](monitoring.md).

## Addresses and transport

Get the packet route totally tubular before tuning anything else. Control
traffic uses User Datagram Protocol (UDP). Receive validation checks the IPv4
time-to-live (TTL) or IPv6 hop limit.

For classical BFD, use `Multihop` to select the transport. If you omit this value or set it to `0`,
the service uses single-hop. Set it to `1` for multihop. The following values
configure the addresses and transport:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `Local` | `REG_SZ` | Required | Local unicast IPv4 or IPv6 literal |
| `Peer` | `REG_SZ` | Required for classical BFD and S-BFD initiators | Target of the same address family; unused by reflectors; classical addresses must differ |
| `Multihop` | `REG_DWORD` | `0` | `0` = single-hop; `1` = multihop |
| `InterfaceIndex` | `REG_DWORD` | Required for classical single-hop or link-local IPv6 | Nonzero incoming/outgoing interface index |
| `PointToPoint` | `REG_DWORD` | `0` | Classical single-hop only: accept peer source-address changes on the configured interface |
| `SourcePort` | `REG_DWORD` | Random available port | Classical or S-BFD initiator source port, 49152–65535; invalid for reflectors |
| `Discriminator` | `REG_DWORD` | Random nonzero value, except required for reflectors | Local session identifier or reflector entity identifier; assign distinct values to coexisting local sessions |
| `Passive` | `REG_DWORD` | `0` | Classical multihop only: wait for a valid peer packet before sending |
| `MinTtl` | `REG_DWORD` | No threshold | Multihop or S-BFD minimum received TTL/hop limit, 1–255 |

`Multihop` must be a `REG_DWORD` with value `0` or `1`. Any other value or
registry type fails startup.

Heads up, buddy: the legacy `Mode` value is ignored. Use `Multihop`; a stored
`Mode=multihop` doesn't select multihop. Single-hop always requires a received
TTL/hop limit of 255 and rejects `MinTtl` and `Passive=1`. An optional
`InterfaceIndex` on another role still constrains incoming traffic to that
interface.

### Address validation

Give address syntax the Donatello treatment, dude. IPv6 addresses must be
literals such as `2001:db8::10`. Link-local addresses require `InterfaceIndex`;
do not add a `%scope` suffix.

For S-BFD, `Local`, `Peer`, and `AllowedPeers` must be usable unicast addresses.
IPv4 `0.0.0.0/8`, IPv4 `240.0.0.0/4`, and IPv4-mapped IPv6 addresses are
rejected, along with unspecified, multicast, and limited-broadcast addresses. `Peer`
and each allowed source must match `Local`'s address family and loopback scope:
use loopback sources with a loopback local address, and non-loopback sources
with a non-loopback local address. Reflectors don't read `Peer`.

With `PointToPoint=1`, outgoing packets still go to the configured `Peer`. Incoming packets must pass the destination, interface, TTL, source-port, discriminator, and authentication checks.

## Seamless BFD

Pick the S-BFD role for this ninja mission. Use these values to select an S-BFD
role and its target or source policy:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `SessionType` | `REG_SZ` | `classical` | `classical`, `sbfd-initiator`, or `sbfd-reflector` |
| `RemoteDiscriminator` | `REG_DWORD` | Required for an S-BFD initiator | Nonzero target entity identifier; invalid for other roles |
| `AllowedPeers` | `REG_SZ` | Absent | Comma-separated IP literals: additional initiator response sources, or a reflector request allowlist |
| `SbfdAdminDown` | `REG_DWORD` | `0` | Reflector only: `0` = Up replies; `1` = AdminDown replies; reloads while running |

S-BFD uses UDP `7784` for both single-hop and multihop paths. Leave `Multihop`
and `Passive` absent or `0` for these roles. A reflector requires an assigned
`Discriminator` and doesn't read `Peer`. For provisioning and the supported
use cases, see [Configure Seamless BFD](seamless.md).

`AllowedPeers` is unsupported for classical BFD. Omit it to use the default;
an empty string is an invalid IP list. An initiator always accepts its configured
target in addition to the listed sources. A reflector with no list accepts any
source that passes its transport, discriminator, and authentication checks.
Reflectors reject `BgpPeerName`, `SourcePort`, and `RemoteDiscriminator`.

## Timing

Bodacious timers need the right units, crew. Transmit (TX) and receive (RX)
intervals use microseconds. For S-BFD initiators, `MinRxUs` is a round-trip time
(RTT) allowance. These values control session timing:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `MinTxUs` | `REG_DWORD` | `300000` | Desired transmit interval while Up, 1–4294967295 microseconds |
| `MinRxUs` | `REG_DWORD` | `300000` | Required receive interval; S-BFD initiator RTT allowance, 1–4294967295 microseconds |
| `StartupTxUs` | `REG_DWORD` | `1000000` | Startup interval, at least one second; the base outside Up is `max(StartupTxUs, MinTxUs)` before congestion backoff |
| `DetectMult` | `REG_DWORD` | `3` | Advertised/local detection multiplier, 1–255; reflectors copy the request multiplier |
| `MaxShutdownAnnounceMs` | `REG_DWORD` | `30000` | Maximum classical AdminDown announcement period at shutdown, in milliseconds, 1–60000; read at startup |

Classical BFD intervals are **microseconds** before jitter:

```text
Transmit interval = max(local desired TX, peer required RX)
Detection time    = peer multiplier × max(local required RX, peer desired TX)
```

Periodic transmit intervals are randomly reduced by 0–25%, or 10–25% when the
local multiplier is 1. With matching 300000-microsecond intervals and multiplier
3, detection time is 900 ms. Gnarly scheduling reality: Windows adds latency;
the service does not guarantee microsecond timing.

For S-BFD, see [timing and live updates](seamless.md#change-timing-and-entity-availability).
For multihop timeout backoff and expired peer RX limits, see
[Classical session behavior](protocol.md#classical-session-behavior).

`MaxShutdownAnnounceMs` limits the longer of the two negotiated Detection Times
used for shutdown announcements. The default is 30 seconds. When that limit
truncates a Detection Time, the service logs a warning: it cannot guarantee that
the peer learns of the administrative stop before detecting a failure. This is
an operational limit on the RFC announcement recommendation, not a change to
the timers used while BFD runs. See [shutdown behavior](protocol.md#supported-modes-and-limits).

## Authentication

Ninja discipline starts with matching authentication settings. These values
select the authentication algorithm and key:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `Auth` | `REG_SZ` | `none` | `none`, `simple-password`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`, or `meticulous-sha1` |
| `AuthKeyId` | `REG_DWORD` | `0` | Key ID, 0–255 |
| `AuthKey` | `REG_SZ` | None | ASCII key |
| `AuthKeyHex` | `REG_SZ` | None | Hexadecimal encoding of a binary key: pairs of digits `0`–`9`, `a`–`f`, or `A`–`F`, with no signs or separators |

Get both ends in sync, dude: configure the same authentication type, key ID, and
key. Set exactly one of `AuthKey` and `AuthKeyHex` when authentication is
enabled. Password/MD5 keys are 1–16 bytes; SHA1 keys are 1–20 bytes. One key is
active at a time.

With `Auth=none`, omit both key values; a nonempty key fails validation. To change
from `AuthKey` to `AuthKeyHex`, remove the earlier value before restarting.

Classical multihop BFD with `BgpPeerName` requires `Auth=meticulous-md5` or
`meticulous-sha1` and a valid matching key. Other modes fail startup validation,
even when `MinTtl` is set. TTL filtering limits accepted network paths; it does
not authenticate a peer. Single-hop BGP without authentication logs a warning
because it depends on a trusted link.

### Configure an authenticated multihop session

For example, after setting `Local` and `Peer`, configure an authenticated multihop session:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name Multihop `
    -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path $parameters -Name Auth `
    -PropertyType String -Value 'meticulous-sha1' -Force
New-ItemProperty -Path $parameters -Name AuthKeyId `
    -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path $parameters -Name AuthKey `
    -PropertyType String -Value 'AUTH_KEY' -Force
```

Replace `AUTH_KEY` with a 1–20-byte ASCII key before running the commands in
PowerShell as Administrator. Configure the same key, ID, and algorithm on the
remote peer. PowerShell displays the values you set, including the authentication
key. Restart execution to load the values, then
[verify peer communication](setup.md#6-verify-peer-communication).

### Authentication behavior

Unauthenticated packets cannot establish an authenticated session, refresh its detection timer, or trigger a reply. All outgoing packets use the configured authentication. Classical keyed modes check digests and sequence windows, including wraparound and restart resynchronization. Authentication failures are logged regardless of `Verbose`; see [event 105](logging.md#operational-events).

S-BFD keyed authentication uses request sequence reflection and outstanding-probe
correlation instead of the classical receive window. See
[Authentication and loop prevention](seamless.md#authentication-and-loop-prevention).

These algorithms support [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html) interoperability. The RFC discourages MD5, and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html) recommends cryptographic authentication for multihop. Registry key contents are unencrypted. Preserve the MSI's Parameters ACL, including read access for the BFD service SID. Authentication keys never appear in logs or configuration errors.

## Logging and BGP

Keep the observation and control gear ready for the turtle team. These values
control text logging and integration with a Windows Border Gateway Protocol
(BGP) peer.

### Text logging

Keep the log receipts ready before pizza time. These values control text
logging:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `LogFilePath` | `REG_SZ` | `C:\ProgramData\BfdWinService\trace.log` | Append log path; use an absolute path under SCM |
| `LogToFile` | `REG_DWORD` | `0` | `0` = disable file output; `1` = enable file output |
| `Verbose` | `REG_DWORD` | `0` | Log generic packet discard reasons, at most once per second |

`LogFilePath` defaults to the literal path shown when absent. The MSI provisions
its value from the machine's ProgramData location; `Initialize-Logging.ps1`
resets it to the literal `C:\ProgramData` path. Logging values reload at startup.
File output rotates at 64 MiB with one `.1` backup; see
[log destinations and limits](logging.md#log-destinations).

### BGP target

Choose the intended target before you kick shell. These values select the
Windows BGP peer:

| Value | Type | Default | Meaning |
| --- | --- | --- | --- |
| `BgpPeerName` | `REG_SZ` | None | Enable control of this configured Windows BGP peer |
| `BgpRoutingDomain` | `REG_SZ` | Default routing domain | Optional domain; requires `BgpPeerName` |

Keep these names legit: both BGP names must contain a non-whitespace character.
Console execution rejects BGP control. Restart both installed services when
changing either BGP value so the BFD worker and broker use the same target. For
classical multihop sessions, configure
[meticulous keyed authentication](#authentication) before enabling
`BgpPeerName`.

For provisioning and verification, see [Logs and events](logging.md) and [Control a Windows BGP peer](bgp.md).
