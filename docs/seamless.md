# Configure Seamless BFD

Cowabunga, S-BFD crew. Choose your part in the probe mission. Windows network
admins, let's catch the IP-routed Seamless Bidirectional Forwarding Detection
(S-BFD) wave. You can run a persistent initiator that probes a remote entity, or
a stateless reflector that answers probes.

The implementation uses [RFC 7880](https://www.rfc-editor.org/rfc/rfc7880.html)
for protocol behavior and [RFC 7881](https://www.rfc-editor.org/rfc/rfc7881.html)
for IPv4/IPv6 UDP transport. [RFC 7882](https://www.rfc-editor.org/rfc/rfc7882.html)
describes the use cases and requirements.

After completing [Before you begin](#before-you-begin), choose
[Configure an initiator](#configure-an-initiator) or
[Configure a reflector](#configure-a-reflector). For an existing deployment, see
[source filtering and anycast](#restrict-sources-and-support-anycast) or
[timing and entity availability](#change-timing-and-entity-availability).

## Before you begin

Before you send probes, get these prerequisites dialed in, buddy:

- Install the [setup bundle](setup.md#install-with-the-offline-setup-bundle).
- Open **PowerShell as Administrator**. These examples use
  `C:\Program Files\BfdWinService`; adjust the path for your installation.
- Assign a nonzero discriminator to the reflector's local entity. Coordinate
  assignments within your administrative domain to avoid unintended matches.
- Configure a routable local address and a route to the target. For link-local
  IPv6, also set `InterfaceIndex`.
- Allow initiator traffic to User Datagram Protocol (UDP) port `7784`, and
  replies from `7784` to each initiator's selected source port.
- Stop an existing `BfdWinService` before changing its role or startup settings.
  Remove values that are invalid for the selected role before starting it.

For Windows service execution, the bundle creates the service and registers the
Operational log. Configure one of the roles in this guide before starting the
service. Each process runs one role. Loose files alone do not provision the
service identities or access policies required for service execution.

## Configure an initiator

Time for the turtle team to send the probes. On the node sending probes to a
provisioned reflector, this is your line to ride.

### 1. Provision the target and discriminators

Set the initiator's addresses and the reflector's provisioned discriminator:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
$localIp = 'LOCAL_IP'
$targetIp = 'TARGET_IP'
$localDiscriminator = [uint32]'LOCAL_DISCRIMINATOR'
$remoteDiscriminator = [uint32]'REFLECTOR_DISCRIMINATOR'

New-Item -Path $parameters -Force
New-ItemProperty -Path $parameters -Name SessionType `
    -PropertyType String -Value 'sbfd-initiator' -Force
New-ItemProperty -Path $parameters -Name Local `
    -PropertyType String -Value $localIp -Force
New-ItemProperty -Path $parameters -Name Peer `
    -PropertyType String -Value $targetIp -Force
New-ItemProperty -Path $parameters -Name Discriminator `
    -PropertyType DWord -Value $localDiscriminator -Force
New-ItemProperty -Path $parameters -Name RemoteDiscriminator `
    -PropertyType DWord -Value $remoteDiscriminator -Force
```

Replace these placeholders before running the commands:

- `LOCAL_IP`: the initiator's local IPv4 or IPv6 address.
- `TARGET_IP`: the reflector's address, of the same address family.
- `LOCAL_DISCRIMINATOR`: a nonzero identifier unique among your node's initiators
  and classical sessions.
- `REFLECTOR_DISCRIMINATOR`: the identifier assigned to the target entity.

The commands display the registry keys and values they create.

Leave `Multihop` and `Passive` absent or `0`. S-BFD uses its own transport for
both single-hop and multihop paths.

### 2. Start the initiator

Start the configured service:

```powershell
Start-Service BfdWinService
```

A successful command produces no output. BFD runs only through SCM.

### 3. Verify establishment

Follow [Verify peer communication](setup.md#6-verify-peer-communication). Event
`100` marks a valid response, and event `102` marks `Up`. The first valid `Up`
response establishes the session without entering `Init`. Cowabunga! That
response is your establishment receipt.

The initial request already contains `RemoteDiscriminator`. No discriminator
exchange or routing-protocol advertisement is required by the service. The
establishment vibe check is one valid `Up` response; an `AdminDown` response
proves communication while the entity remains unavailable.

For operator checks and the broker's private telemetry contract, see
[Available monitoring interfaces](monitoring.md#available-monitoring-interfaces).

## Configure a reflector

Keep the reply side totally tubular, dude. On the node answering initiator
probes, follow this procedure and keep it, like, totally mellow.

### 1. Provision the local entity

On the responder machine, set the local address and discriminator:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
$localIp = 'LOCAL_IP'
$discriminator = [uint32]'REFLECTOR_DISCRIMINATOR'

New-Item -Path $parameters -Force
New-ItemProperty -Path $parameters -Name SessionType `
    -PropertyType String -Value 'sbfd-reflector' -Force
New-ItemProperty -Path $parameters -Name Local `
    -PropertyType String -Value $localIp -Force
New-ItemProperty -Path $parameters -Name Discriminator `
    -PropertyType DWord -Value $discriminator -Force
```

Replace `LOCAL_IP` with the reflector's local address and
`REFLECTOR_DISCRIMINATOR` with its assigned nonzero identifier.
The registry commands display the keys and values they create.

The reflector doesn't require `Peer`. It answers multiple initiators through
one listener and retains no per-initiator timers or authentication windows.
`RemoteDiscriminator`, `SourcePort`, and `BgpPeerName` are invalid for this role.
Its runtime still retains bounded per-source counters to limit reflected traffic.

### 2. Start the listener

Start the configured service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success. The reflector listens on
`Local:7784`; it sends no periodic packets.

### 3. Verify replies

Configure an initiator to target this entity and confirm that the initiator
reaches `Up`. Reflector service startup alone doesn't verify a network path.
Reflectors emit service lifecycle, authentication-failure, and local entity
state events. They remain stateless for peers and don't emit per-peer
communication, state, or diagnostic events. See the
[Operational event reference](logging.md#operational-events).

Each reply reverses the request's discriminator pair and returns to its source
IP address and UDP port. The reply source is the bound local address and port
`7784`, with IP time-to-live (TTL) or IPv6 hop limit `255`. A Windows return-route
lookup must succeed before the reply is sent.

## Restrict sources and support anycast

Channel Donatello: check which sources belong in this setup. Choose who gets
past the source-filter vibe check with `AllowedPeers`:

- On an initiator, `Peer` is always accepted. `AllowedPeers` adds permitted
  response sources, including individual nodes serving an anycast target.
- On a reflector, an absent `AllowedPeers` permits routable unicast sources.
  When present, the list restricts requests to those addresses.

The configured `Peer` and `AllowedPeers` addresses must match `Local`'s address
family and loopback scope. A loopback listener accepts loopback sources;
a non-loopback listener accepts non-loopback sources. Reserved IPv4 and
IPv4-mapped IPv6 addresses are rejected during startup.

For an initiator targeting an anycast address, add the member addresses that can
originate replies:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name AllowedPeers `
    -PropertyType String -Value 'MEMBER_IPS' -Force
```

Replace `MEMBER_IPS` with comma-separated IPv4 or IPv6 literals, such as
`192.0.2.20,192.0.2.21`, of the local address family. Restart the service to
load this setting. PowerShell displays the `AllowedPeers` value.

Every responding member must serve the configured target discriminator and
authentication settings. Changing the permitted response source doesn't reset
the initiator's state or create a separate session.

## Authentication and loop prevention

Turtle power needs authentication and loop checks. Configure matching `Auth`,
`AuthKeyId`, and a DPAPI-protected key in `Secrets\AuthKeyDpapi` using the
[authentication reference](configuration.md#authentication). Simple-password,
both SHA-1 modes, and meticulous keyed MD5 are available.

### Keyed probe correlation

Bodacious replies still need to match the outstanding probe. Replay check, dude:
a keyed reflector verifies the digest and returns the request's sequence number
with a newly computed digest. It doesn't apply a sequence window to incoming
requests. An initiator accepts a keyed response only for an outstanding,
unexpired transmitted sequence and consumes it once, including across
wraparound. The Windows runtime records probes only after a successful socket
send. Tracking is bounded to the newest 1,024 transmitted keyed probes. Choose
rates and round-trip budgets that keep the number of outstanding probes within
this bound.

### Role and port checks

Ninja discipline keeps the request and reply roles straight. Initiators send
Demand=1 and accept only Demand=0 responses. Reflectors accept only Demand=1
requests and send Demand=0 responses. Reflectors also reject source ports `0`
and `7784`, preventing reflector-to-reflector loops. Invalid packets never
refresh liveness or cause a response. Authentication failures use Operational
event `105`.

### Reflection limits

Keep the reply traffic under control before the pizza party. A reflector answers
at most 1,000 valid requests per second from any one source address. The limiter
tracks at most 4,096 source addresses in a one-second window; additional sources
receive no reply until the window resets. These are runtime traffic limits, not
per-peer BFD sessions. Keep that distinction straight, dude. The service reports
withheld replies with Warning event 4. Without `AllowedPeers`, startup also logs
Warning event 4.

## Change timing and entity availability

Cowabunga, maintenance crew. Check which settings can change live. Rad, S-BFD
supports live timing updates and reflector maintenance without restarting the
session. Other settings retain their startup-only behavior.

### Registry reload behavior

In S-BFD service execution, `MinTxUs`, `MinRxUs`, `DetectMult`, and
the reflector's `SbfdAdminDown` are reloaded when a registry change notification
reports a write to the Parameters key; if notification is unavailable, they are
read once per second. Valid changes apply without restarting or resetting the
session. Invalid values and Up initiator wire-timing changes that overlap a
transmitted Poll leave the preceding settings active and produce a text
diagnostic. Rejected updates are retried once per second until they apply,
including after a Poll completes;
another registry write is not required. Each retry reads the latest requested
values, and repeated rejection diagnostics are limited to once per minute.
Other registry settings are read
at startup.

### Initiator probe and detection timing

An initiator uses `MinRxUs` as its expected round-trip time (RTT) allowance. Choose a value
that covers the path's latency and responder scheduling delay. Before jitter,
timing follows these formulas:

```text
Probe interval = max(effective local TX, reflector required RX)
Detection time = local DetectMult × probe interval + local MinRxUs
```

Outside `Up`, the initial desired interval is `max(StartupTxUs, MinTxUs)`.
After missing responses, the initiator doubles its probing interval to reduce
traffic. Backoff stops at the greater of 30 seconds and twice the base interval,
where the base includes the reflector's advertised receive limit. The wire
format's maximum interval bounds this calculation. A slow reflector therefore
still receives fewer probes after loss. A valid response clears this backoff.

### Poll sequence protection

Poll/Final exchanges acknowledge interval changes without adding an `Init` phase.
When `MinTxUs` increases in Up, probes advertise the requested value but continue
at the preceding local TX rate until the Poll receives a Final. The probe and
detection calculations use that effective rate while acknowledgement is pending.
Another wire timer change waits for both the Final and a subsequent response
with Final clear, preventing an older Final from acknowledging a newer change.
Changes combined before the first Poll transmission share that Poll.

### Put a reflector in maintenance

Give the reflector a planned break, turtle crew. For a maintenance break that
keeps the listener active, set the reflector's maintenance flag to mark the
entity temporarily unavailable:

```powershell
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
New-ItemProperty -Path $parameters -Name SbfdAdminDown `
    -PropertyType DWord -Value 1 -Force
```

PowerShell displays the `SbfdAdminDown` value. After the reload, the
reflector responds with `AdminDown`. Initiators remain in communication, enter
`Down`, and send no faster than once per second, including after jitter.
This state indicates entity maintenance rather than loss of reachability.
Set the DWORD to `0` to restore `Up` replies.

Entering reflector maintenance emits Informational state event 106 and Warning
diagnostic event 207. Restoring the entity emits Informational Up event 102.
Administrative shutdown uses the same AdminDown events if the entity wasn't
already in maintenance. These records go to the Operational
channel and the file when enabled.

For library callers, see [S-BFD timing APIs](development/library.md#s-bfd-library-timing-apis).

## RFC 7882 use-case coverage and limits

A totally tubular deployment still stays within the implemented scope. The IP
implementation provides these capabilities:

| Requirement | Implementation |
| --- | --- |
| 1–3: discriminator lookup and establishment without negotiation | Configured entity lookup and first-response establishment |
| 4: controller-initiated monitoring in segment-routed networks | IP initiator API available; controller and segment-selection integration required |
| 5: change parameters without resetting state | Live registry timers and library timing APIs |
| 6: anycast responses without separate sessions | Additional permitted response sources share the configured entity |
| 7: fault isolation | Timeout and maintenance diagnostics; no transit-hop probing |
| 8: multiple sessions between a source/target pair | Library initiators bind distinct source ports and use unique local discriminators |
| 9–10: loop prevention and security | Demand/port checks, address filtering, return-route checks, and authentication |

The service provides IP-routed S-BFD. Native MPLS label stacks, segment-routing
encapsulation, forwarding-plane TTL-expiry delivery, S-BFD Echo, and discriminator
advertisement through routing protocols aren't implemented. These require
additional network or forwarding-plane integration. Classical BFD and S-BFD
use separate ports and can coexist where their local bindings are available.

## Next steps

For all registry types and defaults, see the
[configuration reference](configuration.md#seamless-bfd).
For deployment checks, see [Monitor service status and BFD events](monitoring.md).
