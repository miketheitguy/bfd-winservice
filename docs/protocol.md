# Network and protocol behavior

Cowabunga, packet crew. Know the wire rules before rolling out. Network admins,
here's the playbook for Bidirectional Forwarding Detection (BFD)
interoperability, firewall requirements, and session limits. Get the network
details dialed in before you paddle out. For a fresh installation, see
[Set up a BFD session](setup.md).

The TL;DR, turtle crew: choose one protocol role per process, match the peer's
authentication, and allow the role's actual UDP traffic through your firewall.

Use [transport profiles](#transport-profiles-and-firewall-rules) to check the
network path, [classical session behavior](#classical-session-behavior) to check
timers and packet handling, and [administrative shutdown](#administrative-shutdown)
to check stop behavior.

## Protocol scope

Pick the supported mission before you kick shell. The implementation supports
asynchronous [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html) sessions,
[RFC 5881](https://www.rfc-editor.org/rfc/rfc5881.html) single-hop User Datagram
Protocol (UDP), and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html)
multihop. For the requirement mapping, regression evidence, and optional
features, see the [RFC 5880 conformance review](rfc5880-conformance.md).

IP-routed Seamless BFD (S-BFD) uses [RFC 7880](https://www.rfc-editor.org/rfc/rfc7880.html)
and [RFC 7881](https://www.rfc-editor.org/rfc/rfc7881.html). Its capabilities and
[RFC 7882](https://www.rfc-editor.org/rfc/rfc7882.html) use-case limits are documented
in [Configure Seamless BFD](seamless.md).

## Transport profiles and firewall rules

Channel Donatello and match the path to the port rules. The transport profiles
use these destination ports and received time-to-live (TTL) or IPv6 hop-limit
checks:

| Mode | Control destination port | Received TTL/hop limit |
| --- | --- | --- |
| Classical single-hop | UDP 3784 | Must be 255, including authenticated traffic |
| Classical multihop | UDP 4784 | Must meet `MinTtl` when configured |
| S-BFD initiator/reflector | UDP 7784 for requests; initiator source port for replies | Must meet `MinTtl` when configured |

All outgoing packets use TTL/hop limit 255. Classical sessions and S-BFD
initiators use a stable source port in 49152–65535. Reflectors reply from port
7784 to the request's source port. Classical traffic arrives on the profile's
control port through a separate receive socket; an S-BFD initiator receives
replies on its own source socket. Configure firewall rules for the chosen
transport. The service doesn't create them; the
[MSI installs executable-specific rules](setup.md#msi-firewall-rules) for all
supported roles. Manual installations need equivalent firewall provisioning.

## Control packet format

A bodacious packet still needs the exact header layout. Packets use the version
1, 24-byte mandatory header from
[RFC 5880 section 4.1](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.1).
The five 32-bit discriminator and interval fields use network byte order.
`Length` includes authentication: 24 bytes without authentication, 28–43 bytes
with a simple password, 48 bytes with MD5, or 52 bytes with SHA-1. Intervals are
in microseconds; the advertised multiplier is nonzero.

Header flag vibe check, for sure: the service sets them as follows:

| Flag | Transmit behavior |
| --- | --- |
| Poll (P) | Set on scheduled packets while a local Poll sequence is pending |
| Final (F) | Set when replying to a valid Poll; clears the wire Poll bit |
| Control Plane Independent (C) | Clear; the service shares fate with its control plane |
| Authentication Present (A) | Set exactly when an authentication section is present |
| Demand (D) | Clear for classical BFD and S-BFD reflectors; set for S-BFD initiators |
| Multipoint (M) | Clear |

Packets with both Poll and Final set, or with Multipoint set, are discarded
before state, timers, or authentication sequence tracking change. A received
diagnostic describes the peer; it doesn't replace the local diagnostic.
S-BFD's Demand flag follows
[RFC 7880 section 7.3.2](https://www.rfc-editor.org/rfc/rfc7880.html#section-7.3.2).
All roles advertise a zero Echo receive interval.

Reception also rejects unsupported versions, truncated or inconsistent lengths,
a zero multiplier, a zero sender discriminator, and a zero desired TX interval.
`Your Discriminator` can be zero only in Down or AdminDown. Trailing UDP padding
outside the declared BFD `Length` doesn't participate in authentication.

## States and diagnostics

Turtle power includes knowing what the state actually means. Classical BFD
starts in Down. The state machine follows
[RFC 5880 section 6.2](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.2).
Valid packets produce these local states:

| Previous local state | Peer AdminDown | Peer Down | Peer Init | Peer Up |
| --- | --- | --- | --- | --- |
| AdminDown | AdminDown | AdminDown | AdminDown | AdminDown |
| Down | Down | Init | Up | Down |
| Init | Down | Init | Up | Up |
| Up | Down | Down | Up | Up |

The implementation originates these local diagnostic values in control packets:

| Code | Reason | When emitted |
| --- | --- | --- |
| 0 | No local diagnostic | Initially; retained until a local failure or administrative stop |
| 1 | Receive detection expired | An Init/Up session's control detection timer expires |
| 3 | Peer signaled failure | Up receives Down, or Init/Up receives AdminDown |
| 7 | Local administrative stop | The service shuts down or a reflector enters maintenance |

Classical recovery retains the preceding failure diagnostic in Init and Up.
Repeated packets that leave the state unchanged don't replace that diagnostic.
S-BFD uses its [own state machine](seamless.md#3-verify-establishment): it
establishes directly from Down to Up, and a reflector AdminDown response can
move Up to Down while proving continued communication.
S-BFD clears its failure diagnostic when it transitions back to Up; RFC 7880
leaves initiator diagnostic policy to the implementation.

After validation and authentication, the session retains the peer's state and
raw diagnostic separately from the local reason. Operational and enabled file
logging report all four state values and assigned diagnostics 1–8, including
peer failures that leave the local state unchanged. Up and AdminDown state
events are Informational; Down and detection loss are Warnings. Diagnostic
events have their own severity policy; code 0 produces no standalone diagnostic
event. See the [event IDs and diagnostic levels](logging.md#operational-events).

## Classical session behavior

Keep the session rules totally tubular and explicit. Here's how classical
transmit (TX) and receive (RX) roll, buddy.

### Session ownership and packet acceptance

Sessions use these ownership and acceptance rules:

- One process runs one local/peer session. The receive address/port is exclusively bound; multiple peers sharing it are unsupported. Another process can use a different local address or transport profile.
- Incoming packets must pass peer/path metadata, discriminator, and authentication checks before affecting the session. Point-to-point mode permits source-address changes on the configured single-hop interface. Missing required receive metadata is discarded.

### Intervals and expiry

Ninja timing discipline starts with the negotiated intervals. The session
applies these timing rules:

- Outside Up, the base desired TX is `max(StartupTxUs, MinTxUs)`. Classical multihop doubles the greater of this base and its preceding negotiated interval after an unanswered discovery window or detection timeout. Backoff stops at the greater of 30 seconds and twice that base, bounded by the wire format's maximum interval. This allows even a slow peer's rate to decrease after loss. A valid peer packet clears backoff. Single-hop keeps the base interval.
- Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Both clocks use accepted, authenticated packets, including reception in AdminDown. Passive transmission stops when the learned discriminator expires.

### Poll sequences and state notifications

The session handles interval changes and state notifications as follows:

- Entering Up starts a Poll sequence when desired TX changes. A received Final completes only a Poll that has been transmitted. Valid peer timer changes are honored; timeouts move Init/Up to Down.
- State changes trigger immediate notifications when the active/passive role
  permits transmission, including when a zero peer RX interval suppresses
  periodic traffic. A Final reply can carry the changed state. Separate state
  notifications keep Poll clear; pending Poll sequences use scheduled packets.

### Socket recovery

A rough network day is a bummer, turtle crew; check the recovery policy. An
adapter reset or removed route is a bummer, but these transient network faults
don't stop the engine. Socket use pauses with a 10–250 millisecond backoff while
protocol timers continue, so an unusable path still expires detection. Other
socket errors end the engine; SCM then restarts the service.

## Supported modes and limits

Save the pizza celebration until the feature scope matches your deployment.
Scope check, no cap: classical sessions originate **asynchronous BFD mode**.
Classical Demand initiation, Echo, multipoint BFD, and out-of-band discriminator
signaling aren't implemented. This also excludes
[RFC 9747 Unaffiliated BFD Echo](https://www.rfc-editor.org/rfc/rfc9747.html).
S-BFD provides live timing updates and uses the Demand bit to identify
initiators.

### Periodic transmission and suppression

Classical periodic transmission stops when the peer advertises a zero required
RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is
pending. After one detection time without valid packets, the peer's required RX
interval resets to `1`, as recommended by RFC 5880 section 6.8.18. This removes
stale zero-RX suppression and lets active discovery resume. The last peer TX
interval and multiplier remain available for detection calculations. Accepted classical
Polls receive immediate Final replies unless local state is AdminDown; replies
do not postpone periodic transmissions. S-BFD initiators continue periodic
probing; reflectors answer requests and send no periodic packets.

## Administrative shutdown

Cowabunga, shutdown crew. Read the announcement and cleanup limits. For a mellow
exit, the service sends an immediate AdminDown notification and continues
permitted periodic announcements on normal classical shutdown with a
communicating peer for one Detection Time, up to `MaxShutdownAnnounceMs`, as
recommended by
[RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16)
and [RFC 5882 section 8](https://www.rfc-editor.org/rfc/rfc5882.html#section-8).
The period is the longer of the local Detection Time and the peer's Detection
Time for this system's packets, both measured before AdminDown. The announcement
limit defaults to 30 seconds and accepts 1–60000 milliseconds. If it truncates
the Detection Time, the service logs a warning; the peer might then classify the
stop as a failure. The installer sets a 125-second Windows preshutdown timeout
to cover the maximum announcement period, 60 seconds of cleanup, and final logs.
Zero-RX suppression and passive-role restrictions still apply to periodic
traffic. Without a communicating peer, after a fatal (non-transient) transport
error, or for an S-BFD initiator, shutdown attempts one role-permitted
notification. Passive sessions with no learned discriminator and S-BFD
reflectors send none. Shutdown leaves BGP eligible to run: local or received
AdminDown withdraws a Stop that this BFD controller imposed. A queued Stop can
be superseded by Start; a peer that BFD hasn't stopped remains unchanged.
Waiting for the final broker action can extend total shutdown. See
[BGP lifecycle policy](bgp.md).
