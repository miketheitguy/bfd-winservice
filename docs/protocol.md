# Network and protocol behavior

This reference is for network administrators checking Bidirectional Forwarding Detection (BFD) interoperability, firewall requirements, and session limits. For a fresh installation, see [Set up a BFD session](setup.md).

The implementation follows [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html), [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881.html) for single-hop User Datagram Protocol (UDP), and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html) for multihop.

IP-routed Seamless BFD (S-BFD) uses [RFC 7880](https://www.rfc-editor.org/rfc/rfc7880.html)
and [RFC 7881](https://www.rfc-editor.org/rfc/rfc7881.html). Its capabilities and
[RFC 7882](https://www.rfc-editor.org/rfc/rfc7882.html) use-case limits are documented
in [Configure Seamless BFD](seamless.md).

The transport profiles use these destination ports and received time-to-live (TTL) or IPv6 hop-limit checks:

| Mode | Control destination port | Received TTL/hop limit |
| --- | --- | --- |
| Classical single-hop | UDP 3784 | Must be 255, including authenticated traffic |
| Classical multihop | UDP 4784 | Must meet `MinTtl` when configured |
| S-BFD initiator/reflector | UDP 7784 for requests; initiator source port for replies | Must meet `MinTtl` when configured |

All outgoing packets use TTL/hop limit 255. Classical sessions and S-BFD
initiators use a stable source port in 49152–65535. Reflectors reply from port
7784 to the request's source port. Configure firewall rules for the chosen
transport; the service doesn't create them.

## Control packet format

Packets use the version 1, 24-byte mandatory header from
[RFC 5880 section 4](https://www.rfc-editor.org/rfc/rfc5880.html#section-4).
The five 32-bit discriminator and interval fields use network byte order.
`Length` includes authentication: 24 bytes without authentication, 28–43 bytes
with a simple password, 48 bytes with MD5, or 52 bytes with SHA-1.
Intervals are in microseconds; the advertised multiplier is nonzero.

The service sets the header flags as follows:

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

## States and diagnostics

Classical BFD starts in Down. Valid packets produce these local states:

| Previous local state | Peer AdminDown | Peer Down | Peer Init | Peer Up |
| --- | --- | --- | --- | --- |
| AdminDown | AdminDown | AdminDown | AdminDown | AdminDown |
| Down | Down | Init | Up | Down |
| Init | Down | Init | Up | Up |
| Up | Down | Down | Up | Up |

Local diagnostics use these values:

| Code | Reason | When emitted |
| --- | --- | --- |
| 0 | No local diagnostic | Initially and after successful establishment |
| 1 | Receive detection expired | Control packets stop arriving within the detection interval |
| 3 | Peer signaled failure | Up receives Down, or Init/Up receives AdminDown |
| 7 | Local administrative stop | The service shuts down |

Classical Init recovery retains the preceding failure diagnostic until Up.
Repeated packets that leave the state unchanged don't replace that diagnostic.
S-BFD uses its [own state machine](seamless.md#3-verify-establishment): it
establishes directly from Down to Up, and a reflector AdminDown response can
move Up to Down while proving continued communication.

## Classical session behavior

Transmit (TX) and receive (RX) behavior follows these rules:

- One process runs one local/peer session. The receive address/port is exclusively bound; multiple peers sharing it are unsupported. Another process can use a different local address or transport profile.
- Incoming packets must pass peer/path metadata, discriminator, and authentication checks before affecting the session. Point-to-point mode permits source-address changes on the configured single-hop interface. Missing required receive metadata is discarded.
- Outside Up, desired TX is `max(StartupTxUs, MinTxUs)`. Entering Up starts a Poll sequence when this interval changes. Valid peer timer changes are honored; timeouts move Init/Up to Down.
- Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Passive transmission stops when the learned discriminator expires.
- State changes trigger immediate notifications when the active/passive role
  permits transmission, including when a zero peer RX interval suppresses
  periodic traffic. A Final reply can carry the changed state. Separate state
  notifications keep Poll clear; pending Poll sequences use scheduled packets.

## Supported modes and limits

Classical sessions originate **asynchronous BFD mode**. Classical Demand
initiation, Echo, and out-of-band discriminator signaling aren't implemented.
S-BFD provides live timing updates and uses the Demand bit to identify initiators.

Classical periodic transmission stops when the peer advertises a zero required
RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is
pending. A timeout retains the peer's last timer parameters. Accepted classical
Polls receive immediate Final replies unless local state is AdminDown; replies
do not postpone periodic transmissions. S-BFD initiators continue periodic
probing; reflectors answer requests and send no periodic packets.

Shutdown attempts one packet when transmission is permitted. Passive sessions
with no learned remote discriminator and S-BFD reflectors send none.
Classical shutdown differs from the recommendation to transmit for a detection
period in [RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16).
