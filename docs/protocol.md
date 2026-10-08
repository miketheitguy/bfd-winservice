# Network and protocol behavior

This reference is for network administrators checking Bidirectional Forwarding Detection (BFD) interoperability, firewall requirements, and session limits. For a fresh installation, see [Set up a BFD session](setup.md).

The implementation follows [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html), [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881.html) for single-hop User Datagram Protocol (UDP), and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883.html) for multihop.

The transport profiles use these destination ports and received time-to-live (TTL) or IPv6 hop-limit checks:

| Mode | Control destination port | Received TTL/hop limit |
| --- | --- | --- |
| Single-hop | UDP 3784 | Must be 255, including authenticated traffic |
| Multihop | UDP 4784 | Must meet `MinTtl` when configured |

All outgoing packets use TTL/hop limit 255 and a stable source port in 49152–65535. Allow traffic from that source range to the control destination port in both directions. Firewall rules must be configured separately.

## Session behavior

Transmit (TX) and receive (RX) behavior follows these rules:

- One process runs one local/peer session. The receive address/port is exclusively bound; multiple peers sharing it are unsupported. Another process can use a different local address or transport profile.
- Incoming packets must pass peer/path metadata, discriminator, and authentication checks before affecting the session. Point-to-point mode permits source-address changes on the configured single-hop interface. Missing required receive metadata is discarded.
- Outside Up, desired TX is `max(StartupTxUs, MinTxUs)`. Entering Up starts a Poll sequence when this interval changes. Valid peer timer changes are honored; timeouts move Init/Up to Down.
- Learned remote discriminators expire after one detection time; keyed sequence tracking can resynchronize after two. Passive transmission stops when the learned discriminator expires.

## Supported modes and limits

The service originates **asynchronous BFD mode**. Local Demand initiation, Echo, out-of-band discriminator signaling, and live configuration APIs are unsupported.

Periodic transmission stops when the peer advertises a zero required RX interval, or when both ends are Up, the peer sets Demand, and no local Poll is pending. A timeout retains the peer's last timer parameters. Accepted Polls receive immediate Final replies unless local state is AdminDown; replies do not postpone periodic transmissions.

Shutdown attempts one packet when transmission is permitted. Passive sessions with no learned remote discriminator send none. This differs from the recommendation to transmit for a detection period in [RFC 5880 section 6.8.16](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.16).
