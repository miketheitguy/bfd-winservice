# BFD authentication processing cost

Cowabunga, packet crew. Use this reference to compare authentication work before
choosing a mode. For supported modes and security limits, see
[packet authentication](packet-authentication.md#authentication-modes); for
keys, see [authentication configuration](../configuration.md#authentication).

## Mode selection

Choose a mode supported by both peers. Meticulous keyed MD5 is available for
compatibility or a measured performance constraint; non-meticulous MD5 is
unsupported. Within this service's RFC 5880 profile, prefer meticulous SHA-1
when both peers support it with sufficient headroom.
[RFC 5880 section 4.3](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.3)
discourages MD5;
[RFC 9985](https://www.rfc-editor.org/rfc/rfc9985.html#section-1) describes
limitations of both MD5 and SHA-1. Sequence checks don't remove those algorithm
limitations.

## Hash cost and sequence frequency

The classical sender performs this work:

| Mode | Sequence policy | Outgoing digest work |
| --- | --- | --- |
| `keyed-sha1` | Repeated sequences permitted within the receive window | Reuses an unchanged successfully sent packet for less than one second; changes or expiry require a new digest |
| `meticulous-sha1` | Every packet advances the sequence; repeated receives rejected | Fresh SHA-1 digest per transmitted packet |
| `meticulous-md5` | Same meticulous sequence progression | Fresh MD5 digest per transmitted packet |

The [classical sender](../../src/session.rs) caches only its last successful
keyed-SHA1 transmission. State, Poll/Final, diagnostic, discriminator, or timing
changes invalidate reuse, including state changes that return to identical
contents. Reuse doesn't extend expiry. The next successful send after expiry
advances once; idle time doesn't skip sequence numbers. Failed sends commit
neither a sequence nor a cache entry.

The one-second limit is implementation policy under
[RFC 5880 section 6.7.4](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.7.4).
The cache belongs to one session with immutable authentication settings. A new
session starts empty. Reuse trades computation for replay exposure within the
window; it doesn't provide meticulous protection or satisfy the classical
multihop BGP requirement for meticulous authentication.

Keyed receive traffic still requires per-packet verification. S-BFD
initiators use unique outstanding-probe sequences even with keyed SHA1;
reflectors authenticate each request and sign each reply.

## Measure before tuning

CPU instructions, hash backend, VM scheduling, peer load, and packet intervals
affect cost. This guide provides no comparative Windows benchmark. Measure CPU
use on both ends, loss, scheduling delay, and unexpected Down events with equal
intervals and representative load before choosing MD5 for performance.

Meticulous MD5 packets are 48 bytes; SHA-1 packets are 52 bytes, before
transport headers. That difference and large-buffer hash benchmarks don't
establish a useful saving for short BFD packets. At 300 ms with multiplier 3,
the multiplier changes loss tolerance, not packets per transmit interval. Check
the peer's platform-specific mode and failover restrictions separately.
