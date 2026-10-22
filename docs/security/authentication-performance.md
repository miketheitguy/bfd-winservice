# BFD authentication performance and mode selection

Cowabunga, packet crew. This guide helps Windows operators and maintainers
compare keyed SHA-1, meticulous keyed SHA-1, and meticulous keyed MD5 before
choosing a BFD authentication mode. For keys and registry values, see
[authentication configuration](../configuration.md#authentication).

## Why meticulous keyed MD5 is available

Meticulous keyed MD5 restores a choice for peer compatibility and deployments
where measurements show a better CPU or timing margin with MD5. It retains
per-packet sequence progression and rejects repeated sequences in established
classical sessions. Only meticulous MD5, wire type 3, is restored;
non-meticulous MD5 stays unsupported.

This is an interoperability and deployment tradeoff, dude. Within the service's
supported RFC 5880 profile,
prefer meticulous SHA-1 when both ends support it with sufficient headroom.
[RFC 5880 section 4.3](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.3)
discourages MD5, and [RFC 9985 section 1](https://www.rfc-editor.org/rfc/rfc9985.html#section-1)
notes the cryptographic limitations of both MD5 and SHA-1. Meticulous sequence
handling doesn't remove those algorithm limitations.

## Hash cost and sequence frequency

SHA-1 is the hash algorithm used by both `keyed-sha1` and `meticulous-sha1`.
Meticulous operation changes sequence requirements, not the hash algorithm.
[RFC 5880 section 9](https://www.rfc-editor.org/rfc/rfc5880.html#section-9)
describes the tradeoff between sequence updates, computation, and replay
exposure. The classical BFD modes differ as follows:

| Mode | Classical sequence behavior | Performance implication |
| --- | --- | --- |
| Keyed SHA-1 (`keyed-sha1`) | Repeated sequences are permitted within the receive window. | Classical sessions reuse an unchanged transmitted packet and its digest for less than one second. Changes or expiry require a new digest. |
| Meticulous keyed SHA-1 (`meticulous-sha1`) | Every transmitted packet advances the sequence; repeated receive sequences are rejected. | Changing the sequence requires a fresh SHA-1 digest for each transmitted packet. |
| Meticulous keyed MD5 (`meticulous-md5`) | Uses the same strict sequence progression as meticulous SHA-1. | Each transmitted packet requires a fresh MD5 digest. It retains per-packet work; any CPU advantage depends on the implementation and processor. |

The [classical session sender](../../src/session.rs) caches only the last
successfully transmitted keyed-SHA1 packet. It reuses those wire bytes while
the control fields match and the cache is less than one second old. State
changes invalidate the cache, including transitions that return to the
previous state before another send. Poll/Final, diagnostic, discriminator, or
timing changes require a new sequence and digest. Reuse doesn't extend the
cache lifetime. The next successful send after expiry advances once; idle
time doesn't skip sequence numbers. Failed sends don't commit a new sequence
or cache entry.

The one-second limit is this service's policy. [RFC 5880 section 6.7.4](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.7.4)
leaves non-meticulous sequence frequency to the implementation and recommends
advancing it when state or transmitted contents change. The cache belongs to
one session with immutable authentication settings; it contains transmitted
bytes, not the key. Reconstructing the session for a different key starts with
an empty cache.

The [packet codec](../../src/packet.rs) still verifies each candidate accepted
keyed packet. Both meticulous modes calculate a fresh outgoing digest per
packet. S-BFD initiators also keep per-probe sequences, even with keyed SHA1,
so an accepted reply consumes one unique outstanding probe. Stateless
reflectors continue to authenticate each request and sign each reply.

Reusing keyed-SHA1 packets trades computation for replay exposure within the
sequence window. It doesn't provide meticulous replay protection or satisfy
the service's multihop BGP requirement for meticulous authentication.

## What affects performance

Per-packet authentication can become costly at short intervals or with many
sessions competing for a router's CPU. [RFC 7492 section 5](https://www.rfc-editor.org/rfc/rfc7492.html#section-5)
identifies that scaling problem; [RFC 9985 section 1](https://www.rfc-editor.org/rfc/rfc9985.html#section-1)
also explains the cost of software authentication and the effect of hardware
acceleration. RFC 9985 defines an experimental optimization, which this service
doesn't implement. Restoring MD5 doesn't add that optimization.

[Juniper's BFD authentication documentation](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/bfd-for-bgp-session.html)
also describes additional authentication time for both meticulous modes
relative to their non-meticulous variants. That observation doesn't establish
a speed ranking between meticulous MD5 and meticulous SHA-1 on Windows.

Hash speed depends on the available CPU instructions and library backend.
[Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)
accelerate SHA-1, and the service's [RustCrypto SHA-1 library](https://docs.rs/sha1/0.10.7/sha1/)
supports hardware-specific optimizations. Consequently, a generic claim that
MD5 is faster doesn't establish which mode performs better on your host or VM.

The service emits 48-byte BFD packets with meticulous MD5 and 52-byte packets
with either SHA-1 mode, before transport headers. Those four bytes alone don't
establish a useful CPU or bandwidth saving. Large-buffer hash throughput
figures also don't directly measure these short packets or scheduling delays.

## When meticulous MD5 may fit better

Keep the choice tied to your actual peers, turtle crew:

| Scenario | Reason to consider meticulous MD5 |
| --- | --- |
| A deployed peer supports or is qualified for meticulous MD5 but has no usable meticulous SHA-1 configuration. | The peers can use a matching authenticated mode while retaining meticulous sequence checks. |
| A constrained CPU, older device, or VM has a demonstrably cheaper MD5 path. | Choose it only when representative measurements show better CPU headroom or fewer missed timing deadlines and your deployment permits MD5. Lack of SHA acceleration alone doesn't prove an advantage. |
| A busy peer serves many BFD sessions at short intervals. | A measured per-packet saving can matter across the peer's workload. This service runs one session per process; the remote router's aggregate load also matters. |

Both meticulous modes retain sequence-state costs. For example, Juniper
documents [nonstop active routing (NSR) restrictions](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/bfd-for-bgp-session.html)
for both modes. Cisco documents [in-service software upgrade (ISSU) and stateful switchover (SSO) restrictions](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bfd/configuration/xe-16/irb-xe-16-book/irb-bfd-shop-auth.html).
Switching to MD5 doesn't by itself solve those peer failover limitations; check
the exact model and software release.

Before choosing for performance, compare CPU use on both ends, packet loss,
scheduling delays, and unexpected BFD Down events at the same intervals and
representative load. At 300 ms with multiplier 3, the multiplier changes loss
tolerance, not the number of packets sent per interval. No comparative Windows
or VM performance benchmark is recorded for this restoration. For setup and
functional verification, see [Set up a BFD session](../setup.md).
