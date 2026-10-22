# RFC conformance tests

Cowabunga, conformance crew. Tie each claim to the behavior exercised.
Maintainers and network admins, let's check the protocol receipts. This
reference helps you check BFD protocol behavior. It maps the service's
implemented profile to [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html),
[RFC 7419](https://www.rfc-editor.org/rfc/rfc7419.html), and
[RFC 7880](https://www.rfc-editor.org/rfc/rfc7880.html), records regression
coverage, and explains what passing tests establish.

The service implements classical asynchronous BFD and a persistent S-BFD
initiator or stateless reflector, with one role per process. Echo, locally
initiated classical Demand mode, routing-protocol advertisement of S-BFD
discriminators, and forwarding-plane reset notifications require additional
integration. Tests cover the rules applicable to the implemented profile;
passing them doesn't certify every optional feature or deployment.

Cowabunga for passing tests, dude. Treat them as receipts for the behavior they
exercise. Multipoint BFD from
[RFC 8562](https://www.rfc-editor.org/rfc/rfc8562.html) and Unaffiliated BFD
Echo from [RFC 9747](https://www.rfc-editor.org/rfc/rfc9747.html) are outside
the implemented profile.

To execute the suites, see [Run and interpret validation](#run-and-interpret-validation).
For a section-by-section implementation review of the base protocol, see
[RFC 5880 conformance review](rfc5880-conformance.md).

## RFC 5880: base protocol

Give the base protocol the Donatello treatment, dude. For the complete section
mapping, see the [RFC 5880 conformance review](rfc5880-conformance.md). The
tests exercise this lineup of boundary conditions and protocol behaviors:

| Sections | Requirement checked | Evidence |
| --- | --- | --- |
| 4, 6.8.6, 6.8.7 | Fixed header layout, network byte order, version, lengths, flags, nonzero sender discriminator and multiplier | Independent byte and digest fixtures in `src/packet.rs`; truncated headers, inconsistent declared lengths, and incomplete authentication sections in `tests/rfc5880.rs` |
| 6.1–6.3, 6.8.1, 6.8.6 | Active/passive startup, all four classical states, discriminator selection and retention | All 16 local/remote state combinations in `src/session.rs`; authenticated AdminDown validity clocks and expired zero-RX recovery in `tests/rfc5880.rs` |
| 6.5, 6.8.3, 6.8.6–6.8.7 | Scheduled Polls, independent Final replies, acknowledgement of transmitted Polls, safe interval changes | Unsent-Poll and held-TX tests in `tests/rfc5880.rs`; failed-send preparation in `src/session.rs`; native Poll flood and scheduling tests in `tests/windows_udp.rs` |
| 6.6, 6.8.7 | Peer Demand and zero-RX suppress periodic traffic while valid Polls can receive Final | Session and native UDP tests; local classical D stays clear. Local Demand initiation is outside the implemented profile. |
| 6.7.2, 6.7.4 | Password, both SHA-1 variants, key selection, digest verification, and circular replay windows | `src/packet.rs` fixtures and all key lengths; `tests/rfc5880.rs` checks both keyed types at multipliers 1, 3, and 255, including wraparound, repeated sequences, both window endpoints, and the first value outside each window. MD5 modes are unsupported and rejected. |
| 6.7.4, 6.8.1 | Invalid authentication cannot seed or advance receive sequence state; resynchronization starts only after two detection periods | Regression tests for the SHA-1 sequence-commitment correction; exact nanosecond boundary after a prior session expiry. Successful-send sequence wraparound is checked for both keyed types. |
| 6.8.2–6.8.4, 6.8.12 | TX and RX negotiate independently; peer multiplier changes apply without waiting for Poll completion | Asymmetric 700 ms TX / 1,750 ms detection fixture; multiplier reduction gives a 250 ms deadline, with expiry at that exact instant and no expiry one nanosecond earlier |
| 6.8.3, 6.8.7 | Peer RX changes update the existing transmission schedule | Native UDP regression reduces RX from 1 s to 100 ms after the new deadline is already due, then restores 1 s and checks that the fast schedule is cancelled |
| 6.8.6, 9 | Discarded keyed packets cannot change state, remote parameters, deadlines, Poll state, or authentication tracking | Every individual bit of each authenticated SHA-1 packet is flipped and rejected; the legitimate next sequence still succeeds afterward. Legacy MD5 types are rejected without changing session state or refreshing detection. |
| 6.8.16 | AdminDown notifications continue during the negotiated grace period | Native UDP tests cover repeated announcements, both detection directions, and the configured shutdown limit with its warning; `src/bgp.rs` tests release of BFD-imposed Stop on either end's administrative disable |
| 7, 9 | Congestion reduces multihop traffic; path metadata and authentication protect session input | Slow-peer loss regressions in `tests/rfc5880.rs`; IPv4/IPv6 TTL, source, interface, and destination tests in `src/transport.rs` and native UDP suites |

Classical local timers are startup-only, so the live local RX-decrease rule
doesn't have a runtime mutation path to exercise. S-BFD's `MinRxUs` is a local
round-trip allowance; its initiator wire RX field remains zero. A change to that
allowance therefore isn't a change to the classical advertised RX parameter.

The [verified RFC 5880 errata](https://www.rfc-editor.org/errata_search.php?rec_status=0&rfc=5880)
clarify sequence increments, sequence commitment after digest verification, and
the remote-state variable's name. Held or rejected errata don't override the
published requirements; their interpretation is recorded in the detailed review.

## RFC 7419: common intervals

Bodacious timer choices still follow the interval guidance. Timer vibe check,
like, for real: RFC 7419 is an informational update that recommends common timer
values; it doesn't impose a new timer-precision requirement. Section 3 defines
3.3, 10, 20, 50, and 100 ms, plus 1 s. It also recommends 10 s and multipliers
through 255 for graceful restart. Appendix B discusses peers restricted to
different discrete sets of supported intervals.

[rfc7419.rs](../tests/rfc7419.rs) checks:

- Every pair of the six common intervals and the additional 10 s interval:
  advertisements keep their exact microsecond values and negotiation uses the
  slower supported value in each direction.
- All multiplier values 1–255. A 10 s interval with multiplier 255 gives a
  2,550 s detection period. Maximum-width wire intervals also calculate without
  truncating the detection period to 32-bit microseconds.
- Values outside the common set, including 200/300 ms and 3,300/3,333 us. The
  continuous timer representation accepts these without escalating to 1 s.
- Jitter at every interval: 75–100% normally and 75–90% with local multiplier 1.

These tests establish advertisement, negotiation, arithmetic, and jitter
calculation. They don't establish 3.3 ms wall-clock precision on a Windows host.
Windows waits round up to milliseconds, and CPU scheduling or network delay can
delay packets. Validate short timers under the intended workload before relying
on them; a user-mode service doesn't guarantee hardware-level detection latency.

## RFC 7880: Seamless BFD

Keep the initiator and reflector roles straight, turtle crew. S-BFD retains the
base wire and authentication rules but replaces parts of the classical state
machine. The D bit marks a role and doesn't request classical Demand mode. Keep
the roles straight, buddy: a reflector accepts D=1 and emits D=0; an initiator
rejects D=1 responses. This distinction prevents the reflection loop described
in Appendix A.

The S-BFD test coverage maps to these requirements:

| Sections | Requirement checked | Evidence |
| --- | --- | --- |
| 4, 6, 7.1, 7.2.1 | Nonzero provisioned target, local role initialization, discriminator and transport demultiplexing | Configuration and transport tests, role/discriminator rejection in `tests/seamless.rs`, native source/socket checks in `tests/windows_seamless.rs` |
| 5, 7.2.2–7.2.3 | Reflectors originate only Up/AdminDown, never periodic probes; replies swap discriminators and copy multiplier/TX while advertising local capacity | `tests/rfc7880.rs` tests all 255 multipliers and both reflector states against independent requests in Down, Up, and AdminDown; native tests verify no unsolicited reflector traffic |
| 6.2, 7.2.3, 7.3.2–7.3.3, Appendix A | Role markers prevent loops; initiator RX/Echo RX fields stay zero | Explicit marker rejection in both roles and existing wire-field tests |
| 7.3.1 | An Up reply establishes the initiator without Init; AdminDown and timeout leave it Down | Stateful initiator and native one-reply establishment tests; timeout keeps the provisioned target |
| 7.3.3 | AdminDown proves communication and slows actual probes to at least 1 s; initial timeout includes path latency | Maintenance tests cover several receive limits and jitter; native 1 s minimum-spacing test; large timer/RTT arithmetic and exact expiry boundary |
| 7.5 | Poll/Final runs independently in both directions | Simultaneous Poll regression: a reflector Poll leaves the local Poll pending, the next request carries Final with P clear, and a later request completes the local Poll. An incoming Final is never reflected as Final. |
| 8.2 | Loss reduces generated traffic, including with slow reflector capacity | Congestion regressions at 30 s, 60 s, and 2,500 s receive limits; backoff clears on a valid reply |
| 11 | Reflector authentication doesn't use a per-peer sequence window; it authenticates its response using the request's sequence | Both supported keyed SHA-1 modes with multiple clients, repeated sequences, reverse sequence order, and wraparound |
| 11 | Initiator replies must correlate with acceptable probes | Reordered outstanding replies are accepted; consumed or expired sequences are rejected without refreshing detection |

The initiator uses a local detection policy of
`DetectMult × negotiated probe interval + MinRxUs`. RFC 7880 leaves loss criteria
to the implementation and requires allowance for round-trip latency. Choose
`MinRxUs` to cover that latency and responder scheduling delay.

<a id="congestion-control-correction"></a>

## Congestion-control limits

Ninja discipline includes backing off when replies stop. Classical multihop and
S-BFD initiators use the backoff limit `max(30 s, saturating_double(base))`. The
base retains the peer's slower receive capacity, so a 60 s base backs off to 120
s after loss. Fast sessions stop doubling at 30 s, and valid responses restore
the negotiated rate. The slow-peer regression tests check both protocol roles.

Intervals saturate at `u32::MAX` microseconds, the maximum representable wire
value. A base already at that maximum cannot be increased through the advertised
interval; avoid that configuration when further congestion backoff is required.
Session stopping, route policy, and domain-wide discriminator allocation are
operator responsibilities, rather than claims made by these tests.

## Run and interpret validation

Turtle power means running the relevant suites before the pizza celebration.
Complete the prerequisites in
[Run development checks](../CONTRIBUTING.md#run-development-checks). The
[ASan wrapper](development/validation.md#run-addresssanitizer-checks) initializes
and verifies the selected MSVC sanitizer runtime.

From the repository root on the supported Windows target, run:

```powershell
cargo test-release --offline --test rfc5880 --test rfc7419 --test rfc7880
cargo test-release --offline
.\scripts\Test-Asan.ps1 -CargoArguments @('--offline')
```

### Test coverage and timing

No need to wait out a whole gnarly timeout in real time: the focused suites use
monotonic synthetic times for long periods and exact boundaries, avoiding real
multi-minute waits. Native tests exercise actual Windows UDP, IPv4/IPv6
metadata, private broker COM security, authenticated local RPC, and temporary
registry fixtures.

### Deployment validation limits

The remaining deployment limits include coordinated discriminator uniqueness,
optional features listed above, short-timer scheduling under load, and the
configured AdminDown announcement cap. The cap is an explicit deviation from the
recommended full detection-period announcement and logs a warning when used.
Dude, tests don't replace interoperability checks against another vendor's peer,
live RRAS operations, or installed-service shutdown and recovery checks.
