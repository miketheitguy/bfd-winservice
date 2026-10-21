# RFC 5880 conformance review

Cowabunga, RFC crew. Trace requirements to the implementation receipts.
Maintainers and network admins, let's take the protocol review for a spin. This
reference checks the service's asynchronous BFD implementation against
[RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html). It maps requirements to
code, records regression evidence, and identifies deployment and feature limits.
The review covers the complete RFC, including its security considerations and
non-normative backward-compatibility appendix.

The linked code and tests are the implementation receipts, dude: use them to
check the supported profile before choosing a deployment.

Classical IPv4/IPv6 sessions use the single-hop and multihop transport profiles
described in [Network and protocol behavior](protocol.md). S-BFD uses RFC 5880
where [RFC 7880](https://www.rfc-editor.org/rfc/rfc7880.html) retains its rules;
its role marker, stateless reflector, and state machine differ as specified in
[Configure Seamless BFD](seamless.md). The implementation doesn't provide every
optional RFC 5880 mode or forwarding-plane integration.

For the combined RFC 5880, RFC 7419, and RFC 7880 test matrix,
congestion-control behavior, and validation limits, see
[RFC conformance tests](rfc-conformance.md).

Use the [requirement mapping](#requirement-mapping) to locate an RFC rule,
[errata interpretation](#errata-interpretation) to distinguish correction status,
and [deployment limits](#deployment-and-implementation-limits) to assess a host.

## Requirement mapping

Let the turtle team follow the requirement-to-code trail. Here's the RFC
requirement lineup. The table groups related rules; paths identify the
implementation or its regression tests:

| RFC section | Requirement | Implementation and evidence |
| --- | --- | --- |
| 2–3 | Bidirectional monitoring with independent transmit/receive timing | `Session` tracks local and remote state, rates, and multiplier separately. Classical sessions originate asynchronous mode. |
| 4, 6.8.7 | Version 1 header, network byte order, nonzero multiplier/discriminators, correct flags and length | [packet.rs](../src/packet.rs) encodes the 24-byte header and optional authentication. Byte fixtures cover all states, diagnostic bit values, flags, and authentication formats. C and M remain clear; classical D remains clear. |
| 4.1–4.4, 6.7 | Password and keyed/meticulous SHA-1 formats; optional MD5 modes excluded | Both SHA-1 variants and simple-password are supported. MD5 configurations and wire types are rejected. Digest fixtures verify padded binary keys and whole-packet hashes; password comparisons and digest comparisons use constant-time equality. |
| 5, 6.4, 6.8.5, 6.8.8–6.8.10 | Optional Echo function | Echo is unsupported. Every transmitted control packet advertises zero Required Min Echo RX Interval. No Echo state or diagnostic 2 is originated. |
| 6.1–6.2, 6.8.6 | Ordered reception and classical four-state machine | [session.rs](../src/session.rs) tests every local/remote state pair. Transport, structural, discriminator, and authentication rejection precede session mutation. Local AdminDown updates authenticated peer parameters before stopping state-machine processing. |
| 4.1, 6.2 | Assigned diagnostic codes and all four state values in logs | [event_log.rs](../src/event_log.rs) maps local and peer states to separate Operational IDs and reports diagnostics 1–8 with origin context. Code 0 has no standalone diagnostic event. The output worker mirrors each state/diagnostic record to the enabled file. [Event IDs and severity policy](logging.md#operational-events) are service policy, not an RFC severity requirement. |
| 6.3 | Nonzero, unique local discriminator; Your Discriminator selects a session | The runtime provisions one session per process and exclusively binds its receive socket. Known Your Discriminator must match; zero is accepted only for Down/AdminDown startup with matching path metadata. See [Deployment and implementation limits](#deployment-and-implementation-limits) for uniqueness and transport limits. |
| 6.5, 6.8.6–6.8.7 | Scheduled Poll sequence and prompt Final responses | Pending and transmitted Polls are distinct states. An unsolicited Final cannot complete an unsent Poll. Valid peer Polls receive Final with P clear, independently of periodic traffic; local AdminDown stops processing before replying, following the ordered reception procedure. |
| 6.6, 6.8.11–6.8.14 | Optional local Demand mode; peer Demand suppression | Local Demand mode is unsupported. When both classical ends are Up and the peer advertises D, periodic traffic stops unless a Poll is pending. A Final reply doesn't complete the local Poll. S-BFD D identifies an initiator instead of enabling classical Demand mode. |
| 6.7.1 | Authentication enable/disable and key provisioning | Authentication and one key are read at startup. Live key rollover and authentication transitions are unsupported; restart with matching peer settings. Type, key ID, length, and digest checks precede sequence commitment. |
| 6.7.2, 6.7.4 | Authentication lengths, sequence windows, circular sequence space | Authentication uses only the declared BFD Length, ignoring trailing UDP padding. Reserved keyed-authentication bytes are ignored on receive and zero on transmit. Meticulous SHA-1 sequences advance by one with explicit wraparound; receive bounds distinguish repeated non-meticulous sequences from forbidden meticulous repeats. |
| 6.8.1 | Initialization, state retention, discriminator expiry, authentication resynchronization | LocalDiag starts at zero and survives classical recovery. Authenticated peer validity has a clock separate from liveness, so AdminDown reception refreshes discriminator and authentication tracking without starting detection. Discriminator expiry occurs at one detection time; authentication can resynchronize after two. |
| 6.8.2–6.8.3 | Negotiated intervals and safe timer changes | Peer timer changes apply to the existing schedule. Up local TX increases remain at the preceding effective rate until Final. Live S-BFD wire changes are combined before transmission or rejected while a Poll is transmitted. After Final, another non-Final response separates changes. Classical local timers are startup-only. |
| 6.8.4 | Asynchronous detection time and failure transition | Classical detection is `peer DetectMult × max(local required RX, peer desired TX)`. Expiry in Init/Up sets Down and diagnostic 1. Invalid packets never refresh detection. |
| 6.8.7 | TX negotiation, jitter, suppression, and state notifications | TX uses the greater of effective local TX and peer required RX. Per-packet jitter is 75–100%, or 75–90% with local multiplier 1. Passive discovery requires a known peer. Zero-RX suppresses periodic traffic. State notifications keep P clear and don't consume a pending Poll. Native UDP tests cover authentication and scheduling. |
| 6.8.15, 6.8.17 | Forwarding-plane reset and concatenated-path signals | No external reset or concatenated-path notification API is implemented. C remains clear. Diagnostics 4, 5, 6, and 8 aren't originated; received diagnostic values are preserved as peer information rather than copied to LocalDiag. |
| 6.8.16 | Administrative shutdown and continued announcements | Shutdown sets AdminDown/diagnostic 7 and never stops BGP; per RFC 5882 sections 3.2 and 4.1, either end's AdminDown withdraws a Stop that BFD imposed. A communicating classical session repeats permitted announcements for the longer Detection Time, bounded by `MaxShutdownAnnounceMs`. Truncation is a documented deviation and logs a warning. Native regressions check repeated announcements, the grace period, and the configured limit. |
| 6.8.18 | Retain RX limits while peers communicate; release stale suppression | Peer required RX is retained until a detection time passes without valid packets, then resets to 1. Active probing resumes after an expired zero-RX advertisement; passive sessions still require a learned discriminator. |
| 7 | Multihop congestion control and time-critical scheduling | Unanswered classical multihop discovery and detection loss double the desired interval. The cap is the greater of 30 seconds and twice the base including the preceding negotiated interval, bounded by the wire format. Valid reception clears backoff. The runtime handles one datagram per pass, keeping timers and Stop processing responsive under floods. Single-hop retains the startup floor without exponential backoff. |
| 8–9 | Assigned authentication/diagnostic values; replay and spoofing considerations | Wire values follow the RFC. Both SHA-1 variants are available; keys accept ASCII and hexadecimal provisioning. Sequence windows, random initial sequences, and transport source/TTL/interface checks reduce spoofing and replay exposure. No confidentiality is provided. |
| Appendix A | Non-normative version 0 compatibility | Only version 1 is supported; version 0 is rejected without automatic downgrade. |

## Errata interpretation

Give correction status the Donatello treatment before applying it. The review
considers the
[RFC Editor's RFC 5880 errata](https://www.rfc-editor.org/errata/rfc5880).
Verified corrections and proposals held for a future document update have
different status:

| Erratum | Status | Effect on this review |
| --- | --- | --- |
| [2530](https://www.rfc-editor.org/errata/eid2530) | Verified | Applies to the unsupported MD5 modes. |
| [7082](https://www.rfc-editor.org/errata/eid7082) and [7083](https://www.rfc-editor.org/errata/eid7083) | Verified | The SHA-1 correction is applied: receive sequences become known only after digest verification succeeds. Rejected packets cannot seed or advance tracking. The MD5 correction is outside the supported profile. |
| [6926](https://www.rfc-editor.org/errata/eid6926) | Verified, editorial | Remote-state terminology doesn't change the state-machine behavior. |
| [7240](https://www.rfc-editor.org/errata/eid7240) | Held for Document Update | Its explanatory notes confirm retention of the last classical failure diagnostic through recovery. The implementation follows the published initialization and transition procedures. |
| [5205](https://www.rfc-editor.org/errata/eid5205) | Held for Document Update | Its proposed diagnostic update for already-Down timeout isn't treated as a published requirement. Diagnostic 1 is assigned when Init/Up detection expires. |
| [4410](https://www.rfc-editor.org/errata/eid4410) | Held for Document Update | Clarifies local Demand Poll timeout; local Demand initiation is unsupported. |
| [6818](https://www.rfc-editor.org/errata/eid6818) | Rejected | Doesn't change the published simple-password receive rules. |

## Deployment and implementation limits

A bodacious deployment still needs these scope checks. Before you shout
Cowabunga, like, check these limits on the implemented protocol profile.

### Discriminator allocation

Ninja discipline starts with distinct session identifiers. Keep session
identities dialed in: assign a distinct `Discriminator` to each coexisting BFD
session on the same system. An omitted classical discriminator uses a random
nonzero value; the service doesn't coordinate allocation with other processes or
other BFD implementations. S-BFD reflector identifiers must also be unique in
their configured discriminator domain.

### Transport and feature scope

Path validation implements the configured single-hop/multihop profiles.
Discriminator-based session selection doesn't remove source, interface, port,
or TTL policy checks. Out-of-band discriminator signaling, automatic routing
protocol advertisement, Echo, local Demand mode, and external forwarding-plane
notifications require additional integration.

The RFC 5880 updates for
[RFC 8562 multipoint BFD](https://www.rfc-editor.org/rfc/rfc8562.html) and
[RFC 9747 Unaffiliated BFD Echo](https://www.rfc-editor.org/rfc/rfc9747.html)
are outside this profile: multicast endpoints and the Multipoint bit are
rejected, and the service has no Echo implementation.

### Shutdown announcements

Classical shutdown uses the section 6.8.16 announcement period, bounded by
`MaxShutdownAnnounceMs` (30 seconds by default, at most 60 seconds). Truncating
that period is a documented deviation from the announcement recommendation and
produces a warning; the peer can detect a failure before receiving AdminDown.
The installer sets Windows' preshutdown timeout to 125 seconds to cover this
period and cleanup. Fatal transport errors, sessions without a communicating peer, and
S-BFD initiators use one permitted notification. Passive and zero-RX restrictions
remain in force. A final BGP action can extend total stop time.

### Library transmission ownership

Turtle power includes honoring the packet-delivery contract. The public
`Session::packet` convenience APIs treat returned bytes as a transmission for
sequence and probe tracking. Callers must deliver those bytes; retry the same
bytes if a send fails. Don't freestyle the ownership contract, buddy. The
Windows runtime uses separate prepare and commit steps, so actual send failure
preserves its sequence and pending Poll/Final state.

### Authentication and scheduling

Keep interoperability and timing expectations totally tubular and realistic.
SHA-1 and cleartext passwords are provided for protocol interoperability; MD5 is
unsupported.
An unauthenticated peer has no cryptographic identity check. Sequence windows
cannot prove that a remote implementation is uncompromised. Very short timers
depend on host scheduling and network capacity; this user-mode service doesn't
guarantee hardware-level detection latency. No cap: timer settings alone don't
prove what a busy host can deliver.

## Regression evidence

Check the regression receipts before the pizza victory lap. These suites bring
the receipts for protocol behavior, shutdown, and diagnostic output.

### Session and packet regressions

[rfc5880.rs](../tests/rfc5880.rs) verifies retained diagnostics, stale zero-RX
recovery, both AdminDown validity-clock cases, unsent Poll acknowledgement,
delayed Up TX increases, separation of timer changes, and multihop discovery
backoff. Slow-peer regressions check that backoff retains the preceding
negotiated rate as its floor after RX expiry and reduces traffic even when the
peer's interval already exceeds 30 seconds.
Session unit tests also verify failed-send preparation, exact sequence
wraparound, and preservation of an unsent S-BFD Final/probe record.

### Shutdown and BGP regressions

The shutdown tests in [windows_udp.rs](../tests/windows_udp.rs) check repeated
AdminDown packets, both detection directions, and truncation warnings at the
configured grace-period limit. Byte fixtures, all 16 state transitions,
authentication rejection tests, and native Poll scheduling checks cover the
base protocol. BGP unit tests in [bgp.rs](../src/bgp.rs) check administrative
release of this controller's Stop, including a queued final Start at shutdown.

### State and diagnostic logging regressions

The logging regressions verify all state/diagnostic ID and level mappings against
the SDK-compiled manifest, exact payload fields, paired ETW/file output, disabled
file output, and continued file logging after an ETW error. The UDP regression
accepts every assigned peer diagnostic while the local session stays Up and
checks repeated-report suppression. Runtime tests cover reflector maintenance,
shutdown, and Informational recovery with a retained local failure diagnostic.
Invalid-header and authentication tests verify that rejected packets don't
change the recorded peer state or diagnostic.

### Validation commands and recorded results

For the validation commands, see [Run development checks](../CONTRIBUTING.md#run-development-checks).
For recorded checks and their limits, see the dated
[correctness review](../CODE_REVIEW.md) and
[Rust skills validation](../RUST_SKILLS_VALIDATION.md).
