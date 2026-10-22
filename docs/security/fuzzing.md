# BFD fuzz harness security reference

This reference helps maintainers and security reviewers assess which untrusted
packet boundaries the fuzz harness exercises and how its checks work. For
tool installation, bounded campaigns, and replay commands, see the
[fuzz harness guide](../../fuzz/README.md). For the deployed packet policy, see
[BFD packet authentication](packet-authentication.md).

## Target boundaries and checks

The harness calls in-memory library APIs with synthetic configuration and
authentication bytes derived from public input fields.
It uses no sockets, service-control operations, registry configuration, local
RPC calls, or BGP provider operations. Its assertions act as oracles: a panic,
sanitizer report, or failed assertion makes the input a candidate for replay and
investigation.

Each target covers a specific boundary:

| Target | Entry points | Assertions |
| --- | --- | --- |
| `packet` | `ControlPacket::decode` and `AuthConfig::verify` | Accepted input satisfies separate assertions for header fields, declared length, authentication mode, key ID, password, and keyed sequence bounds. Decoded headers round-trip through every supported authentication mode. |
| `session` | Classical `Session::receive`, `expire`, and `set_timing` | Rejected reception preserves an observable state snapshot. A reference session skips rejected inputs and must match the tested session after subsequent actions. Packets with an invalid version, wrong receiver discriminator, zero sender discriminator, or truncation must be rejected. |
| `initiator` | S-BFD `Session::packet_at`, `receive`, `expire`, and `set_timing`, with `Reflector::respond` | Every accepted keyed response must match an unconsumed, unexpired probe in an independent bounded model. Rejections preserve snapshots; signed unissued sequences and wrong discriminators cannot consume valid probes. Loss, delayed/replayed replies, Poll/Final timing changes, and maintenance are interleaved. |
| `reflector` | `Reflector::respond`, with ordinary and administrative-down configuration | Repeated calls are deterministic and preserve reflector state. Accepted requests satisfy the reflector discriminator, Demand, state, interval, and authentication constraints. Replies reverse discriminators, acknowledge Poll with Final, authenticate, and echo keyed request sequences. |

The session snapshot includes state, diagnostics, discriminators, remote state,
polling, communication status, transmit/detection timing, the detection deadline,
and transmit eligibility. Internal authentication tracking is not read directly;
subsequent traffic compares the behavior of the two sessions. The session target
uses classical multihop configuration. Its timing-update action checks the
classical rejection path. The separate `initiator` target exercises live S-BFD
timing negotiation and outstanding-probe correlation. Its public packet API
commits generation as transmission; native failed-send commitment and sequence
wraparound use focused crate regressions. A 32-action campaign cannot span the
complete 32-bit sequence space.

Successful decoding alone does not establish authentication or permission to
change session state. Arbitrary bytes can form a valid packet, especially under
`none` authentication. The oracles check acceptance constraints and deliberately
invalid cases rather than requiring all mutated input to be rejected. The keyed
checks use the production digest implementation; the harness does not provide an
independent cryptographic implementation.

## Mutation and authentication

The harness retains normal authentication code through `--no-cfg-fuzzing`.
It uses the five supported modes: `none`, `simple-password`, `keyed-sha1`,
`meticulous-sha1`, and `meticulous-md5`. Authentication test bytes come from
public input fields; the harness embeds no shared credential. Packet and
reflector targets use the sender discriminator encoded as four network-order
bytes. Sessions use all eight bits of their selector byte, widened to four
network-order bytes. Configuration, structured mutations, and seed generation
use matching derivations so replay
needs no external credential. These publicly known bytes exercise authentication
code and provide no secrecy. Use generated test inputs when extending the corpus;
deployment keys do not belong in the harness or corpus.

Packet mutations change control fields and re-encode them with a selected
authentication mode. Reflector mutations additionally preserve valid S-BFD
request constraints. Session mutations insert, remove, duplicate, replace, or
modify complete action frames, including explicit rejection actions. See the
[session input format](../../fuzz/inputs.md#session-input-format) for the action
encoding.

One-quarter of mutation seed values select libFuzzer's default byte mutator.
Packet mutations also fall back when the structured output cannot fit the
available buffer. This preserves exploration of malformed lengths,
authentication sections, truncation, and frame boundaries. The structured
mutation choices derive from libFuzzer's supplied seed and respect the output
buffer's size limit.

## Resource and build limits

The [PowerShell wrapper](../../scripts/Test-Fuzz.ps1) bounds each target run by
both an input-count budget and a time budget after compilation. It configures a
five-second input timeout and a 2 GiB resident-memory limit. Packet and reflector
inputs are limited to 256 bytes. Classical session and initiator inputs are limited to 2,049 bytes: one
authentication selector and up to 32 frames of 64 bytes. The oracles also limit
packet processing to 256 bytes and session processing to 32 actions.

The [fuzz package](../../fuzz/Cargo.toml) has a separate workspace and lockfile.
It pins `libfuzzer-sys`; the wrapper requires cargo-fuzz 0.13.2, fetches locked
dependencies, then builds offline and checks that the lockfile has not changed.
The wrapper uses the repository-selected nightly toolchain and initializes the
matching x64 MSVC compiler and AddressSanitizer (ASan) runtime.

The wrapper selects the fuzz package's optimized development profile, with one
codegen unit, full debug information, overflow checks, and unwinding enabled.
Rust harness and dependency code receive ASan and coverage instrumentation. The
fuzz build uses the prebuilt standard library rather than the repository's
`build-std` setting; that library and Windows system/runtime libraries do not
receive the harness's instrumentation. Rust EH-continuation instrumentation and the final
`/GUARD:EHCONT` link flag are omitted for this build because the prebuilt standard
library lacks matching metadata. See
[test-profile differences](build-hardening.md#test-profile-differences) for the
ordinary test and production graphs.

The test-only C++ libFuzzer engine has its own MSVC compiler settings, including
`/EHsc`, `/MD`, `/GS`, CFG, EH-continuation metadata, `/sdl`, and `/W4` diagnostics.
Its upstream warnings are nonfatal, and C4146 is suppressed for intentional
unsigned negation. These settings do not change the maintained native RPC C
policy. Oracles and mutation logic use safe Rust. An MSVC-only Rust module calls
a test-only C helper to register linker-provided sanitizer counters and the
program-counter table once, after the C++ runtime initializes. The helper is
compiled separately, without LLVM coverage instrumentation, to keep reserved
sanitizer section names out of instrumented Rust modules. It takes no input and
transfers no ownership. Its MSVC C build uses `/TC`, `/MD`, `/GS`, CFG,
EH-continuation metadata, `/sdl`, `/W4 /WX`, and static analysis. The helper does
not receive ASan instrumentation. Review this registration when changing the
toolchain or libFuzzer dependency.

## Artifacts and replay

The wrapper stores working corpora, crash inputs, logs, and build products under
`target/fuzz`. The repository ignores that directory. The fuzz package also
ignores its default `target`, `corpus`, `artifacts`, and `coverage` directories,
plus loose libFuzzer failure inputs. LLVM profile files and logs are ignored.
Keep harness source, seed-generation code, manifests, and `fuzz/Cargo.lock` in
version control.

Preserve a failing input before rerunning or cleaning outputs. Follow the
[replay procedure](../../fuzz/README.md#run-and-reproduce-cases), then turn a
confirmed failure into a focused regression. Ignored working corpora and
artifacts are not a durable regression suite.

The workflow's separate `fuzz` job runs short campaigns on pull requests, main
branch pushes, tags, and manual dispatch. It audits the fuzz lockfile and checks
the harness before the campaigns. Release publication depends on `fuzz`, `asan`,
and `build-msi` succeeding. On tags, the release-version script updates the
service entry in the fuzz lockfile before locked builds. The diagnostic upload
step uses `always()` and retains available target logs and failure inputs for
14 days. See [GitHub Actions](../../fuzz/README.md#github-actions) for the
campaign budgets, artifact name, and download location.

## Coverage limits

These targets cover only the specified in-memory APIs and assertions. They do
not validate UDP address/port/TTL metadata, firewall policy, installed service
identities or ACLs, native RPC unmarshaling, COM/MI provider behavior, BGP actions,
or router interoperability. Source coverage and a completed campaign describe
executed paths; they do not establish exhaustive rejection or absence of defects.

Use the [ASan test procedure](../development/validation.md#run-addresssanitizer-checks),
[RFC conformance tests](../rfc-conformance.md), and
[service isolation reference](service-isolation.md) for the adjacent validation
boundaries.

## Implementation map

Use these files when changing a target or reviewing its assumptions:

| File | Responsibility |
| --- | --- |
| [fuzz/src/lib.rs](../../fuzz/src/lib.rs) | Oracles, state snapshots, bounds, synthetic configuration, and deterministic seed cases |
| [fuzz/src/initiator.rs](../../fuzz/src/initiator.rs) | Stateful S-BFD oracle and independent outstanding-probe model |
| [fuzz/src/mutators.rs](../../fuzz/src/mutators.rs) | Structured packet and action-frame mutations, plus byte-mutator fallback |
| [fuzz/fuzz_targets](../../fuzz/fuzz_targets) | libFuzzer target and custom-mutator entry points |
| [fuzz/src/msvc_coverage.rs](../../fuzz/src/msvc_coverage.rs) | Once-only MSVC sanitizer-coverage registration |
| [fuzz/native/msvc_coverage.c](../../fuzz/native/msvc_coverage.c) | Linker-section declarations and native lifetime assumptions |
| [fuzz/build.rs](../../fuzz/build.rs) | Test-only C helper build and compiler policy |
| [scripts/Test-Fuzz.ps1](../../scripts/Test-Fuzz.ps1) | Dependency/toolchain setup, compiler overrides, budgets, output paths, and replay |
