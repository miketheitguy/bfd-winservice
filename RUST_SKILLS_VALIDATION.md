# Rust skills validation — current guide

Cowabunga, validation crew. Bring receipts for the checkout you inspect. Use
the local [Rust skill](.codex/skills/rust-skills/SKILL.md) when reviewing Rust.
This page connects current guidance to dated results; it does not claim a fresh
265-rule audit or a passing test run for your checkout.

## Choose a validation task

Pick your test mission, turtle crew:

| Task | Guide |
| --- | --- |
| Run required, optimized, ASan, Miri, or opt-in native checks | [Development validation](docs/development/validation.md) |
| Check a production artifact | [Hardening verification](docs/security/build-hardening.md#verification) |
| Review API and engine ownership | [Library development](docs/development/library.md) |
| Inspect native service boundaries | [Local RPC security](docs/security/local-rpc.md) and [BGP provider contract](docs/reference/bgp-provider.md) |
| Validate the installed service | [Setup](docs/setup.md), [monitoring](docs/monitoring.md), and [BGP actions](docs/bgp.md) |
| Interpret earlier results | [Read the validation receipts](#read-the-validation-receipts) |

## Read the validation receipts

Donatello checks the revision and the scope. Counts, hashes, and successful
checks belong to their recorded revision. A prose glow-up doesn't rerun a test.
Use the current reference when an older entry describes superseded behavior:

| Historical detail | Current source of truth |
| --- | --- |
| Foreground flags, STDOUT logging, or runtime privilege removal | [Service migration](docs/console.md) and [read-only startup validation](docs/security/service-isolation.md#bfd-privilege-allowlist) |
| Debug symbols, native C instrumentation, or compiler settings | [Build hardening](docs/security/build-hardening.md) |
| Five-second shutdown announcement cap | [Protocol shutdown limits](docs/protocol.md#supported-modes-and-limits) |
| BGP named pipes or AdminDown actions | [BGP action rules](docs/bgp.md) and [RPC identity matrix](docs/rpc-authentication.md#bgp-control-over-local-rpc) |
| Helper processes, rejected status, or worker replacement | [Status contract](docs/rpc-session-status-design.md) |
| String configuration errors or mutable validated state | [Library APIs](docs/development/library.md) |
| Local fixtures treated as RRAS interoperability | [Windows/BIRD test record](docs/windows-bgp-interop-2026-10-22.md) |

## Current API and validation

### Check the current checkout

Follow [development validation](docs/development/validation.md), then record
which revision and paths you exercised. Native child fixtures are launched by
their parent tests; don't run those entry points directly. Live SCM, Event
Viewer, and RRAS behavior require the corresponding installed-host checks.

The [2026-10-22 service-only record](docs/service-only-validation-2026-10-22.md)
captures host, native Windows VM, installer, and Windows/Ubuntu scenario results
for the working tree based on v3.0.2. It is a validation record, not a published
release or a fresh 265-rule assessment.

### Resolved public API findings

F1 (private authentication kind/key) and F2 (validated immutable configuration)
are covered by compile-fail and configuration regressions. Use the
[library API reference](docs/development/library.md#use-the-rust-configuration-and-error-apis)
for constructors, typed errors, and transmission semantics, and the
[configuration reference](docs/configuration.md) for registry contracts.

### Ownership and concurrency boundaries

Review packet acceptance before state mutation, single-owner engine state,
provider thread affinity, and native storage through cancellation. The
[library reference](docs/development/library.md), [native RPC flows](docs/security/local-rpc.md),
[provider lifecycle](docs/reference/bgp-provider.md), and
[logging ownership](docs/reference/logging-internals.md) maintain those details.
Miri covers portable Rust logic; it does not execute Windows APIs or the C RPC bridge.

## Historical validation records

The [2026-10-21 baseline archive](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md)
preserves the dated 2026-10-05 through 2026-10-15 records, including their original
counts and superseded implementation descriptions. The
[2026-10-01 matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) retains the
original 265-rule review. The following anchors preserve existing links.

<a id="local-rpc-security-validation--2026-10-15"></a>

### Local RPC security validation — 2026-10-15

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#local-rpc-security-validation--2026-10-15).

<a id="state-and-diagnostic-logging-validation--2026-10-08"></a>

### State and diagnostic logging validation — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#state-and-diagnostic-logging-validation--2026-10-08).

<a id="rfc-5880-validation--2026-10-08"></a>

### RFC 5880 validation — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rfc-5880-validation--2026-10-08).

<a id="rust-security-fixes--2026-10-08"></a>

### rust-security fixes — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rust-security-fixes--2026-10-08).

<a id="expanded-hardening-review--2026-10-08"></a>

### Expanded hardening review — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#expanded-hardening-review--2026-10-08).

<a id="exception-handling-hardening--2026-10-08"></a>

### Exception handling hardening — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#exception-handling-hardening--2026-10-08).

<a id="control-packets-and-state-signaling--2026-10-08"></a>

### Control packets and state signaling — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#control-packets-and-state-signaling--2026-10-08).

<a id="windows-build-hardening--2026-10-08"></a>

### Windows build hardening — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#windows-build-hardening--2026-10-08).

<a id="ip-routed-seamless-bfd--2026-10-08"></a>

### IP-routed Seamless BFD — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#ip-routed-seamless-bfd--2026-10-08).

<a id="technical-documentation-improvements--2026-10-08"></a>

### Technical documentation improvements — 2026-10-08

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#technical-documentation-improvements--2026-10-08).

<a id="code-and-documentation-review--2026-10-07"></a>

### Code and documentation review — 2026-10-07

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#code-and-documentation-review--2026-10-07).

<a id="rust-check-remediation--2026-10-07"></a>

### rust-check remediation — 2026-10-07

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#rust-check-remediation--2026-10-07).

<a id="documentation-review--2026-10-05"></a>

### Documentation review — 2026-10-05

See the [archived record](docs/archive/RUST_SKILLS_VALIDATION_2026-10-21.md#documentation-review--2026-10-05).
