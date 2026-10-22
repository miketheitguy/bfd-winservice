# Correctness reviews

Cowabunga, review crew. Keep the evidence tied to its revision. Rust
maintainers, here's the review history with the receipts attached. Use this
record to check dated findings and validation limits, dude. For fresh
installation instructions and settings, see
[Set up a BFD session](docs/setup.md) and the
[configuration reference](docs/configuration.md).

No cap: these receipts belong to specific revisions. Each entry preserves the
behavior, test counts, and limits recorded at that time. A passing check in one
entry does not validate later changes. Use the
[validation guide](RUST_SKILLS_VALIDATION.md) and
[contributor guide](CONTRIBUTING.md) for the implemented API and commands.

## Find a review

Pick the historical mission, turtle crew. Pick a topic and cruise to its dated
evidence:

| Topic | Review entries |
| --- | --- |
| Private local RPC | [BGP probe removal](#bgp-control-probe-removal--2026-10-22), [Restricted-caller alignment](#rpc-restricting-sid-alignment--2026-10-22), [C exception handling](#native-c-exception-handling--2026-10-16), [BGP control migration](#bgp-control-rpc-migration--2026-10-16), [Rejection recovery](#rpc-status-rejection-recovery--2026-10-15), [session-status implementation](#rpc-session-status-implementation--2026-10-15), and [earlier security review](#local-rpc-security-review--2026-10-15) |
| Protocol requirements | [RFC 5880 / RFC 7419 / RFC 7880 validation](#rfc-5880--rfc-7419--rfc-7880-validation--2026-10-09) and [RFC 5880 remediation](#rfc-5880-conformance-remediation--2026-10-08) |
| Service reliability and security | [Reliability follow-up](#reliability-follow-up--2026-10-09) and [reliability/security review](#reliability-and-security-review--2026-10-09) |
| Deployment and observability | [MSI packaging](#msi-packaging-review--2026-10-08) and [state/diagnostic logging](#state-and-diagnostic-logging-review--2026-10-08) |
| Earlier Rust remediation | [rust-security remediation](#rust-security-remediation--2026-10-08), [rust-check remediation](#rust-check-remediation--2026-10-07), and [review before remediation](#review-before-remediation--2026-10-07) |
| Original review and rule assessment | [Historical review](#historical-review--2026-10-05) and [archived rule matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md) |

## Read superseded behavior

Donatello would check what changed after an older review. History vibe check:
these later changes supersede descriptions in older entries:

| Older description | Implemented behavior and reference |
| --- | --- |
| BGP control uses a named pipe, PID/SCM matching, or caller impersonation. | Both service channels use authenticated `ncalrpc`; BGP retains a separate interface and serialized provider worker. See [BGP RPC security](docs/rpc-authentication.md#bgp-control-over-local-rpc). |
| BGP control uses a connection probe, broker-instance nonce, or restart-triggered replay. | `BgpControl` 2.0 exposes only Get/Start/Stop. BFD sends no startup or idle control calls and retries only outstanding failed actions. See [BGP worker behavior](docs/reference/bgp-provider.md#worker-retries-and-broker-recovery). |
| An isolated broker child performs RPC connection checks, or invalid status stays quarantined until restart. | One worker inside the broker queries typed status. Rejected replies clear the cache and retry; only a stuck native worker quarantines telemetry. See [RPC session-status query](docs/rpc-session-status-design.md). |
| Stop always stops BGP, or AdminDown never changes BGP. | Local or peer AdminDown releases a Stop issued by BFD by queuing Start; it leaves other peers untouched. See [BGP behavior](docs/bgp.md). |
| Shutdown announces once or uses a five-second cap. | Classical communicating sessions announce for the longer Detection Time, bounded by `MaxShutdownAnnounceMs` (default 30 seconds). See [shutdown behavior](docs/protocol.md). |
| Release images include full PDBs, the service has no native C, or no CI exists. | Production images omit symbols/PDBs; the RPC bridge includes compiled native C; tagged releases run the [Windows MSI workflow](.github/workflows/build-msi.yml). See [build instructions](CONTRIBUTING.md). |
| One Automatic LocalSystem service is installed with WiX 5, and restricted service SIDs remain unevaluated. | WiX 7 packages delayed-start LocalService BFD with a restricted service SID and a separate LocalSystem broker. See [bundle installation](docs/setup.md#install-with-the-offline-setup-bundle) and [security boundaries](docs/security.md). |

## BGP control probe removal — 2026-10-22

Cowabunga, control crew. Review baseline: `0d488c9`. Removed the startup
connection probe, startup-only provider status query, idle connection polling,
broker-instance nonce, and restart-triggered replay of completed actions.
The worker waits on its condition variable until a BFD action or shutdown;
outstanding failed actions retain their existing retry and supersession rules.
SCM recovery and the independent broker-to-BFD telemetry worker keep their
existing behavior.

The private BGP interface advances to `BgpControl` 2.0 at
`BfdWinService.Bgp.v2`. Its result is eight bytes: provider status and Boolean
value. MIDL and the manager accept only Get/Start/Stop opcodes `1..3`; the old
probe opcode `0` is rejected. Both executables must come from the same build.
Functional calls retain server identity pinning, per-call shared Authz checks,
protected ACLs, bounded dispatch, native cancellation, and completion ownership.
The client no longer tracks connection health or requires interior mutability.

Validation: the full optimized suite passed, including 212 library tests with
11 ignored installed/provider checks and child entry points. The ASan library
run also passed 212 tests; the final focused BGP ASan run passed 27 tests with
three ignored. The wrapper verified emitted native RPC ASan hooks. Regressions
cover the reduced C/Rust result layout, rejection of opcode 0 and other invalid
values, idle waiting after success, failed-action retries, authorization,
cancellation, and shutdown. Strict all-target Clippy and API documentation
checks passed, as did read-only native BGP RPC/MI coexistence and both
production executable-hardening checks. Actual installed-service and live RRAS
tests remain separate from these local fixtures.

The BGP guide, provider and RPC references, setup and packaging guidance,
source map, Mermaid runtime view, editable Draw.io source/PNG, and concrete
RPC skill profile describe the reduced contract and state-driven behavior.

## RPC restricting-SID alignment — 2026-10-22

Cowabunga, identity crew. Both RPC directions now use the same stronger caller
guard. Review baseline: `f323c54`. Both already required the exact account and
enabled, non-deny-only service group. Only BGP control additionally checked the
expected service SID in a nonempty caller restricting list.

A new native telemetry regression reproduced the difference: an own-account
write-restricted caller with the expected normal group but a different restricting
group received status successfully. The test uses existing World and Authenticated
Users groups, never installed service SIDs. The same test passes after the shared
guard rejects the missing restricting SID. Positive cases verify matching restricted
callers, unrestricted recovery, and rejection of deny-only normal groups.

The common guard now queries and validates restricting SIDs on both channels.
Empty lists permit an otherwise authorized unrestricted caller; nonempty lists
must contain the expected service SID. The callback and manager independently
use that guard. Native interface ACLs remain an additional gate. See the
[identity matrix](docs/rpc-authentication.md#bgp-control-over-local-rpc) and
[native authorization flow](docs/security/local-rpc.md#per-call-authorization-and-cleanup).

The broker retains its normal SYSTEM account and unrestricted service SID; BFD
retains LocalService and its restricted service SID. Wire contracts, privilege
allowlists, and installed ACLs retain their existing policy. Production still
uses Authz without impersonation. The shared test-only reduced-token helper has
a thread-bound restoration guard; identity buffers and RPC contexts retain their
existing bounded storage and ownership.

Validation: the full optimized suite passed. The ASan library run passed 213
tests with 11 ignored provider/installed-service checks and child entry points;
the wrapper verified emitted ASan hooks in the native RPC client. Strict
all-target Clippy, formatting, and API documentation checks passed. Native
RPC/MI coexistence tests and production-image hardening checks also passed.
Fixtures verify the policy independently of actual SCM-issued service tokens;
installed-service checks remain separate CI evidence. The authentication
Draw.io page, embedded editable PNG, Mermaid view, and concrete channel profile
describe the matching policy.

## Native C exception handling — 2026-10-16

Turtle power means reading this as a dated review receipt. Reviewed the
handwritten C bridge, MIDL managers/allocators, generated-stub build settings,
and asynchronous cleanup against Microsoft's RPC exception and cancellation
guidance. Client SEH uses one shared `RpcExceptionFilter` policy; fatal native
fault classes are not converted to transport errors. No new SEH handler wraps
Rust server managers. The bind wrappers and uncertain-ownership handling share
common implementations.

Enabled `/W4 /WX` for all native C and `/analyze` for handwritten translation
units. Static analysis found missing MIDL allocation callback annotations; the
callbacks now inherit the Windows SDK's SAL contracts. A separate native test
object raises recoverable RPC exceptions inside C and tests the fatal filter;
production entry points do not reference it.

Validation: the full optimized suite passed, including both new native SEH
regressions, and strict all-target Clippy and native static analysis passed.
The read-only BGP RPC/MI coexistence test passed. Production release builds and
both executable-hardening checks passed; import inspection confirmed the
synthetic exception test object is absent from both production executables.
The native source inventory contains no C++ translation units. Compilation is
explicitly pinned to C with `/TC`, and the compiler process removes ambient
`CL`/`_CL_` overrides. `/EHsc` is reserved for a separate future C++ policy;
C RPC SEH does not need C++ exception unwinding. A production build with ambient
options requesting C++ mode and disabling security flags still passed both
executable-hardening checks, confirming those overrides cannot weaken the
maintained native build. A follow-up ABI audit confirmed the maintained Rust
callbacks use only non-unwinding C/system ABIs and production uses aborting
panics. The contributor/security guidance explicitly requires any future C++
wrapper to catch C++ exceptions and return integer errors, and forbids unwinding
across FFI in either direction. This policy clarification changes documentation
only. No installed service or live RRAS operation was changed or exercised.

## BGP control RPC migration — 2026-10-16

Follow the recorded interface migration before calling the old design tubular.
BGP control uses `BgpControl` 1.0 at `ncalrpc:BfdWinService.Bgp.v1` in place of
the named pipe. Shared RPC security helpers supply WINNT packet privacy, static
Identify credentials, V5 conditional server descriptors, protected service-SID
interface ACLs, per-call local/private authentication checks, and Authz
user/group checks. The broker additionally checks any restricting-SID list for
BFD's service SID. No RPC caller token is attached to a provider thread. Runtime
management is denied in both service processes, and control registration
precedes SCM Running.

A fixed MIDL contract, one admission permit, and a one-slot queue preserve
serialized, fixed-target provider operations. Native cancellation retains storage
through completion; queued cancelled requests are discarded. Cancellation cannot
undo an already running MI operation. A broker-instance nonce detects restarts.
Uncertain BGP client ownership fails BFD closed; telemetry keeps its supervised
worker retention/quarantine policy. The installer harness now checks rejection
through the real RPC interface rather than opening the old pipe.

Validation: the complete optimized test suite passed, including executable
hardening and native RPC tests. All 11 targeted BGP RPC tests passed under Rust
AddressSanitizer, as did the five shared Authz parser tests; MSVC-built native
stubs remain uninstrumented. Both production release images passed the release
hardening harness. Both read-only
MI/RPC coexistence regressions passed. Formatting and strict all-target Clippy
passed. Native reduced-token tests ran outside the process sandbox because
Windows rejects creating write-restricted tokens from its already restricted
token. MSI installation, actual SCM-issued service-token exchange, and live RRAS
Start/Stop were not exercised locally; use the hosted installation harness and
a provisioned Windows Server for those checks.

The diagram/documentation follow-up verified both service channels share the
`ncalrpc` registration, LRPC-only binding/call checks, packet privacy, and
service-identity policy. Runtime and lifecycle arrows now show one-way call
initiation: broker to BFD for session status; BFD to broker for BGP control.
Replies use the existing calls, with no RPC callback operations. The canonical
draw.io source and all three PNGs were regenerated outside the sandbox and
visually inspected; XML directions and local documentation links passed checks.
This follow-up changes diagrams and documentation only; runtime tests were not
rerun.

## RPC status rejection recovery — 2026-10-15

Check the recovery policy recorded for this mission, ninja crew. Cleanly
rejected status data clears the cache and retries automatically. Both checked
Rust conversion failures and recoverable native marshaling errors discard the
entire reply and clear prior cached status to `Unavailable`. The same worker
retries after 1, 2, 4, 8, 16, then 30 seconds; a valid reply resets the delay.
Rejected-data errors and ordinary failures have independent one-minute reporting
limits that successful replies do not reset.

Only a stuck native worker retains the until-restart quarantine. Stop interrupts
even the longest backoff wait, while pending native storage remains owned.
Fatal native exceptions remain outside the RPC recovery handler. Authentication,
wire bounds, packet processing, and the BGP provider contract are unchanged.
See [the failure policy and Rust boundary](docs/rpc-session-status-design.md#secure-response-to-invalid-data).

Validation: all 29 targeted RPC tests passed in both optimized and
AddressSanitizer profiles. Regression coverage includes native and Rust
rejection, recovery on the same worker, backoff capping/reset, and Stop during
a 30-second retry wait. Authentication, replacement rejection, cancellation,
and stalled-worker lifetime tests also passed. Strict all-target release Clippy,
formatting, documentation links, 27 PowerShell examples, and three editable
draw.io exports passed their checks. Installed-service MSI validation was not
run locally; the opt-in MI/RPC coexistence test was not rerun for this policy
change.

## RPC session-status implementation — 2026-10-15

The [rejection-recovery entry](#rpc-status-rejection-recovery--2026-10-15)
supersedes this revision's permanent
quarantine for invalid data; its validation results describe that earlier policy.

The broker now calls `GetSessionStatusV1` from a worker thread inside its
existing process. The authenticated reply carries local and peer state,
diagnostics, accepted receive and successful send times, addresses, timing,
and counters from one immutable engine publication. Queries never request
packet-loop work or change the existing snapshot publication frequency. The
BGP provider COM/MI contract and process privileges remain unchanged.

The fixed native record contains only integers and fixed arrays. Native MIDL
range checks and one Rust `TryFrom` conversion construct enums, nonzero values,
addresses, and checked times without adding a validation dependency. Invalid
records and native marshaling faults clear the broker cache and quarantine
telemetry until restart. They never fabricate Down, issue a BGP action, or
restart the provider process. Transient failures clear the cache and retry.

One supervisor bounds status fetching independently of native completion.
Cancellation retains call storage until RPC completes; uncertain ownership
retains that single worker without blocking broker shutdown or creating
replacement workers. The implementation and operational limits are documented
in [RPC session-status query](docs/rpc-session-status-design.md) and
[RPC authentication](docs/rpc-authentication.md).

Validation passed all 266 optimized default tests and strict all-target release
Clippy. Coverage includes native C/Rust layout, native and Rust rejection,
historical peer reports, stale data, quarantine, recovery, cancellation,
responsive shutdown, and live BFD with concurrent retained snapshot readers.
All 27 targeted RPC tests also passed under AddressSanitizer, including native
cancellation and malformed replies. The explicit read-only native MI/RPC
coexistence test also passed: real provider schema traffic and fixed-policy RPC
share one process, reject a replacement
server, and recover afterward. A 200,000-publication measurement with four
concurrent readers averaged 609 ns per publication on this host; that is not a
real-time latency guarantee. Formatting, three rustdoc tests, PowerShell syntax,
documentation links, and the three editable draw.io exports were checked.
Installed SCM-token first-start/repair validation
remains a separate MSI check and was not run locally.

## Local RPC security review — 2026-10-15

Heads up, buddy: this entry records the earlier connection-only implementation.
The
[session-status implementation](#rpc-session-status-implementation--2026-10-15)
supersedes its isolated-child design and cleanup policy.

The private `ncalrpc` interface exposes a connection check to an isolated broker
child. The review checked Windows credentials, service-SID authorization,
restricted BFD identity, Identify-level QOS, server identity descriptors,
authorization-cache isolation, and asynchronous completion lifetimes against
Microsoft's guidance. The mechanisms and primary references are in
[Local RPC authentication and authorization](docs/rpc-authentication.md).

Native testing reproduced the RPC runtime's separate management-query surface.
BFD now denies every runtime management operation before opening its endpoint.
The application interface still admits authenticated connection checks. Binding cleanup
also fails closed inside the isolated child if unbind/free cannot complete.
The BGP provider COM/MI contract and its host privileges remain unchanged.

The implementation review passed 253 optimized tests, strict release Clippy,
executable hardening checks, and an explicit native MI schema compatibility
test. Native fixtures include wrong identities, anonymous callers, same-account
server replacement, management denial, cancellation, and bounded child cleanup.
The installed SCM-token handshake is a separate MSI first-start/repair check;
it was not run locally. Documentation and diagram changes do not establish that
deployment validation passed.

## RFC 5880 / RFC 7419 / RFC 7880 validation — 2026-10-09

Reviewed the published base BFD, common interval, and S-BFD specifications,
including RFC 5880's verified authentication errata. The requirement-to-test
mapping and implementation limits are in [RFC conformance tests](docs/rfc-conformance.md).

Added 22 regression tests across the RFC suites and native UDP tests. Coverage
includes asymmetric timing and exact expiry, all common interval pairs, all
255 multipliers, circular authentication windows for all four keyed types,
every individual authenticated bit tamper, incomplete authentication sections,
sequence resynchronization, S-BFD role markers and stateless reflection,
simultaneous Polls, reordered/consumed/expired reply sequences, large RTT and
interval arithmetic, maintenance spacing, and native timer rescheduling.
Failed-send sequence wraparound coverage now includes all four keyed types.

Two regressions reproduced one shared defect before its correction: a negotiated
base of 30 seconds or more hit the backoff cap without reducing traffic after
loss, in both classical multihop and S-BFD. The limit now allows the greater of
30 seconds and twice the base, saturating at the maximum wire interval. A
60-second base can therefore back off to 120 seconds. Fast sessions retain their
30-second cap; a valid response clears backoff. Maximum-width interval
saturation remains an explicit operational limitation.

All 215 default tests pass in both release and AddressSanitizer profiles.
Formatting, release Clippy with warnings denied, version-stamping tests,
protected ACL validation, production MSI compilation and table checks, and
hardening checks for both production executables pass. The initial sandboxed
full test run couldn't create temporary registry fixtures; the permitted native
run passed. This
validation doesn't establish hardware-level scheduling precision, interoperation
with another vendor, or live RRAS and installed-service shutdown/recovery.

## Reliability follow-up — 2026-10-09

The follow-up review identified two regressions and two older defects in the
preceding changes. Shutdown now signals cancellation under the BGP mailbox lock,
before the worker can dequeue its final action; interrupted final actions return
an error instead of being reported as superseded. Pipe acceptance resets and
retries when a client closes before acceptance. The broker's Stopped status is
terminal, including for queued control handlers. Live S-BFD settings retain a
retry obligation after rejected updates and read the latest values once per
second until they apply; a second notification is not required.

Operational limits were also added. `MaxShutdownAnnounceMs` defaults to 30000
and accepts 1–60000 milliseconds. Truncating a negotiated Detection Time logs a
warning and is an explicit deviation from the RFC announcement recommendation.
The installer sets BFD's Windows preshutdown timeout to 125 seconds and preserves
its previous value in the BSI3 rollback snapshot. A broker watchdog detects
provider requests active for 20 seconds, including schema lookup and cleanup,
while Running or stopping. Running timeouts exit without reporting Stopped so
SCM crash recovery restarts the broker; requested stops remain final. Status
reporting failures keep the worker under watchdog supervision until it ends.

Regression coverage includes cancellation publication and final-action errors,
native reconnect after a disconnect before acceptance, terminal broker status,
live settings retry after Poll completion, active-provider timeout detection,
bounded native UDP shutdown with a warning. Installation tests check the
preshutdown setting; rollback tests check restoration of the previous default.

Validation: all 193 default tests pass in the release and AddressSanitizer
profiles; the ignored read-only native MI schema test also passes. Formatting,
release Clippy, version stamping, protected ACL validation, and MSI compilation
and table checks pass. Live RRAS mutations, SCM recovery during a real provider
stall, and MSI installation/rollback remain Windows Server or CI integration
checks; the local review did not install or reconfigure services.

## Reliability and security review — 2026-10-09

Reviewed the whole codebase for crashes, stalls, races, and Rust/Windows security
issues. No memory-safety defect or remotely reachable panic was found: packet,
ancillary-data, and authentication parsing stay in bounds under `panic = "abort"`
and `overflow-checks = true`. These findings were fixed:

| Finding | Correction |
| --- | --- |
| Any receive or wait error other than WouldBlock or `WSAEMSGSIZE` ended the engine, stopping BGP, and BFD had no SCM recovery. | Network-condition Winsock errors pause socket use with a 10–250 ms backoff while timers continue. BFD restarts 10 seconds after a crash or unrequested failure exit; requested stops report exit code 0, so recovery never undoes a Stop. Both services use Automatic (Delayed Start). |
| Shutdown could take minutes, and StopPending checkpoints advanced indefinitely, hiding hangs. | Closing cancels a superseded in-flight call; each call of the final BGP action has a 20-second budget. BFD ends its process 60 seconds plus its AdminDown announcement period after Stop; the broker after 60 seconds. BFD accepts preshutdown, so its final BGP action reaches the broker before the shutdown phase. |
| Final events were written after SERVICE_STOPPED, when the process can end. | Both services flush logs before reporting Stopped; the broker creates its logger first. |
| BFD required the broker even without BGP, and a squatted pipe name stopped the broker. | BFD checks its broker connection only with `BgpPeerName`; the broker stays Running and retries the name each second. |
| Congestion backoff grew to about 71 minutes. | Backoff stops at 30 seconds, or a slower negotiated base. |
| Weak authentication settings were silent; peer events were unbounded; the file log never rotated; the reflector replied without limit. | Warning event 4 reports weak settings; session events are limited to 32 per second; the file rotates at 64 MiB to one backup; the reflector replies at most 1,000 times per second per source. |
| MI function-table entries were transmuted from `isize` to non-null function pointers. | `entry` rejects zero entries before conversion, so a missing entry is an error rather than undefined behavior. |
| The LocalService process kept SeImpersonatePrivilege. | Both run modes remove all but two privileges at startup. |
| Startup checkpoints never advanced; a connection-check/worker pipe race logged a spurious failure; S-BFD settings were read every second. | Startup advances checkpoints; clients wait briefly for a busy pipe instance; a registry change notification triggers reloads, with polling as a fallback. |
| `AuthKeyHex` accepted `+` signs; key copies were never cleared; the nightly toolchain floated. | Hex digits are checked; key buffers are wiped with volatile writes; `rust-toolchain.toml` pins `nightly-2026-10-01`; CI runs `cargo audit`. |

The `Restricted` service SID type was evaluated but not adopted: without a
runtime check of ETW under a write-restricted token, it
could not be validated.

Follow-up policy change: stopping BFD no longer stops BGP. Local AdminDown, set
only at service stop, maps to no BGP action. A Down caused by the peer's AdminDown
also leaves BGP unchanged, per RFC 5882 section 3.2, so stopping BFD at either end
keeps the BGP session. The broker no longer stops a peer when its client
disconnects or when it shuts down, so a BFD stop, failure, or crash leaves BGP on
its own hold timer.

Second follow-up, closing the RFC 5882 gaps: section 4.1 requires adjacencies to
be allowed while BFD is administratively disabled at either end, so local
AdminDown at service stop, or a peer's AdminDown, withdraws a Stop that BFD
issued by starting the peer; peers that BFD never stopped are untouched, and the
queued final action now runs at shutdown. Section 8 and RFC 5880 section 6.8.16
call for AdminDown to be asserted for at least one Detection Time, so the former
five-second cap is removed: the period is the longer Detection Time in either
direction, and the BFD stop budget extends by that period. After both follow-ups, all 186 tests pass in debug, `cargo test-release`, and `cargo asan`.

Validation on the pinned toolchain: `cargo fmt --check`; Clippy with
`-D warnings` for all targets in the dev profile and in CI's release
configuration; and all 182 tests in debug, `cargo test-release`, and `cargo asan`
with no sanitizer report. The ignored native MI test also passed under the
broker's narrower COM policy. New tests cover transient-error classification,
retry backoff and Stop-only pauses, notification wakeups, the event and reply
limits, file rotation, registry change notification, IPC cancellation and busy
pipes, privilege removal in a child process, the 30-second backoff ceiling,
exit-code policy, startup checkpoints, checked MI entries,
the BSI2 rollback snapshot, and hex-key parsing.

Not validated locally: building the MSI requires accepting the WiX OSMF EULA, so
`Test-Msi.ps1` table checks (recovery rows, broker start type) were
not run; their PowerShell syntax and the WiX XML were checked. The installation
and rollback scripts, now covering delayed start and recovery flags, run only on
GitHub-hosted runners. Transient Winsock faults have unit coverage but no fault
injection in the native UDP tests.

## MSI packaging review — 2026-10-08

Added the [Build Windows MSI workflow](.github/workflows/build-msi.yml),
[WiX package](installer/Package.wxs), and
[local build script](scripts/Build-Bundle.ps1). The x64, per-machine MSI installs
the documented Automatic LocalSystem service without starting it, registers
the event manifest with installed resource paths, creates the ProgramData
folder, and provisions the single-hop/file-logging defaults. Operators provision
addresses before starting the service.

Four executable-specific UDP rules cover classical control traffic, S-BFD
requests, replies to initiators' high source ports, and reflector responses.
The native WiX extensions provide installation, rollback, and removal actions.
Each registry default has a separate never-overwrite component so repair can
preserve administrator settings. Uninstall removes an empty log directory but
retains generated files. WiX and extensions are pinned to version 5.0.2;
GitHub actions use verified commit IDs and a read-only contents permission.

Local validation passed: production release build, WiX compilation, read-only
MSI table assertions for architecture, payload, service account/start type,
registry types/defaults, manifest resource resolution, firewall ports/directions,
and transactional action presence; checksum verification; production executable
hardening regression; actionlint; PowerShell syntax checks; documentation links;
and whitespace checks. No Rust source changed, so protocol suites weren't rerun.

The [installation test](scripts/Test-MsiInstall.ps1) runs only on a disposable
GitHub-hosted runner and exercises install, rendered ETW delivery, configured
service execution, file logging, repair, and uninstall. That test and the
complete GitHub workflow haven't been executed in this local session. Target
service, Event Log, and firewall configuration weren't changed locally. The
package is unsigned. See [Build the offline setup bundle](docs/development/packaging.md#build-the-offline-setup-bundle) and
[Install with the offline setup bundle](docs/setup.md#install-with-the-offline-setup-bundle).

Applied the `technical-documentation` skill to the setup, README, network,
and build references. **Score: 9/10 → 10/10** for the changed documentation
sections: file-only installation guidance is extended with the package procedure,
and installer behavior is verified against authoring and MSI tables. The revised
documents are linked in this record.

### Documentation change log

The documentation changes follow this skill-rule lineup:

| Change | Rule ID and name | Reason |
| --- | --- | --- |
| Add package installation, required provisioning, verification, and removal steps | P1 — Numbered, single-action procedures | Administrators can complete installation without creating duplicate service or provider registrations. |
| Document actual firewall ports, resource paths, registry defaults, and stopped Automatic service | P11 — Every behavior verified in code | The administrator reference matches the compiled package and explains which settings remain operator tasks. |
| Keep MSI build tooling and workflow details in the developer guide | R2 — Document type matches the reader's task (inferred taxonomy) | Systems administrators can install the package without build instructions. |

## State and diagnostic logging review — 2026-10-08

Reviewed state changes against
[RFC 5880 section 6.2](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.2)
and the state/diagnostic fields in
[section 4.1](https://www.rfc-editor.org/rfc/rfc5880.html#section-4.1).
The [Operational event reference](docs/logging.md#operational-events) lists all
22 event IDs, fields, and severity levels. Fixed these logging gaps:

| Finding | Correction |
| --- | --- |
| State text and ETW output were queued separately; the state-event helper alone produced no file entry. | Each state or diagnostic record owns both the ETW payload and its text representation. The worker submits it to ETW and writes the enabled file with the same ID and level. |
| AdminDown shared event 104 with Init; reflector maintenance was text-only, and reflector shutdown skipped state logging. | Dedicated Informational AdminDown event 106, Informational Up event 102, and separate Warning diagnostic 207 cover local session and reflector entity transitions. |
| Peer state or diagnostic changes were invisible when local state stayed unchanged. | Track one accepted peer report and emit remote state events 110–113 and diagnostic events 201–208. Authentication/packet rejection precedes report changes. Repeated reports are suppressed. |
| Diagnostics 2, 4, 5, 6, and 8 had no manifest mapping or events. | Report these peer reasons as Errors. Diagnostics 1, 3, and 7 are Warnings; 0 and reserved values have no standalone diagnostic event. Local optional Echo/path mechanisms remain unsupported. |

State and diagnostic severity are independent. Up and AdminDown remain
Informational, including recovery with a retained historical LocalDiag.
Entering AdminDown emits its state event and the Warning diagnostic 7 event.
Diagnostic 6 is Error, following the requested path-failure policy.
`--console` retains STDOUT and optional file output without ETW registration.

The administrative event-ID and file-output regressions first failed against
the preceding code. Tests cover every ID/level mapping, manifest agreement,
packed payload and origin fields, paired submissions/file lines, disabled file
output, ETW failure isolation, reflector maintenance/shutdown, and recovery.
Native UDP tests report all peer diagnostic codes while local state remains Up
and verify local timeout, peer-down, and shutdown diagnostics.

Applied the [rust-check skill](.codex/skills/rust-check/SKILL.md), the available
[rust-security instructions](.codex/skills/rust-security/SKILL.md), and relevant
[Rust skill rules](.codex/skills/rust-skills/SKILL.md). Event records move owned
buffers through the existing bounded queue; synchronous ETW writes borrow those
buffers. Peer reports use one inline Copy value, with no unbounded collection.
The changes add no unsafe code, protocol-loop locks, or secret-bearing messages.
The rust-security skill's referenced domain files remain absent.

Validation passed: **133 tests** in each debug, optimized, and ASan suite,
with one opt-in CIM schema test ignored; **35 session, event-payload, and S-BFD
tests** under Miri with strict provenance and tree borrows; formatting; strict
all-target Clippy; rustdoc with warnings and missing documentation denied; and
the rebuilt production release's x64 PE hardening/PDB regression. The manifest
compiled with the Windows SDK tools, and all 22 Rust descriptors match that
output. Native test suites ran sequentially to avoid shared loopback-port
conflicts. Documentation links and whitespace checks passed.

Native emission capture exercises the production output loop but doesn't
establish Event Viewer delivery. Installed provider registration, service
settings, and BGP state weren't changed. The existing 256-record queue and
500-millisecond shutdown drain limits still permit output loss when blocked.

### Documentation change log

Applied `technical-documentation` to the affected event references.
**Score: 9/10 → 10/10** for the event reference: the failed fact-verification
row is corrected, with no remaining blocking descriptions. The complete
revised reference is in [Logs and events](docs/logging.md).

The documentation changes follow this skill-rule lineup:

| Change | Rule ID and name | Reason |
| --- | --- | --- |
| Correct AdminDown, peer-report, reflector, and dual-output descriptions | P11 — Every behavior verified in code | The event reference matches the implementation and distinguishes submissions from delivery. |
| Document every state and diagnostic ID, level, and origin field | S6 — Tables have headers, introductions, and no empty cells | Administrators can look up event meanings and severity without reading source code. |
| Document accepted peer state/diagnostic getters and emitter-test limits | A1 — Every public element documented | Library callers and maintainers can interpret peer reports and validation evidence. |

## RFC 5880 conformance remediation — 2026-10-08

Re-read the complete [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880.html),
its errata, and the relevant RFC 7880 overrides. The
[requirement mapping](docs/rfc5880-conformance.md) records supported procedures,
optional features, and deployment limits. Fixed the confirmed discrepancies:

| Severity | Finding | Correction |
| --- | --- | --- |
| P1 | Local AdminDown reception left the authentication resynchronization clock stale, permitting replay after two detection periods despite fresh authenticated traffic. A session first receiving in AdminDown also never expired its learned discriminator. | Separate authenticated peer-validity and liveness clocks; preserve ordered AdminDown processing without starting detection. Both cases have regression tests. |
| P1 | An Up S-BFD TX increase took effect before Final; overlapping timer changes made Final acknowledgement ambiguous. An unsolicited Final also completed an unsent Poll. | Typed Pending/Sent/Quiet Poll states, a held effective TX rate, atomic rejection with `PollInProgress`, and non-Final separation after acknowledgement. |
| P1 | Classical multihop had no discovery congestion backoff. Failed socket sends consumed meticulous sequences and S-BFD probe/Final tracking. | Saturating timeout backoff with the preceding negotiated rate as its floor; packet preparation commits protocol tracking only after successful runtime sends. |
| P2 | Classical recovery cleared the previous failure diagnostic. Stale zero-RX advertisements suppressed active discovery indefinitely. Shutdown attempted only one AdminDown packet. | Retain LocalDiag through recovery; reset stale peer RX after one detection time; repeat permitted normal classical shutdown announcements for the detection period, capped at five seconds. |

The first eight RFC boundary regressions and the shutdown regression failed
before their fixes. A ninth boundary regression then exposed the need to retain
a slow peer's rate as the multihop backoff floor. Existing wire fixtures and the
16-case classical state matrix remain valid; the native recovery assertion now
expects the retained diagnostic.

Applied the [rust-check skill](.codex/skills/rust-check/SKILL.md), the installed
[rust-security skill](.codex/skills/rust-security/SKILL.md), and the relevant
[Rust guidelines](.codex/skills/rust-skills/SKILL.md). Packet I/O borrows one owned
buffer without cloning it. Small Poll states remain inline, probe tracking stays
bounded, backoff saturates, and authentication sequences explicitly wrap.
The changes add no unsafe code or shared locks to the protocol loop. The
rust-security skill's referenced domain files remain absent; this review applies
its available main instructions rather than claiming coverage of missing rules.

Validation passed: **124 tests** in each debug, optimized, and ASan suite, with
one opt-in CIM schema test ignored; **54 tests** covering configuration, packets,
sessions, S-BFD, and RFC boundary regressions under Miri with strict provenance
and tree borrows; formatting; strict all-target Clippy; rustdoc with warnings and
missing documentation denied; and a rebuilt production release passing its x64
PE hardening/PDB regression. The initial overlapping optimized/ASan runs caused
test-port conflicts; sequential runs passed. Native fixtures used temporary files,
HKCU keys, and loopback sockets. Installed service settings and BGP state were
untouched. Live SCM, Event Viewer delivery, real peer interoperability, and BGP
provider mutations remain outside this validation.

Applied the installed `technical-documentation` skill to the affected
administrator and developer references. **Score: 5/10 → 9/10**
for the updated pages: incorrect behavior descriptions are corrected, and the
requirement map distinguishes supported procedures from optional features and
bounded shutdown behavior. The complete revised text is in the linked guides.

### Documentation change log

The documentation changes follow this skill-rule lineup:

| Change | Rule ID and name | Reason |
| --- | --- | --- |
| Correct diagnostic recovery, validity clocks, stale RX, backoff, send commitment, and shutdown descriptions | P11 — Every behavior verified in code | Administrator references describe the implemented behavior and its limits. |
| Document `PollInProgress` and convenience packet API delivery obligations | A4 — Return values and exceptions documented | Library callers can handle deferred updates and failed sends correctly. |
| Add a focused RFC requirement map and link it from the README and development guide | R2 — Document type matches the reader's task (inferred taxonomy) | Maintainers can locate protocol evidence without mixing it into installation procedures. |

## rust-security remediation — 2026-10-08

Applied the installed [rust-security skill](.codex/skills/rust-security/SKILL.md),
which declares the name `build-rust`, and the relevant local Rust guidelines.
Fixed both confirmed defects from the review:

- **P1: blocked logging could stall protocol execution and shutdown.** Engine,
  BGP, MI cleanup, and service supervisor messages now share a bounded output
  worker. Producers use nonblocking enqueue operations. The control handler
  queues status diagnostics without performing output under its mutex. An unread
  STDOUT pipe regression first failed, then passed with bounded queue growth,
  a timed-out flush request, and successful engine shutdown.
- **P2: S-BFD accepted unusable startup addresses.** Configuration and receive
  validation now share the unicast, address-family, and loopback policy. Reserved
  IPv4, IPv4-mapped IPv6, and incompatible loopback sources fail startup instead
  of creating a session that discards every response. The regression first failed
  for `192.0.2.1` targeting `240.0.0.1`, then passed.

Also implemented the applicable API recommendations. `Options::into_validated`
produces an immutable shared snapshot with typed roles and nonzero S-BFD
identifiers. Registry loading validates once; runtime components reuse the
snapshot, while live timing and maintenance state remain separate. Public
configuration, packet, authentication, and receive errors are typed enums.
Key-bearing configuration still omits `Debug`, and errors omit secrets.

These changes affect library callers: `load_registry` returns `ValidatedOptions`,
`Logger::new` returns `io::Result<Logger>`, and domain APIs return typed errors.
See the [configuration and error API guide](docs/development/library.md#use-the-rust-configuration-and-error-apis).
Registry names and the `--console` interface remain compatible. The log queue
holds 256 records, caps text at 16 KiB, and allows up to 500 ms to drain on final
drop. Saturated or blocked output can lose records, including lifecycle events;
see [logging limits](docs/logging.md#log-destinations).

Validation passed: 112 tests in each debug, optimized, and AddressSanitizer suite,
with one opt-in CIM schema test ignored; 43 configuration, packet, classical
session, and S-BFD tests under Miri with strict provenance and tree borrows;
formatting; strict Clippy; and rustdoc with warnings and missing documentation
denied. The separate production release build passed its x64 PE hardening and
PDB-presence regression. Local documentation links and whitespace checks passed.

Native fixtures use temporary files, HKCU registry keys, and loopback UDP sockets.
No installed service configuration or BGP state was changed. Live SCM deployment,
Event Viewer delivery, and real BGP mutations remain untested. The installed
skill's domain reference files are absent; this applies its available main
instructions and does not claim complete skill compliance.

## rust-check remediation — 2026-10-07

Applied the explicitly requested [rust-check skill](.codex/skills/rust-check/SKILL.md) to the service code, using its minimal-change guidance. **The P2 console-output finding below is resolved.** `Logger` now uses fallible `Write` calls, reports console failure once per logger on a best-effort basis, and suppresses subsequent STDOUT writes while preserving console mode, file logging, and engine/BGP execution. Failed STDERR diagnostics cannot panic in the logger. The closed-pipe regression first failed on the old implementation with OS error 232, then passed after the fix, reaching AdminDown and recording subsequent lifecycle messages in the file log. No BGP provider mutation is needed for this regression.

Other targeted changes use `thiserror` for the internal receive-rejection enum, derive the applicable value traits for the small `Received` result, simplify entry-point imports and automatic error conversion, and express SDK PATH lookup with iterators. Native UDP log fixtures now use `tempfile` for ownership and cleanup; the existing console subprocess assertion uses `assert_cmd`. Public logger docs include a compiled example and describe output-error handling.

The synchronous Winsock timer loop and dedicated MI worker remain appropriate for the current runtime; adding an async executor would require a separate architectural change. Key-bearing configuration types continue to omit `Debug`. Existing public string error APIs remain compatible; the skill's preferences do not justify rewriting those interfaces in this fix. The skill's note-taking CLI examples and undefined “Constitution II” reference do not describe this project; its test-first instruction was applied to the stdout regression. No complete Rust-skill compliance claim is made.

The required `cargo fmt` and strict `cargo clippy --all-targets` checks passed. The default test suite passed 71 tests: 60 library tests, 2 service tests, 7 native UDP integration tests, and 2 doctests; the opt-in CIM schema test was ignored. The closed-pipe regression also passed with both STDOUT and STDERR unavailable, checking the diagnostic failure path. Rustdoc with warnings denied, the release build, release help, all 311 local documentation links, and `git diff --check` passed. Live SCM deployment, Event Viewer delivery, and actual BGP Start/Stop remain untested here.

## Review before remediation — 2026-10-07

Reviewed all service Rust modules, unit/integration tests, `build.rs`, Cargo configuration and lockfile, the ETW manifest, README, API comments, instruction files, and validation/review records at commit `66eeaf6`. Applied the local [Rust skill](.codex/skills/rust-skills/SKILL.md), concentrating on ownership/borrowing, native handle lifetimes and drop order, memory layout/alignment, unsafe pointer bounds, error handling, numeric conversion, and concurrency. Vendored skill examples and their checks crates are reference material rather than service code. This is a defect review, not a new 265-rule compliance matrix.

### Finding subsequently resolved

**P2 — Handle failed console writes without bypassing shutdown.** At that revision, [Logger::log](src/runtime.rs) used `print!` for STDOUT. Rust's [print documentation](https://doc.rust-lang.org/std/macro.print.html#panics) confirms that write failures panic. A standalone Windows probe connected STDOUT to an anonymous pipe, closed its reader, and called `Logger::new(true).service_started()`: `catch_unwind` observed a panic with OS error 232 (“The pipe is being closed”). The probe used no service configuration or BGP provider calls.

In that revision, a downstream reader closing the console pipe could unwind out of `run_session` before `Engine::run` reached AdminDown and its shutdown packet. A panic in the state-change log could also occur before the BGP Stop was queued. `Controller::drop` joined the worker and preserved already queued Stops but did not create a new Stop, so a previously started BGP peer could be left running. A log failure in the BGP worker could terminate that worker and prevent subsequent queued actions. The recommendation was to replace the panicking write with fallible `Write` handling and add a closed-pipe regression. This finding was open at the end of the documentation-only review and was subsequently resolved as described above.

No P0/P1 ownership, borrowing, or memory-safety defect was identified. Authentication rejection remains before session mutation; registry data has bounded initialized buffers and checked narrowing; ETW field order/widths and descriptors match the compiled manifest. Winsock ancillary parsing checks lengths before unaligned reads. MI results are copied while their operations remain live, child objects are released before parents, and provider calls stay outside the mailbox mutex. The existing BGP supersession and SCM lifecycle regressions cover the previously corrected races. This does not establish the absence of other defects.

### Documentation corrections

At the 2026-10-07 revision, the README distinguished permitted relative `LogFile` paths from the recommendation to use absolute paths under SCM. It also described numeric lifecycle Mode `0` and its `Windows service` rendering, and documented verbose gating and rate limits for generic discards/send errors. Documentation covered console output failure and its cleanup implications in the README and public runtime API comments. The 2026-10-05 review's CLI compatibility and test counts applied to its own revision. The registry configuration at the 2026-10-07 revision used `CommandLine` for `--console` and `Options::new`/`config::load_registry` for settings.

### Validation and limits

`cargo test --locked --offline` passed: 59 library tests, 2 service tests, 7 native UDP integration tests, and 1 compile-fail doctest (69 total); one namespace-dependent schema test was ignored. Strict Clippy, including `clippy::undocumented_unsafe_blocks`, passed. The closed-pipe probe reproduced the open finding above. After the documentation edits, `cargo fmt --check`, rustdoc with warnings denied, and `git diff --check` passed; release help matched the documented `--console`/help/version interface. All 310 local Markdown file links resolved. Comparing `src/runtime.rs` with its committed contents after removing API comments confirmed that production code was unchanged.

No full Miri rerun, live SCM installation/start/stop, manifest installation/Event Viewer rendering, or actual BGP Start/Stop was performed in this review. Native ETW registration/writes do not prove delivery to a registered Operational channel. The earlier validation records retain their own dates and limits.

## Historical review — 2026-10-05

Like, total flashback, turtle crew: these findings, compatibility notes, and
checks describe the revision before ETW and registry configuration were added.
They remain the record of that review; a fresh validation flex needs fresh
checks.

Reviewed all service source modules and tests, Cargo configuration, and operational documentation. Applied the relevant ownership, borrowing, memory layout, FFI, concurrency, error handling, and numeric rules from the local Rust skill. The earlier 265-rule assessment is preserved as a [historical guideline matrix](docs/archive/RUST_SKILLS_VALIDATION_2026-10-01.md); this review concentrates on defects and their fixes. [The current validation guide](RUST_SKILLS_VALIDATION.md) describes the API guarantees and links to that snapshot.

### Findings fixed

| Priority | Finding | Correction and evidence |
|---|---|---|
| P1 | A queued BGP Start could run after a newer Down/AdminDown, including during shutdown. A Down arriving during the preceding status query also failed to prevent Start. | Stop supersedes queued recovery actions; closing removes Starts; Start checks for supersession before and after querying. Mailbox, blocked-worker shutdown, and Down-during-query regressions pass. |
| P2 | SCM StopPending was reported only after `Engine::run` had already finished BGP cleanup. Concurrent startup could also overwrite a StopPending update if reporting were moved into the handler without synchronization. | The control handler reports StopPending immediately. One mutex serializes lifecycle reporting. A supervisor advances checkpoints while the engine thread finishes. Tests cover stop/start ordering, terminal state protection, and checkpoint fields. This follows Microsoft's [service control handler guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function). |
| P2 | A failed final BGP Stop was logged but service/console shutdown could still report success. | The worker returns its final error; explicit controller shutdown joins and propagates it through `Engine::run`. A mocked provider rejection regression verifies error propagation. Ordinary background failures still retry. |
| P2 | Public mutation of `AuthConfig.kind` could invalidate a previously validated key length and panic in verification. | The kind field is private with a read-only accessor. Authentication changes require a validated new configuration. A compile-fail doctest prevents the original mutation. This closes F1 in the earlier audit. |
| P2 | Programmatic options bypassed Clap numeric/conflict checks; raw session construction and writable session identifiers could emit invalid BFD packets. | `Options::validate` now checks all numeric ranges and key conflicts. Session construction validates and rejects mismatched authentication. Runtime construction validates and normalizes options before opening sockets; transport also checks numeric ranges. Session fields are read-only outside the crate. Constructor and options mutation regressions pass. This closes F2 in the earlier audit. |
| P2 | Only ICMP port-unreachable error reporting was disabled; Windows can also surface TTL-expired feedback as a UDP receive error, which the runtime treats as fatal. | Both `SIO_UDP_CONNRESET` and `SIO_UDP_NETRESET` are disabled. Native IPv4/IPv6 UDP tests exercise socket creation with both IOCTLs. ICMP packet injection was not performed. Microsoft's [Winsock IOCTL documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls) describes the two independent controls. |
| P3 | The older UDP handshake fixture did not join its engine on an assertion failure. | It now uses the same RAII shutdown/join fixture as the other engine tests. |

Also corrected unsafe union-access comments, replaced the ancillary parser's invariant-based `unwrap` with an explanatory `expect`, and updated README statements about BGP queueing, shutdown failure, and implemented routing integration.

### Protocol and FFI review

- Authentication is verified before peer state, timers, sequence tracking, or Poll/Final processing changes. Invalid authentication causes silent discard as required by [RFC 5880 section 6.8.6](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.6).
- BFD state transitions, detection expiry, passive transmission, remote Demand/zero receive-interval suppression, jitter, discriminator expiry, and keyed authentication sequence wrap/resynchronization were checked against RFC 5880. Local timer settings remain startup-only.
- MI function-pointer signatures were checked against the installed Windows SDK `mi.h`. Borrowed result pointers are consumed before fetching the next result or closing an operation. Normal result retrieval drains operations before closing; error cleanup attempts cancellation and draining, logging cleanup failures. Child native objects are released before their session/application.
- Provider calls execute on one BGP worker and never under the mailbox mutex. Queue growth is bounded. Already issued MI calls finish before the next state action; a later Stop follows an in-flight Start. There is no claim that an in-flight provider mutation can be atomically canceled when a UDP packet arrives.
- Ancillary data uses bounds-checked unaligned reads; real Winsock output lengths are checked before slicing. No new raw-pointer ownership or manual Send/Sync implementation was introduced.

### Compatibility at that revision

The 2026-10-05 changes retained the command-line interface then in use. Library callers had to handle `Session::new(...) -> Result<Session, String>`, use `AuthConfig::kind()`, and use the session's state/diagnostic/discriminator/polling accessors instead of public fields. Supplied session authentication had to match its options. Later changes replace the string error with typed errors and remove the former command-line settings; see the [configuration and error API guide](docs/development/library.md#use-the-rust-configuration-and-error-apis).

### Validation at that revision

| Check | Result |
|---|---|
| `cargo test --locked --offline` | 44 library tests, 2 service tests, 6 Windows UDP integration tests, and 1 compile-fail doctest pass. One namespace-dependent schema test is opt-in. |
| Explicit read-only CIM schema test outside the restricted sandbox | Pass; verifies qualifier metadata on `MSFT_NetAdapter`, without changing BGP. Total native/default plus explicit tests: 54. |
| `cargo clippy --locked --offline --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks` | Pass. |
| `cargo fmt --check` | Pass. |
| `cargo build --release --locked --offline` | Pass. |
| Miri with `-Zmiri-strict-provenance` | Full 39-test library suite passed before the final query-race regression was added. All 13 BGP tests then passed on the final code, including that regression; both pure service status tests also passed. |

Native Winsock and `mi.dll` execution are outside Miri's supported paths. They were checked through native UDP tests, native local MI fixtures, and the read-only schema test. SCM installation/start/stop and actual `PS_BgpPeer.Start/Stop` require a provisioned Windows Server and were not exercised against a live BGP peer. Provider timeout settings request five seconds per operation; they are not a guarantee that every provider call or teardown finishes within five seconds ([MI timeout semantics](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_operationoptions_settimeout)). No additional confirmed defect remains from this review; testing cannot establish the absence of all bugs.
