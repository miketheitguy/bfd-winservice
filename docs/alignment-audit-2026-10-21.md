# Documentation Audit: repository code, tests, and documentation

**Baseline score:** 8/10 — 7–8 band. The findings below describe the reviewed
baseline. See [remediation and release validation](#remediation-and-release-validation)
for the corrected v2.0.1 checkout and its validation limits.

**Baseline diagnostic:** 8/10 — failed rows: 2 (the validation guide mixes current guidance
and dated records), 3 (the deployment, telemetry, and socket-recovery contracts
have the mismatches below).

**Doc type / reader:** repository audit for Windows service maintainers and
operators. **Language:** en.

**Local style guide:** AGENTS.md, CONTRIBUTING.md, and established repository
conventions honored, including the existing conversational tone. This audit
prioritizes behavior and evidence over wording preferences.

**Baseline blocking findings:** the documented reflector deployment does not admit every supported
request source port; loose-file deployment omits a required native runtime;
telemetry loses configured IPv6 scope; socket recovery and transport descriptions
disagree across current references.

Reviewed baseline: `4f533483fba6ecbf907d51bb6d530ec0becba583`, package `1.5.0`,
on 2026-10-21 (America/Los_Angeles). The working tree was clean before the audit.
No P0 or P1 defect was confirmed. At that baseline the five confirmed findings
below were open; passing the existing tests did not resolve them.

## Baseline findings

The documentation rule severity and engineering priority describe different
things: P11 factual errors block a documentation sign-off even when their
engineering priority is P2 or P3.

| # | Location | Rule (ID + name) | Before | After | Severity |
| --- | --- | --- | --- | --- | --- |
| F1 | [Installer firewall rules](../installer/Package.wxs#L63), [reflector validation](../src/transport.rs#L191), [setup port table](reference/installation.md#installed-firewall-rules) | P11 verified behavior | The reflector accepts request source ports outside 49152–65535, but installed rules admit only that range. | Give reflector requests/replies their own port policy, preserve the classical restrictions, and update validators, tests, and the setup table together. | Blocking; P2 |
| F2 | [Status capture](../src/local_rpc/status.rs#L498), [scope test](../src/local_rpc/status/tests.rs#L157), [status contract](rpc-session-status-design.md#session-fields) | P11 verified behavior | Constructing local/peer socket addresses from bare IP addresses discards the configured link-local interface scope. | Preserve scope when constructing both configured endpoints and test the complete snapshot-to-RPC conversion. | Blocking; P2 |
| F3 | [Setup prerequisites](setup.md#before-you-begin), [loose-file preparation](console.md#prepare-installation-files), [contributor deployment instructions](development/packaging.md#prepare-installation-files) | P1 complete procedures | The loose-file route supplies executables and a logging script without provisioning or requiring the native Visual C++ runtime. | State the x64 runtime prerequisite and provide an installation/verification step before launching loose executables. | Blocking; P2 |
| F4 | [Socket recovery](protocol.md#socket-recovery), [warning reference](logging.md#service-warnings), [send handling](../src/runtime.rs#L563) | P11 verified behavior | General socket-recovery wording promises backoff, Warning event 4, and termination for other errors; send errors follow a separate policy. | Distinguish send errors from receive/wait errors, including retry cadence, event visibility, and shutdown behavior. | Blocking; P2 |
| F5 | [Broker security instructions](development/library.md#initialize-broker-management-security), [deployment text](development/packaging.md#prepare-installation-files), [service description](../installer/Package.wxs#L87) | P11 verified behavior | Current text still describes an authenticated local pipe, temporary pipes, and overlapped-I/O cancellation. | Describe authenticated `ncalrpc`, generated asynchronous RPC stubs, and the actual isolated native RPC fixtures. | Blocking; P3 |

### F1: installed rules exclude supported S-BFD initiators

`Datagram::validate` accepts a reflector request from source port `40000` when
the address, destination, TTL, and other checks pass. The inbound installer rule
for local port `7784` permits remote ports `49152-65535` only. Its reflector
outbound rule has the same remote-port restriction. A host relying on these
rules cannot receive the supported request from port `40000`; a host with
outbound default-deny policy also lacks the corresponding reply allowance.

This is an interoperability issue:
[RFC 7881 section 2](https://www.rfc-editor.org/rfc/rfc7881.html#section-2)
permits an initiator source port outside the dynamic range, excluding `7784`.
The implementation additionally rejects zero as a local policy.

The installer checks repeat the same restricted matrix:
[Assert-InstallerHardening.ps1](../scripts/Assert-InstallerHardening.ps1) and
[Test-MsiInstall.ps1](../scripts/Test-MsiInstall.ps1#L102). Thus they prove that
the current rules were installed, without checking that the rules admit the
transport's supported S-BFD traffic. Add coverage for ports on both sides of
`7784`, a port below `49152`, and a dynamic port; retain rejection of `0` and
`7784`. Exercise real installed traffic on a disposable host as well as the
static rule matrix. No live firewall policy was changed during this audit.

### F2: the codec test misses scope loss during capture

The existing test round-trips an already scoped `SocketAddrV6` through
`WireAddress`. That conversion works. The preceding capture step instead uses
`SocketAddr::new(s.local_address, ...)` and `SocketAddr::new(peer, ...)`, which
construct IPv6 endpoints with scope zero. The separately returned interface
index does not preserve the scope inside those endpoint values.

A temporary unit regression constructed a valid configuration with
`Local=fe80::1`, `Peer=fe80::2`, and `InterfaceIndex=17`, then captured and
converted its published snapshot. It failed with:

```text
actual:   [fe80::1]:52000
expected: [fe80::1%17]:52000
```

The peer construction has the same omission. Preserve scope only where it
applies, following `Options::address`; global IPv6 addresses should retain scope
zero. The accepted-source field already preserves the supplied socket scope.
The temporary test was removed and the original source file restored byte for
byte. Its reproduction and output remain in `target/audit-scope-regression.rs`
and `target/audit-scope-regression.log`.

### F3: loose executables require a runtime absent from the file list

The maintained native bridge is compiled with `/MD`. Inspection of the ordinary
production `bfd-winservice.exe` with `dumpbin /dependents` confirmed an import
of `VCRUNTIME140.dll`, in addition to the Windows CRT API-set imports. On a
machine without the native runtime, the loader can reject the process before
Rust starts, so neither `--console` nor `--version` can produce the documented
application output.

The setup bundle provisions this dependency. The separate loose-file route in
README, setup, and CONTRIBUTING does not list or install it. Document an x64
Visual C++ Redistributable compatible with the build; Microsoft's
[runtime deployment guidance](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170)
requires a runtime at least as recent as the MSVC tools used. A clean disposable
VM should verify the loose-file prerequisite and successful launch. The runtime
was not removed from this workstation to simulate that condition.

### F4: send failures do not use the receive/wait recovery path

`Engine::transmit` handles every send error by updating telemetry, queuing a
rate-limited text message, and returning normally. The reflector reply path
does likewise. Neither path classifies the error with `is_transient`, uses
`SocketFaults::pause`, emits Warning event 4, or returns a fatal send error to
SCM supervision. The next attempt follows the protocol/reply schedule.

The `Engine::run` API comment and the logging guide's
[console and packet text](logging.md#console-and-packet-text) section describe
this behavior correctly. The general protocol recovery paragraph and warning
reference need the same distinction. In the default service configuration, file
logging is disabled, so these send-error text messages are not Operational
events. Existing backoff tests exercise the helper's delay calculation; they
do not establish send-error behavior. Add injected send/receive/wait failures
if the implementation is changed to provide a unified policy.

### F5: the contributor guide retains the previous transport

The README, security references, implementation, IDL, and communication diagrams
agree on `ncalrpc`. CONTRIBUTING lines 414–415 and 568–571, plus the broker's
installed service description, retain pipe terminology. Update those current
descriptions without rewriting historical review records that explicitly
describe earlier designs.

## Additional test and release gaps

These are uncovered scenarios or missing guards, not demonstrated runtime
failures at this revision.

| ID | Priority | Evidence | Work needed |
| --- | --- | --- | --- |
| G1 | P2 | `Package.wxs` declares `MajorUpgrade`, but `Test-MsiInstall.ps1` requires a pristine machine. Bundle tests repeat install/repair of one version. Rollback fixtures model preexisting services, not an installed previous product. | Test previous-version-to-current bundle/MSI upgrade and failed-upgrade rollback, preserving Parameters, keys, logs, service policy, and uninstall behavior. Include a previous package with legacy COM registration if that migration remains supported. |
| G2 | P2 | The redistributable is pinned to `14.51.36247.0`, while native compiler discovery can select the latest installed toolset. Build/packaging checks validate the pinned runtime's provenance, not its compatibility with the selected compiler. | Pin the native toolset or reject a build whose required runtime exceeds the bundled minimum. Record compiler/runtime versions together. This host used MSVC `14.51.36231`, so this audit did not demonstrate a current version mismatch. |
| G3 | P3 | The session fuzz target constructs classical sessions only. Its timing action therefore exercises rejection of classical live updates. It does not generate initiator probes or drive the stateful S-BFD response-correlation path. | Extend the stateful harness with initiator/reflector exchanges, successful/failed transmission commitment, outstanding-probe expiry, sequence reuse/wrap, and live Poll changes. Existing deterministic S-BFD tests already cover substantial behavior; this is a fuzz-coverage extension. |

## Scope and alignment checks

The baseline inventory contains 131 tracked product text files (35,206 lines),
including 58 Rust files, six C files, one C header, two IDLs, two ACFs, 22
PowerShell scripts, and 29 Markdown documents. The audit traversed these product
areas and traced their public/operational contracts, with detailed review of
native boundaries and the mismatches above. Third-party dependency source and
bundled agent-skill documentation are outside the product-source inventory.

The following areas were compared:

| Area | Implementation, tests, and documentation compared |
| --- | --- |
| Packet/protocol | Encoding, authentication, sequence commitment, classical states/timers, S-BFD initiation/reflection, RFC suites, protocol/configuration/conformance references |
| Runtime/transport | IPv4/IPv6 metadata, source/path checks, scheduling, live registry reload, shutdown, status publication, UDP/status integration suites |
| Service/RPC | Startup identity and privilege reduction, native buffer ownership/alignment, FFI layouts, authorization, deadlines/cancellation, bounded workers, service supervision, security references |
| BGP/provider | Fixed targets, state-driven actions, retries/reconnection, administrative release, COM/MI lifetime and result handling, fake-provider and read-only native tests |
| Logging/events | Manifest IDs/severities/payloads, bounded queues, file rotation, failure handling, lifecycle and diagnostic guides |
| Packaging/release | WiX definitions, vendored runtime metadata/signature, installer and rollback validators, version stamping, CI gates, deployment instructions |
| Documentation/diagrams | All 29 project Markdown files, three editable diagram pages, three PNG exports, current guidance versus dated evidence |

No P0/P1 ownership, borrowing, layout, or resource-lifetime issue was confirmed
in the reviewed boundaries. Checks included aligned native output storage,
length/count/SID bounds, RAII allocator/handle pairs, struct drop ordering,
manual `Send`, non-unwinding exports, completion-before-release, and bounded
queues/workers. This records review scope and observed evidence, not a proof of
absence of defects.

## Baseline validation performed

All checks below used the repository's pinned Rust toolchain and locked
dependencies where applicable.

| Check | Result |
| --- | --- |
| `cargo test --locked --no-fail-fast` | 278 passed; 10 ignored |
| `cargo test-release` | 278 passed; 10 ignored |
| `scripts/Test-Asan.ps1` | 278 passed; 10 ignored; wrapper verified emitted native RPC ASan hooks |
| Three opt-in read-only CIM/RPC coexistence tests | All passed, including fixed-policy replacement rejection and BGP RPC/provider coexistence |
| Fuzz harness regression suite | Eight passed |
| `scripts/Test-Fuzz.ps1 -Seconds 15 -Runs 10000 -Offline` | All three targets completed 10,000 runs without a reported failure; final coverage values: packet 314, session 833, reflector 543 |
| Formatting and strict Clippy | Passed |
| Rust documentation with warnings and missing public documentation denied | Passed |
| Ordinary `cargo build --locked --release` | Passed after optimized tests; production abort profile restored |
| Production PE hardening test | Both service and broker passed architecture, mitigation, debug-output, and sanitizer-import checks |
| Vendored redistributable | Size, SHA-256, version, and Microsoft Authenticode signature passed `Test-VcRedist.ps1` |
| Release version fixture tests | Passed |
| ACL, installer-hardening, and rollback-privilege fixture tests | Passed, including 24 unsafe installer mutations and 19 privilege fixtures |
| PowerShell syntax | All 22 scripts and 69 documentation samples parsed |
| Local Markdown references | 872 references checked; 261 heading/ID fragments checked; no missing targets found |
| Diagram consistency | All three PNGs visually inspected; embedded node labels, styles, and edges match their editable source pages |

The first sandboxed native test run failed to create HKCU keys/restricted tokens.
The same full suite passed with normal host access. The ACL fixture similarly
passed outside the sandbox. Those failures are environment limitations, not
repository findings.

The 10 default ignored tests include three child-fixture entry points exercised
by parent tests, three read-only provider checks run explicitly above, three
installed-service checks, and one opt-in publication-cost measurement. The
installed-service checks and measurement were not run separately here.

No live MSI/bundle install, repair, removal, upgrade, firewall change, service
configuration change, RRAS mutation, real BGP Start/Stop, or OS preshutdown test
was performed on this workstation. Installer lifecycle scripts deliberately
require a disposable runner/VM. Miri was not installed in the pinned toolchain,
and was not run. External references were checked for the disputed S-BFD port
and runtime-deployment claims; this was not an external-link crawl or a fresh
certification of every RFC claim.

Detailed baseline inventory, execution logs, and the temporary scope reproduction
are under the ignored `target/audit-*` paths. That audit did not change the
production implementation or existing tests.

**Baseline rewrite plan:** fix the reflector firewall contract and scoped telemetry,
then complete the loose-file runtime prerequisite. Align send-error and RPC
transport descriptions with the chosen behavior. Add the upgrade and
compiler/runtime guards, then extend initiator fuzz coverage. To reach 10/10 on
the documentation diagnostic, also move dated validation records into linked
historical documents while retaining their anchors and evidence.

## Remediation and release validation

The v2.0.1 change set resolves F1–F5 and supplies the missing validation guards
identified in G1–G3. Current guides separate historical receipts from checkout
instructions; the [baseline validation guide](archive/RUST_SKILLS_VALIDATION_2026-10-21.md)
preserves dated records and the current guide retains their incoming anchors.

| Finding | Resolution |
| --- | --- |
| F1 | Five firewall rules separate classical control from reflector requests. Both reflector directions admit ports 1–7783 and 7785–65535. Static mutation fixtures and installed-filter checks use the same contract. An opt-in installed-service regression exercises ports 1, 7783, 7785, 40000, 52000, and 65535 and rejects 7784. Loopback traffic alone does not establish firewall enforcement. |
| F2 | Snapshot capture applies the configured scope to link-local local and peer endpoints. A full snapshot-to-RPC regression also checks global IPv6 and IPv4 without spurious scope. |
| F3 | README, setup, and contributor procedures include the verified native x64 runtime, checksum/signature checks, installation, and installed-version verification before console execution. Equal or newer runtimes are retained. |
| F4 | Protocol and warning references distinguish receive/wait backoff and Event 4 from send-error telemetry and rate-limited text output on the normal protocol schedule. |
| F5 | Current contributor instructions and the service description identify authenticated ncalrpc and asynchronous RPC cancellation fixtures. Historical descriptions remain dated. |
| G1 | A disposable-host gate upgrades from the real published v2.0.0 bundle. It forces deferred failure and requires restoration of both old executable hashes, MSI registration, typed configuration, service policy, and logs; then checks normal upgrade, updated firewall rules, repair, mutual RPC authentication, and removal. |
| G2 | Both production images record the selected native MSVC toolset and serviced CRT header version in their version resources. Packaging compares both versions with the pinned runtime and rejects missing or newer versions, including SkipBuild. Boundary fixtures cover compatible and incompatible versions. |
| G3 | A fourth safe-Rust fuzz target models S-BFD outstanding probes and exercises authenticated exchanges, loss, delayed replies, replay, timing updates, Poll/Final, maintenance, and rejection without consuming a valid probe. Native failed-send commitment and sequence wrap remain covered by focused crate regressions. |

Local validation of the corrected checkout:

| Check | Result |
| --- | --- |
| Debug, optimized, and native/Rust ASan suites | 279 passed and 11 ignored in each suite; ASan wrapper verified native RPC hooks |
| Three opt-in read-only RPC/provider checks | Passed |
| Root and fuzz formatting and strict Clippy | Passed |
| Rust documentation with warnings and missing descriptions denied | Passed |
| Fuzz regression suite | Nine passed |
| Four ASan fuzz targets | 10,000 runs each without a reported failure; final coverage: packet 314, session 835, initiator 1064, reflector 543 |
| Release version, native runtime, ACL, installer, and rollback fixtures | Passed, including 29 unsafe installer mutations and 19 rollback privilege fixtures |
| Production PE hardening and native runtime receipts | Both service and broker passed; MSVC toolset 14.51.36231 and CRT headers 14.51.36244.0 are covered by runtime 14.51.36247.0 |
| v2.0.1 offline bundle | Built and extracted; internal MSI tables, versions, runtime provenance, embedded bytes, detection policy, and checksum passed |
| PowerShell and documentation | All 26 scripts and 72 examples parsed; 950 local references across 32 Markdown documents resolved; three embedded diagram graphs match their source |

Hosted installation and upgrade validation passed at `83ba005` in
[workflow run 39721235148](https://github.com/miketheitguy/bfd-winservice/actions/runs/39721235148),
including the installed-reflector regression and actual v2.0.0 upgrade/rollback.
The final CRT servicing receipt was additionally validated locally with strict
Clippy, native/Rust ASan, production hardening, boundary fixtures, and bundle
extraction; the exact release tag reruns all hosted gates before publication.

Hosted installation and upgrade validation is enforced before release publication
by the ASan, fuzz, and build-msi jobs. Local logs are under `target/fix-*`;
installer mutation is confined to disposable hosted runners or the explicitly
provisioned VM. This workstation's installed services, firewall, and RRAS were
not changed. Previous-version coverage is v2.0.0, without legacy COM registration;
it does not certify every historical MSI. Real router interoperability, BGP
provider mutations, OS preshutdown, and Miri remain outside this run.

Version selection is documented in the [v2.0.1 release notes](releases/2.0.1.md):
compatible corrections to the v2.0.0 contract warrant a patch release.
