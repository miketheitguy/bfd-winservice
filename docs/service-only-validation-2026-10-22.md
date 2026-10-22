# Service-only validation — 2026-10-22

Cowabunga, validation crew. This record describes the service-only working tree
based on v3.0.2, commit `2a95110a1cb4265a923c7dfa3bb97f68e3a2bdc0`.
It records completed checks before the documentation audit; editing these guides
does not repeat the runtime tests. For commands and prerequisites, see
[development validation](development/validation.md).

## Tested change and revision scope

BFD accepts no command-line arguments and runs only through SCM. Both daemons
validate their installed identities and require exactly enabled
`SeChangeNotifyPrivilege` using read-only token queries. SCM supplies that
minimum before process creation; startup does not remove privileges. The
foreground runner, Ctrl+C handler, STDOUT logging, and public help/version
options are removed. The broker retains its private MSI transaction commands.

The private package retained version `3.0.2`; it is not the published v3.0.2
bundle or a new release. Removed CLI and Rust APIs require a major release.
See [migration and revision scope](console.md#revision-scope).
Final API comment clarifications followed packaging; functional daemon code
was unchanged after the tested build.

## Lab and results

The tests used the checkpointed Windows Server 2025 `BFD-WS2025` guest with
RRAS BGP and the Ubuntu 26.04.1 `BFD-Ubuntu2604` guest with BIRD 2.18.
The functional lab used 300 ms TX/RX intervals and multiplier 3. Authentication
material remained in protected lab configuration and is omitted here.

The completed checks produced these results:

| Check | Result |
| --- | --- |
| Required Rust tests, strict Clippy, formatting, and API documentation | Passed |
| Optimized tests and both opt-in RPC/MI coexistence checks | Passed |
| Rust/native AddressSanitizer suite | Passed |
| Fuzz harness regression tests | 9 passed |
| Production bundle/MSI build and hardening checks | Passed |
| Native Windows VM checks | 299 passed |
| Installed daemon argument and direct-launch rejection cases | 12 passed |
| Excessive SCM privilege rejection and corrected-policy recovery | Both services passed |
| Actual partial/full privilege rollback cases | 9 passed |
| Installer driver steps: install, repair, removal, rollback, prerequisite, bundle maintenance, and published-version upgrade | 7 passed |
| Functional Windows/Ubuntu scenarios | 46 passed |
| File-logging-disabled failure/recovery phases | 2 passed |
| Final stability observation | 120.8 seconds passed |

The 46 functional scenarios comprise 24 authentication cases covering
keyed SHA-1, meticulous MD5, meticulous SHA-1, and simple-password; three
isolated BIRD-controlled and three Windows-controlled withdrawal/recovery
cycles; two BGP-only cases; and 14 service, peer, process, adapter, and packet
interruption cases. The installed argument cases and RPC/MI checks overlap
the native check totals; the table is not an additive test count.

Final receipts confirmed the candidate executable hashes, original typed
configuration and keys, executable ACLs, BIRD configuration, both minimum SCM
policies, actual service tokens, BFD's restricted SID, BFD/BGP establishment,
both advertised /32 routes, timers, and removal of injected faults. Both VMs
were running at the end of validation; this is a dated observation.

## Evidence and limits

Local receipts remain in ignored output directories:

- `target/service-only/REPORT.md`, `summary.json`, `host-checks.json`,
  `asan.log`, and `fuzz-regressions.log` record the consolidated and host results.
- `target/service-only-20261022/` contains installer, rollback, deployment,
  native VM, live-token, and final-state receipts.
- `target/bird-interop/service-only-20261022/` contains functional matrices,
  rendered events, key-free wire metadata, and stability observations.

These paths are local evidence, not files distributed with the repository.
The consolidated summary was written at `2026-10-22T20:26:16Z`. No release-tag
workflow or published service-only asset is claimed by these checks.

The first route-suite attempt used an incorrect expected prefix introduced
while adapting the private harness's version string. The harness was corrected;
error capture and sampling of non-atomic CLI state were also tightened. The
affected route suite and remaining scenarios then passed. Failed harness
receipts were retained separately; no daemon fix was needed.

The normal sandbox blocked native token/registry fixtures. The complete native
checks passed in a normal token environment. Installed service and provider
mutations were confined to the disposable VM; host service policy was unchanged.
These results cover the tested Windows Server/BIRD pairing. They do not establish
other Windows versions, every historical upgrade, short-timer performance under
arbitrary load, or the absence of security defects. The fuzz result here is
regression coverage; it is not a new bounded fuzz campaign or a full Rust-rule audit.
