# BFD fuzzing harness

This harness is for Windows contributors testing BFD's untrusted input
boundaries. Use it to test the in-memory packet, authentication, and session
APIs with coverage-guided input mutation and AddressSanitizer. The package has
its own workspace and lockfile; it adds no production dependency or runtime
setting.

For the trust boundaries, acceptance and rejection assertions, build differences,
and coverage limits, see the
[fuzz harness security reference](../docs/security/fuzzing.md).

The targets check these properties:

| Target | Properties |
| --- | --- |
| `packet` | Arbitrary decoding and authentication never panic. Accepted input satisfies independent header and authentication constraints and round-trips through every supported authentication mode. |
| `session` | Rejected input preserves observable state. Explicitly malformed version, discriminator, and length cases are rejected. A session receiving arbitrary packets stays equivalent to a reference session that skips rejected packets. |
| `reflector` | Reflection is stateless and deterministic. Accepted requests satisfy the S-BFD constraints; replies authenticate, reverse the discriminators, acknowledge Poll, and preserve the keyed request sequence. |

Authentication stays enabled. Authentication test bytes are derived from public
input fields, with no embedded credentials: packet and reflector targets use the
sender discriminator's four network-order bytes; sessions use the selector byte
widened to four network-order bytes. The mutators and seed generator use the same
derivation to reach authenticated paths and preserve reproducible replay. These
public values provide no secrecy and must not be used as deployment keys. The
wrapper uses `--no-cfg-fuzzing` to retain normal conditional compilation.
Packet and reflector inputs are limited to 256 bytes.
A session input is limited to 2,049 bytes and processes at most 32 actions. The
targets use no sockets, service control, registry configuration, RPC operations,
or BGP provider calls. Transport metadata and native RPC unmarshaling need
separate fuzz targets.

Each target combines byte-level mutation with protocol-aware mutation. Packet
mutations rebuild and sign valid wire packets, reflector mutations retain the
S-BFD request constraints, and session mutations preserve the authentication
selector and fixed-size action frames. Deliberately invalid session actions
must be rejected without changing observable state. One-quarter of mutation
seeds use libFuzzer's default mutator so campaigns continue to explore malformed
lengths, authentication fields, and frame boundaries.

## Set up Windows fuzzing

Install the repository's pinned Rust toolchain and Visual Studio C++ Build Tools
with AddressSanitizer, as described in [the contributor guide](../CONTRIBUTING.md#before-you-begin).
The [Windows cargo-fuzz guide](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html)
describes the runtime requirements.

After you install the prerequisites, set up the driver and run a bounded
campaign:

1. Install the pinned driver into the ignored output directory. Run its
   installer outside the checkout so the production Cargo configuration does
   not apply to building the driver:

   ```powershell
   $repository = (Get-Location).Path
   Push-Location $env:TEMP
   try {
       cargo +stable install cargo-fuzz --version 0.13.2 --locked `
           --root (Join-Path $repository 'target/fuzz-tools') `
           --target-dir (Join-Path $repository 'target/fuzz-tools-build')
   } finally {
       Pop-Location
   }
   ```

2. From the repository root, run a bounded smoke campaign:

   ```powershell
   .\scripts\Test-Fuzz.ps1 -Seconds 15 -Runs 10000
   ```

The wrapper selects the MSVC compiler and matching ASan runtime, checks the
driver version, fetches locked dependencies, generates a starting corpus, and
runs all three targets. It forwards the configured Windows hardening flags to
cargo-fuzz, which otherwise replaces target-specific Rust flags. `--dev` selects
the fuzz package's optimized development profile with debug information, avoiding
the production profile's `/DEBUG:NONE`. The wrapper disables the repository's
global `build-std` setting by invoking cargo-fuzz outside the checkout because
cargo-fuzz 0.13.2 documents it as incompatible with sanitizer-coverage
instrumentation. The harness and its Rust dependencies receive AddressSanitizer
and coverage instrumentation; the pinned prebuilt standard library does not.
Fuzz builds omit the Rust EH-continuation compiler flag and final
`/GUARD:EHCONT` link setting because that prebuilt library has no matching
metadata. Production builds continue to rebuild the standard library with the
complete hardening configuration.

Confirm that each target ends with a `DONE` line containing a nonzero `cov`
value. The wrapper exits with an error if libFuzzer reports that the executable
has no coverage feedback.

The test-only libFuzzer C++ engine uses `/EHsc`, `/MD`, `/GS`, CFG, EH-continuation
metadata, `/sdl`, and visible `/W4` diagnostics. Its upstream narrowing, shadowing,
and unused-parameter warnings are nonfatal. The wrapper suppresses C4146 only
because `/sdl` promotes libFuzzer's intentional unsigned negation to an error.
CRT compatibility definitions permit its portable `fopen` and `putenv` calls.
These settings are scoped to the C++ engine; maintained RPC C retains its
independent `/W4 /WX` policy. All harness oracles are safe Rust. A narrow,
MSVC-only unsafe module registers the linker-provided sanitizer counters and PC
table after libFuzzer's C++ globals have initialized; the registration is
process-lifetime and runs once before the first oracle invocation.

## GitHub Actions

The [Build Windows MSI workflow](../.github/workflows/build-msi.yml) runs a
separate `fuzz` job on pull requests, pushes to `main`, version tags, and manual
dispatch. The job audits the fuzz lockfile, checks formatting and Clippy, runs
the harness regression tests, and runs all three ASan targets with
`-Seconds 15 -Runs 10000`. Each campaign stops at whichever budget it reaches
first, after compilation. Release publication requires successful `asan`,
`fuzz`, and `build-msi` jobs for the same workflow run.

On tags, version stamping updates the service entry in `fuzz/Cargo.lock` along
with the root manifest and lockfile. This keeps locked fuzz builds consistent
with the release version without changing the fuzz package's version or locked
third-party dependencies.

The diagnostic upload step runs even after a failure. It retains
`target/fuzz/*.log` and `target/fuzz/artifacts/**`, when present, for 14 days in
the workflow artifact `Fuzz-diagnostics-COMMIT_SHA`. Replace `COMMIT_SHA` with the
run's source commit. Download the artifact from the workflow run's **Summary**
page under **Artifacts**. The upload includes logs and failure inputs; compiled
executables and working corpora remain outside the diagnostic artifact.

To replay a downloaded failure, select its target and follow
[Run and reproduce cases](#run-and-reproduce-cases).

## Run and reproduce cases

Run one target for a longer campaign:

```powershell
.\scripts\Test-Fuzz.ps1 -Target session -Seconds 600 -Runs 1000000
```

The run stops at its input-count or time budget, whichever comes first. The time
budget applies after compilation. Each input has a five-second timeout and the
engine has a 2 GiB resident-memory limit. Mutated corpora, logs, and crash inputs
are kept under `target/fuzz`. Keep a failing input and replay it before changing
the code:

```powershell
.\scripts\Test-Fuzz.ps1 -Target session `
    -InputFile 'target/fuzz/artifacts/session/CRASH_FILE' -Offline
```

Replace `CRASH_FILE` with the saved artifact's filename. `-Offline` uses cached
dependencies. A successful replay after a fix exercises that exact input again.
Promote confirmed failures into focused regressions before removing their saved
artifacts. A bounded run establishes coverage of the executed inputs only.

For corpus regression tests without building the C++ engine, run:

```powershell
.\scripts\Initialize-Asan.ps1
cargo test --locked --manifest-path fuzz/Cargo.toml `
    --no-default-features --lib --target-dir target/fuzz-tests
```

Confirm the test suite passes. It checks session setup with input-derived
authentication, rejection with different authentication material, generated
seeds against their oracles, and mutator output structure, determinism, and
byte-level fallback.

## Session input format

The first byte selects `none`, `simple-password`, `keyed-sha1`, or
`meticulous-sha1` using its low two bits. All eight selector bits supply the
public value used to derive authentication test bytes. Each subsequent
64-byte frame has an operation byte, a time-advance byte in units of
10 milliseconds, and a payload.
The operation's low three bits select one of these actions:

| Value | Action |
| --- | --- |
| `0` | Receive the payload as arbitrary wire bytes. |
| `1` | Generate and sign a structurally valid packet from the payload. |
| `2` | Expire the session at the advanced time. |
| `3` | Attempt a timing update; classical sessions reject it. |
| `4` | Generate a signed packet, then set an invalid version. |
| `5` | Generate and sign a packet with the wrong receiver discriminator. |
| `6` | Generate and sign a packet with a zero sender discriminator. |
| `7` | Generate a signed packet, then remove its last byte. |

Actions `4` through `7` must be rejected without changing observable session
state. A final partial frame is accepted when it contains both control bytes.
Generated traffic keeps structural fields valid so mutations can explore state
transitions while raw reception covers rejection.
