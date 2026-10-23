# BFD fuzzing harness

This harness is for Windows contributors testing BFD's untrusted input
boundaries. Use it to test the in-memory packet, authentication, and session
APIs with coverage-guided input mutation and AddressSanitizer. The package has
its own workspace and lockfile; it adds no production dependency or runtime
setting.

For the trust boundaries, acceptance and rejection assertions, build differences,
and coverage limits, see the
[fuzz harness security reference](../docs/security/fuzzing.md).

Choose a target for your test mission, dude:

| Target | Boundary |
| --- | --- |
| `packet` | Wire decoding and authentication |
| `session` | Classical session state and rejection invariants |
| `initiator` | Stateful S-BFD probes, reply correlation, replay, loss, and live timing |
| `reflector` | Stateless S-BFD request acceptance and authenticated replies |

The harness uses synthetic inputs and public authentication test bytes. Those
bytes provide no secrecy; don't use them as deployment keys. Targets call
in-memory APIs and don't open sockets, services, RPC endpoints, or BGP peers.
For exact input bounds, mutation strategy, and assertions, see the
[security reference](../docs/security/fuzzing.md#target-boundaries-and-checks).

## Set up Windows fuzzing

Install the repository's pinned Rust toolchain and Visual Studio C++ Build Tools
with AddressSanitizer, as described in [the contributor guide](../CONTRIBUTING.md#before-you-begin).
Run the build wrapper commands in PowerShell 7 (`pwsh`).
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
runs all four targets. It forwards the configured Windows hardening flags to
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

The [Build Windows bundle workflow](../.github/workflows/build-msi.yml) runs a
separate `fuzz` job on pull requests targeting `main` and release-tag pushes
matching `v*`. Ordinary pushes to `main` don't start full validation. See the
[workflow trigger policy](../docs/development/packaging.md#build-with-github-actions).
The job audits the fuzz lockfile, checks formatting and Clippy, runs
the harness regression tests, and runs all four ASan targets with
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

## Input formats

For stateful frame layouts and action tables, see [Stateful fuzz input formats](inputs.md).
