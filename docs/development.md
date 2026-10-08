# Build and validate the service

This guide is for Rust developers building the Windows service and checking its protocol, registry, and native integrations. Run the commands from the repository root. Use [Set up a BFD session](setup.md) to deploy a fresh installation.

## Build

You need:

- Windows 10 or later, or a corresponding Windows Server release.
- Rust with a `windows-msvc` target.
- Visual Studio's **Desktop development with C++** workload, including the Microsoft Visual C++ (MSVC) toolchain and Windows Software Development Kit (SDK).

Build the executable and inspect its command-line help:

```powershell
cargo build --release
.\target\release\bfd-winservice.exe --help
```

A successful build creates `target\release\bfd-winservice.exe`. The help lists `--console`, `--help`, and `--version`; session settings come from the registry. Event Tracing for Windows (ETW) metadata and English messages are embedded during the build using the SDK's `mc.exe` and `rc.exe`.

Use Developer PowerShell if the MSVC linker is unavailable on `PATH`. The build finds the manifest tools on `PATH` or in the installed Windows 10/11 SDK. For a custom SDK location, set `BFD_MC_PATH` and `BFD_RC_PATH` to the absolute tool paths.

## Run development checks

Run these checks before committing Rust changes:

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- `
    -D warnings -D clippy::undocumented_unsafe_blocks
cargo fmt --check
$env:RUSTDOCFLAGS = '-D warnings -D missing-docs'
cargo doc --locked --no-deps
```

Confirm that the commands complete without errors. The documentation check also rejects undocumented public API elements.

Configuration validation and protocol modules are portable. Registry loading, User Datagram Protocol (UDP) transport, ETW, native Management Infrastructure (MI), and Windows Service Control Manager (SCM) integration require Windows. IPv4 time-to-live (TTL) metadata requires `IP_RECVTTL` support.

Native tests use temporary `HKEY_CURRENT_USER` (HKCU) registry keys, local MI fixtures, and loopback UDP sockets. They do not change installed service settings or Border Gateway Protocol (BGP) peers. The read-only Common Information Model (CIM) schema test requires namespace access and is opt-in. Run it separately:

```powershell
cargo test native_mi_reads_enum_qualifiers_from_local_class_schema -- --ignored
```

The default suite reports this schema test as ignored. With nightly Rust and Miri installed, check portable logic:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance'
cargo +nightly miri test --locked --lib -- --test-threads=1
```

Miri checks the portable logic and synthetic ancillary-data parser. Native Winsock, MI, registry, ETW, and subprocess tests are excluded. To check the parser with both strict provenance and tree borrows, run:

```powershell
$env:MIRIFLAGS = '-Zmiri-strict-provenance -Zmiri-tree-borrows'
cargo +nightly miri test --locked --lib ancillary_metadata
```

Validate SCM lifecycle, Event Viewer delivery, and actual BGP Start/Stop on the target server using the [setup guide](setup.md) and [BGP guide](bgp.md). For BGP testing, cover initially stopped and running peers, then disconnect and restore Bidirectional Forwarding Detection (BFD) while watching the logs and BGP state.

See the [validation guide](../RUST_SKILLS_VALIDATION.md) and [code review](../CODE_REVIEW.md) for recorded results and test limits.
