# Contribute to BFD Windows service

Developers, let's build something totally tubular. This guide gets you from a
checkout to a tested change. Run commands from the repository root. For
installation and operation, use the [administrator guides](docs/README.md).

## Choose a development task

Pick your mission, code crew:

| Task | Guide |
| --- | --- |
| Build an executable | [Build the executable](#build-the-executable) |
| Run required, optimized, ASan, Miri, or native checks | [Development validation](docs/development/validation.md) |
| Inspect compiler protections or a production executable | [Build hardening](docs/security/build-hardening.md) |
| Change library APIs, engine ownership, or RPC boundaries | [Library and service development](docs/development/library.md) |
| Run fuzz campaigns or replay crashes | [Fuzz harness](fuzz/README.md) |
| Update Mermaid and Draw.io views | [Diagram maintenance](docs/development/diagrams.md) |
| Prepare deployment files, build installers, or publish a release | [Packaging and releases](docs/development/packaging.md) |

## Before you begin

Get your development gear together before you kick shell:

- 64-bit Windows 10 or later, or Windows Server 2016 or later, on an
  x64 processor.
- Rust installed through rustup. The repository's `rust-toolchain.toml` pins a
  dated nightly Rust, `x86_64-pc-windows-msvc`, Clippy, rustfmt, and `rust-src`,
  so every build and release uses the same compiler. Update the date deliberately
  and rerun the full test, ASan, and hardening checks when you do.
- Visual Studio's **Desktop development with C++** workload, including the Microsoft Visual C++ (MSVC) toolchain and Windows Software Development Kit (SDK).

The Windows local RPC interface also needs the SDK's MIDL compiler (`midl.exe`)
and the x64 MSVC compiler and librarian (`cl.exe` and `lib.exe`). The build
generates RPC stubs from the interface definition and compiles a small native
wrapper that contains Windows RPC exceptions. Service logic and authentication
remain in Rust.

Before you ship, bring receipts, dude: record the checks you ran and the
deployment behavior that still needs a provisioned Windows Server.

## Build the executable

Bodacious builds start with the compiler output. Build and inspect the file version:

```powershell
cargo build --locked --release
(Get-Item '.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe').VersionInfo |
    Select-Object FileVersion, ProductVersion
```

A successful build creates
`target\x86_64-pc-windows-msvc\release\bfd-winservice.exe`. BFD accepts no
command-line arguments and runs only through SCM. Session settings come from
the registry; file properties contain the version.
Event Tracing for Windows (ETW) metadata and English messages are embedded during
the build using the SDK's `mc.exe` and `rc.exe`. Windows file properties also
contain file and product versions generated from `Cargo.toml`.

The build finds `midl.exe`, `mc.exe`, and `rc.exe` on `PATH` or in the installed
Windows 10/11 SDK. It discovers the x64 MSVC environment through Visual Studio
environment variables or `vswhere.exe`, then loads `vcvars64.bat` for the native
RPC build. For custom installations, set `BFD_MIDL_PATH`, `BFD_MC_PATH`, and
`BFD_RC_PATH` to the corresponding absolute tool paths, and
`BFD_VCVARS64_PATH` to the absolute path of `vcvars64.bat`.

## Run development checks

Before submitting Rust changes, run the [required checks](docs/development/validation.md#required-checks).
Choose additional coverage for changed native boundaries, protocol behavior,
or build settings. Record what ran and what still needs a provisioned server.
For dated results, see the [validation records](RUST_SKILLS_VALIDATION.md).

## Write and maintain documentation

Keep the slang, dude. Cowabunga belongs here; exact commands, identifiers,
and protocol meanings still need to be clear.

- Give each fact or procedure one main home and link to it elsewhere.
- Keep operator steps in the administrator guides. Put implementation details
  in the development, reference, or security documents.
- Include prerequisites and verification with each procedure.
- Keep the PNG images, editable Draw.io pages, Mermaid views, and text
  explanations aligned. Follow [diagram maintenance](docs/development/diagrams.md).
- Keep dated test receipts tied to their original revisions. A prose edit
  doesn't earn a fresh runtime victory lap.

## Choose a release version

Use [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) to choose
the next version. Start from the latest published release on the intended
release line and review the complete set of changes since that release.
As the maintainer or release agent, choose the increment based on compatibility
and functionality, and explain the decision in the release notes.

The public contract includes supported command-line options, registry settings,
service behavior, BFD interoperability, public Rust APIs, supported Windows
versions, and installation and upgrade behavior. Choose the highest required
increment for changes to that contract:

| Change | Increment | Example from `v1.10.0` |
| --- | --- | --- |
| Compatible bug fixes | Patch | `v1.10.1` |
| Compatible functionality or a public API deprecation | Minor; reset patch to zero | `v1.11.0` |
| Incompatible public contract changes | Major; reset minor and patch to zero | `v2.0.0` |

Use a patch release for fixes such as correcting status-publication timestamp
ordering without changing supported interfaces. Use a minor release for an
optional protocol role or configuration capability that preserves existing
deployments. Adding an optional offline setup bundle while retaining the
standalone MSI would be compatible functionality. Switching to bundle-only
distribution removes the documented standalone MSI deployment contract, so it
requires a major release, such as `v2.0.0` after `v1.10.0`. Existing installations
can upgrade through the bundle; deployment scripts must switch from `msiexec`
to the setup executable and its switches. Describe that migration in release notes.
Substantial internal functionality or improvements can also
justify a minor release; explain the benefit and verify compatibility.
Documentation, test, refactoring, dependency, or security labels alone don't
determine the increment. A bug-fix-only release uses a patch increment regardless
of the size of the fix.

Version private RPC interfaces separately from the product. Check any supported
mixed-version behavior before treating an internal change as compatible.
Keep published tags and assets unchanged; apply this policy to subsequent
releases.

For tag syntax, release gates, and publication steps, see
[Package and release the Windows service](docs/development/packaging.md#publish-a-github-release).

## Submit a change

Make the handoff totally tubular for the next maintainer:

1. Update tests when behavior or validation changes.
2. Update the canonical guide when configuration, service behavior, logging,
   or build procedures change; link to it from related pages.
3. Run the applicable [development checks](docs/development/validation.md).
4. Describe the resulting behavior, checks performed, and validation limits
   in your change description.
