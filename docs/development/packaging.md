# Package and release the Windows service

Cowabunga, release crew. Use this guide to build and publish the offline setup
bundle from a tested checkout. Run commands from the repository root on the
[Windows build host](../../CONTRIBUTING.md#before-you-begin), after completing
[development validation](validation.md) and
[production hardening verification](../security/build-hardening.md#verification).

## Prepare installation files

Distribute the setup bundle and its matching SHA-256 file. It embeds both
service executables, the Event Log manifest, administration scripts, and
Microsoft's pinned x64 Visual C++ runtime. The MSI is a private bundle payload.
For installed accounts, permissions, and firewall rules, see the
[installation inventory](../reference/installation.md).

## Build the offline setup bundle

Install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or a
later SDK. The [.NET tool manifest](../../.config/dotnet-tools.json) pins WiX
and its extensions. Review the
[WiX OSMF EULA](https://docs.firegiant.com/wix/osmf/) and applicable maintenance
fee before building: `Build-Bundle.ps1` accepts that EULA by default through
`AcceptWixEula`.

To build the hardened executables and setup bundle, run:

```powershell
.\scripts\Build-Bundle.ps1
```

The script checks the runtime's signature/checksum, executable versions and
native runtime compatibility, MSI tables, embedded payloads, and prerequisite
detection. Successful output ends with the setup path. It writes:

| Output | Purpose |
| --- | --- |
| `target/installer/BfdWinService-VERSION-x64-setup.exe` | Offline setup bundle |
| `target/installer/BfdWinService-VERSION-x64-setup.exe.sha256` | SHA-256 checksum |
| `target/bundle-build/VERSION` | Internal MSI and WiX intermediate files |

`VERSION` is the package version from `Cargo.toml`. Both service executables
must match it. Use `-SkipBuild` only with already-built production executables
of that version. Release builds omit Rust PDBs and WiX symbols. The BFD MSI and
setup bundle are unsigned; the embedded Microsoft installer retains its
signature.

To reproduce a tag's version locally before building, run:

```powershell
.\scripts\Set-ReleaseVersion.ps1 -Tag 'v1.2.0'
.\scripts\Build-Bundle.ps1
```

Replace `v1.2.0` with the intended tag. Stamping updates the service package in
`Cargo.toml`, `Cargo.lock`, and `fuzz/Cargo.lock`, preserving dependency
versions. Accepted tags use `vMAJOR.MINOR.PATCH`, without leading zeros,
prerelease identifiers, or build metadata. MSI limits are `255.255.65535`.
Windows numeric file versions append a fourth zero; MSI and installed-app
versions use three components.

### Runtime prerequisite

Follow [runtime provenance and updates](../../installer/redist/README.md) to
refresh the pinned redistributable. Update its binary, metadata, and checksum
together. The build records both the MSVC toolset version and `crtversion.h`
version in each executable's Comments field. `Test-NativeRuntime.ps1` rejects
missing receipts or either version newer than the bundled runtime, including
with `-SkipBuild`. If that check fails, update the runtime pin or select a
compatible Visual Studio installation.

The bundle skips an equal or newer installed runtime, retains the shared runtime
after BFD removal or rollback, and accepts exit code `3010` without forcing a
restart. See [installation](../setup.md#install-with-the-offline-setup-bundle)
for checksum verification, setup switches, and repair.

### Inspect the MSI without installing it

To validate MSI metadata without changing installed services, run:

```powershell
.\scripts\Test-Msi.ps1 -Path 'MSI_PATH'
```

Replace `MSI_PATH` with the internal MSI under `target/bundle-build/VERSION`.
The check reports x64/elevation requirements, services, payload, defaults,
firewall rules, and manifest lifecycle.

## Build with GitHub Actions

The [Build Windows bundle workflow](../../.github/workflows/build-msi.yml) runs
on pull requests targeting `main` and tag pushes matching `v*`. Ordinary branch
pushes and manual dispatch don't trigger it. Open or update a pull request to
validate a branch; require these jobs through branch protection:

| Job | Validation |
| --- | --- |
| `asan` | Rust/native ASan tests with native instrumentation verification |
| `fuzz` | Fuzz dependency audit, formatting, linting, regression tests, and four bounded ASan campaigns |
| `build-msi` | Dependency audit, version/ACL/key/recovery fixtures, formatting, release Clippy/tests, RPC/MI coexistence, production hardening, and installer lifecycle tests |

Each job uses the pinned Rust toolchain on a separate `windows-2025` runner. Tag
builds stamp their version before validation; pull requests use `Cargo.toml`.
ASan output is separate from production payloads. Test harnesses use unwinding;
production executables use `panic = "abort"`.

### Installer lifecycle coverage

Run installation tests only on a hosted runner or the explicitly selected
disposable `BFD-WS2025` VM. They install/remove services and change SCM,
registry, Event Log, and firewall state. Preserve the lab configuration and
checkpoint first; see
[disposable-host validation](validation.md#validate-installed-service-security-in-a-disposable-vm).

The workflow runs these suites in order:

| Suite | Checks |
| --- | --- |
| [Test-MsiRollback.ps1](../../scripts/Test-MsiRollback.ps1) | Fresh/existing-service rollback; exact restoration of dependency lists, security descriptors, SID and recovery policy, and distinct absent/empty/explicit privilege fixtures |
| [Test-MsiInstall.ps1](../../scripts/Test-MsiInstall.ps1) | Fresh installation, independent service lifecycle, actual tokens, expected startup rejection, mutual RPC authentication, unrelated-caller denial, broker recovery, ETW, file logging/rotation, repair, and removal |
| [Test-BundleInstall.ps1](../../scripts/Test-BundleInstall.ps1) | Runtime detection, repeated installation, repair, removal, and shared runtime retention |
| [Test-MsiUpgrade.ps1](../../scripts/Test-MsiUpgrade.ps1) | Published-baseline upgrade and injected failed-upgrade rollback preserving bytes, registration, configuration, service policy, ACLs, and logs |

The workflow downloads and verifies its upgrade baseline. That fixture covers
the named baseline, not every release. Use a VM without the runtime to test its
actual installation; hosted runners can already satisfy that prerequisite.
Loopback reflector tests and firewall-rule inspection establish separate checks.
They don't prove external firewall enforcement or peer interoperability.

After a successful build, `BfdWinService-x64-COMMIT_SHA` contains the setup
bundle and checksum. Installer logs, including bounded service diagnostics on
failure, are uploaded separately. `COMMIT_SHA` identifies the source commit.

## Publish a GitHub release

Publication requires successful `asan`, `fuzz`, and `build-msi` jobs for a
version tag. Only the separate publication job receives `contents: write`;
pull-request validation has read-only repository access. The release uses
`docs/releases/VERSION.md` as its notes and attaches only the setup bundle and
SHA-256 file. Missing notes block publication.

### Tag and publish the release

To release a tested commit:

1. Choose an unused version under the
   [release version policy](../../CONTRIBUTING.md#choose-a-release-version).
2. Add `docs/releases/VERSION.md` with functionality, compatibility, version
   rationale, and validation limits. Update the canonical guides and commit the
   tested changes. The tag workflow stamps Cargo versions from the tag.
3. Create and push an annotated tag, replacing `1.2.0` with the chosen version:

   ```powershell
   git tag -a v1.2.0 -m "BFD Windows Service v1.2.0"
   git push origin v1.2.0
   ```

4. Wait for **Build Windows bundle** to succeed. On the
   [Releases page](https://github.com/miketheitguy/bfd-winservice/releases),
   verify the setup/checksum assets and check the downloaded setup's SHA-256.

Keep published tags and assets unchanged. Diagnose a failed check before
retrying the same commit. If source changes, validate it and select the next
version. The publication job can complete a draft or add missing assets without
replacing assets already attached to a published release.
