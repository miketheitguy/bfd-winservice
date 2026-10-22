# Package and release the Windows service

Cowabunga, release crew. Build deployment files and publish the offline setup
bundle from one tested checkout. Complete the [development checks](validation.md)
and [production hardening check](../security/build-hardening.md#verification)
before packaging. Commands run from the repository root on the
[Windows build host](../../CONTRIBUTING.md#before-you-begin).

## Prepare installation files

Pack the whole turtle team from the same checkout. Keep the deployment bundle
dialed in: give administrators these files from the same source revision:

- `bfd-winservice.exe`: the release executable.
- `bfd-bgp-broker.exe`: the privileged BGP broker, installed by the MSI.
- `BFD-Service.man`: the Event Log provider manifest.
- `Initialize-Logging.ps1`: the script that provisions logging defaults.
- `VC_redist.x64.exe` and its `.sha256` file: the verified native x64 runtime
  prerequisite, required before loose executables can run.

Copy them into a deployment folder. Verify the runtime pin and both executable
toolset receipts before supplying loose files:

```powershell
.\scripts\Test-VcRedist.ps1
$runtimeVersion = (Get-Content 'installer/redist/VC_redist.x64.json' -Raw |
    ConvertFrom-Json).FileVersion
foreach ($name in @('bfd-winservice','bfd-bgp-broker')) {
    .\scripts\Test-NativeRuntime.ps1 `
        -Path "target/x86_64-pc-windows-msvc/release/$name.exe" `
        -RuntimeVersion $runtimeVersion
}
$deploymentDirectory = Join-Path $PWD 'target\deployment'
New-Item -ItemType Directory -Path $deploymentDirectory -Force
Copy-Item `
    -LiteralPath '.\target\x86_64-pc-windows-msvc\release\bfd-winservice.exe' `
    -Destination $deploymentDirectory
Copy-Item `
    -LiteralPath '.\target\x86_64-pc-windows-msvc\release\bfd-bgp-broker.exe' `
    -Destination $deploymentDirectory
Copy-Item -LiteralPath '.\events\BFD-Service.man' `
    -Destination $deploymentDirectory
Copy-Item -LiteralPath '.\scripts\Initialize-Logging.ps1' `
    -Destination $deploymentDirectory
Copy-Item -LiteralPath 'installer/redist/VC_redist.x64.exe',
    'installer/redist/VC_redist.x64.exe.sha256' -Destination $deploymentDirectory
Get-ChildItem -LiteralPath $deploymentDirectory | Select-Object Name
```

PowerShell displays the deployment folder and these filenames:

```text
Name
----
BFD-Service.man
bfd-bgp-broker.exe
bfd-winservice.exe
Initialize-Logging.ps1
VC_redist.x64.exe
VC_redist.x64.exe.sha256
```

Deliver the folder's contents with the [setup guide](../setup.md).
Administrators don't need Rust, the MSVC toolchain, or the Windows SDK to
follow that guide.

Loose files support console execution. Use the setup bundle for SCM execution: it
provisions the LocalService BFD process, Automatic (Delayed Start) LocalSystem broker, enabled
service SIDs, service dependency, and scoped registry/file/log ACLs. Native MI
code is confined to `src/bgp_broker/mi.rs`; the BFD worker uses `src/bgp/ipc.rs`.
Broker operations accept only fixed Get/Start/Stop frames and load their target
from protected configuration. Protocol, authorization, reconnect, disconnect
cleanup, and asynchronous-call cancellation tests use isolated native `ncalrpc`
endpoints and fake provider operations, with no service installation or BGP changes.

## Build the offline setup bundle

Cowabunga, packaging crew. Check the prerequisites before building. Install the
[.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or a later SDK.
WiX 7 requires explicit acceptance of its
[Open Source Maintenance Fee EULA](https://docs.firegiant.com/wix/osmf/). Hold
up, buddy: review the terms and any applicable maintenance fee before accepting
them. The build script accepts the EULA by default. To build the bundle, run from
the repository root:

```powershell
.\scripts\Build-Bundle.ps1
```

The script builds both hardened x64 production executables with Cargo's locked
dependencies, verifies the vendored Microsoft runtime's signature and checksum,
checks both executables' embedded native MSVC toolset receipts against that
runtime, and restores WiX and its extensions. It compiles one private MSI payload and validates its tables,
including per-machine scope and required administrator privileges. It then builds
the offline setup bundle, extracts it to verify the embedded packages and runtime
detection policy, and writes the bundle's SHA-256 checksum. Successful output
ends with the setup path. The internal MSI and WiX intermediate files stay in
`target\bundle-build\VERSION` for validation; no standalone MSI or MSI checksum
is generated in the distribution directory. The build removes standalone output
files left there by the previous packaging script.
For a local build, the package version comes from `Cargo.toml` and must contain
three numeric fields within Windows Installer's `255.255.65535` version limits.
To reproduce a tagged release locally, stamp its version before building:

```powershell
.\scripts\Set-ReleaseVersion.ps1 -Tag 'v1.2.0'
.\scripts\Build-Bundle.ps1
```

The stamping script updates only the `bfd-winservice` version in `Cargo.toml`,
`Cargo.lock`, and `fuzz/Cargo.lock`; dependency versions remain locked. It rejects malformed tags,
prerelease or build metadata, leading zeros, and versions beyond MSI limits.
Before packaging, the script checks the executable's `--version` output and
Windows file and product versions against the Cargo version. It also checks the
MSI's `ProductVersion` and packaged executable version. `-SkipBuild` rejects an
executable from another version; rebuild it before packaging.

Both executables use the same Cargo version and receive separate filename and
description resources. Tagged Actions builds stamp both from the GitHub tag.

Output files appear in `target\installer`:

| File | Purpose |
| --- | --- |
| `BfdWinService-VERSION-x64-setup.exe` | Offline bundle: native Microsoft runtime installer, then BFD MSI |
| `BfdWinService-VERSION-x64-setup.exe.sha256` | SHA-256 checksum of that setup bundle |

`VERSION` is the build's package version, such as `1.2.0`. Release builds
disable Rust PDBs for both services and WiX symbols with `-pdbtype none`.
Use `-SkipBuild` when changing installer authoring after already building the
matching production executable. The normal command always rebuilds the executable.

The script's `AcceptWixEula` switch defaults to true and passes
`-acceptEula wix7` to extension restore and package build commands. Explicit
`-AcceptWixEula` calls continue to work. Acceptance applies to these commands
without recording per-user acceptance.

The [.NET tool manifest](../../.config/dotnet-tools.json) pins WiX `7.0.0`; the script
restores `WixToolset.Util.wixext`, `WixToolset.Firewall.wixext`, and
`WixToolset.BootstrapperApplications.wixext` at the same
version into the ignored `.wix` cache and loads those exact versions for the
build. Administrators don't need .NET or WiX
to install the setup bundle. The internal BFD MSI and outer setup executable
are unsigned; signing isn't configured in this workflow. The embedded Microsoft
installer retains its valid Microsoft Authenticode signature.

The [bundle definition](../../installer/Bundle.wxs) embeds the unmodified x64
Visual C++ Redistributable from [installer/redist](../../installer/redist/README.md)
before the MSI. Registry detection skips an installed runtime of the pinned
version or newer. The native installer runs with `/install /quiet /norestart`;
failures stop the chain, and exit code `3010` requests a restart without forcing
one. The shared runtime remains installed after BFD removal or rollback.
Update the binary, provenance metadata, checksum, and documented runtime version
together when refreshing the prerequisite. `scripts/Test-VcRedist.ps1` verifies
the pin, and `scripts/Test-Bundle.ps1` verifies that the final bundle contains
the exact verified Microsoft installer and validated internal MSI.
The native build records the `vcvars64.bat` environment's `VCToolsVersion` in
each executable's Windows Comments field, together with the CRT version from
that toolset's `include/crtversion.h`. Servicing can change CRT revisions without
changing the toolset directory name. `Test-NativeRuntime.ps1` rejects missing
receipts or either version newer than the bundled runtime, including with
`-SkipBuild`. Refresh the runtime pin or select a compatible Visual Studio
installation when that guard fails. `Test-NativeRuntimePolicy.ps1` checks version
comparison boundaries. The build fingerprints the default-toolset selection file
and the CRT header so a Visual Studio update triggers a fresh receipt and native
compilation. The embedded runtime must cover both versions under Microsoft's
[redistributable compatibility policy](https://learn.microsoft.com/en-us/cpp/porting/binary-compat-2015-2017).

The [package definition](../../installer/Package.wxs) uses the `v4` XML schema
namespace, which WiX 7 retains, and uses
[ServiceInstall](https://docs.firegiant.com/wix/schema/wxs/serviceinstall/),
[ServiceControl](https://docs.firegiant.com/wix/schema/wxs/servicecontrol/),
[EventManifest](https://docs.firegiant.com/wix/schema/util/eventmanifest/), and
[FirewallException](https://docs.firegiant.com/wix/schema/firewall/firewallexception/).
WiX handles manifest/firewall installation, rollback, and removal through its
native extension actions. Resource paths resolve to the installed executable.
Core [PermissionEx](https://docs.firegiant.com/wix/schema/wxs/permissionex/)
elements apply protected SCM ACLs through `MsiLockPermissionsEx`. SYSTEM and
Administrators receive service full access (`0xf01ff`). Authenticated Users receive
only query config/status, enumerate dependents, interrogate, and read-control
rights (`0x2008d`); Start/Stop and configuration changes require elevation.
See [Windows service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
File-log read permissions and the Event Log channel policy remain unchanged.
Separate registry-value components preserve administrator values during repair.
Fixed-target native SCM custom actions provision accounts, service SID types,
delayed automatic start for both services, and recovery after a nonzero BFD exit.
They snapshot the previous settings in the protected installation directory,
restore them during MSI rollback, and remove the snapshot on commit.
WiX documents limitations in the native MSI service-configuration action; these
settings therefore use explicit SCM calls instead of `MsiServiceConfig` authoring.
See [WiX ServiceConfig](https://docs.firegiant.com/wix/schema/wxs/serviceconfig/).
The installed service is Automatic (Delayed Start) and remains stopped for address configuration.
See [bundle installation](../setup.md#install-with-the-offline-setup-bundle).

### Build with GitHub Actions

Send the build through its training session before calling it bodacious. The
[Build Windows bundle workflow](../../.github/workflows/build-msi.yml) runs on pull
requests, pushes to `main`, and version tags matching `v*`. It also supports
manual dispatch from a tag or branch. It audits `Cargo.lock` against the RustSec
advisory database with `cargo audit`, then checks version stamping, Rust
formatting, Clippy, and optimized tests on an x64 `windows-2025` runner using
`rust-toolchain.toml`. The auditor is built with stable Rust outside the
repository, so the repository's build-std configuration doesn't apply to it.
In parallel, the `asan` job runs `scripts/Test-Asan.ps1` on a separate Windows
runner, including native instrumentation verification and the default sanitized
test suite. It retains diagnostic logs and build records without uploading
instrumented executables.

The parallel `fuzz` job audits `fuzz/Cargo.lock`, checks harness formatting and
Clippy, runs the harness regression tests, and invokes `scripts/Test-Fuzz.ps1`.
Each of its four ASan campaigns stops after 15 seconds or 10,000 inputs,
whichever comes first; compilation is outside the campaign time budget. The job
uses the pinned cargo-fuzz driver and the repository's Rust toolchain on its own
`windows-2025` runner. See the [fuzz harness guide](../../fuzz/README.md#github-actions)
for the target scope and diagnostic artifact contents.

Every run builds and tests the offline setup bundle and its internal MSI. For a tag, the workflow
removes the leading `v` from a tag such as `v1.2.0` and writes `1.2.0` into the
service package entries in `Cargo.toml`, `Cargo.lock`, and `fuzz/Cargo.lock` in
the runner's checkout. The separate fuzz package keeps its own version.
The executables, MSI, setup bundle, artifact filenames, and installation checks use that
stamped version. Branch and pull-request builds use the version in `Cargo.toml`.
The workflow validates production executable hardening before
testing installation. Pull-request and branch runs upload validated artifacts
and installer logs with a read-only repository token. Release publication
requires a version tag, successful `asan`, `fuzz`, and `build-msi` jobs, and runs
in a separate job with `contents: write`.
No signing or release credentials are available to pull-request validation.
To enforce validation before merging, configure branch protection to require
`asan`, `fuzz`, and `build-msi`. Pushes to other branches can be checked by
manual dispatch.

The workflow explicitly passes `-AcceptWixEula` for bundle builds, accepting
the WiX 7 OSMF EULA for extension restore and package compilation.

In `build-msi`, linting, optimized tests, and production builds use the release
profile. Linting and tests enable unwinding for the test harness; the production
build uses
`panic = "abort"`. The final hardening check reuses the compiled release test
executable so it doesn't rebuild or replace the packaged production images.
The separate ASan job uses its development-derived profile and isolated output
directory; its artifacts never supply the MSI payload.

The installation test runs only on a GitHub-hosted runner. It checks fresh
installation, actual service configuration, registry types, firewall rules,
rendered Operational events, disabled/enabled file output, repair without
resetting settings, administrator service start/stop, installed service ACLs,
and uninstall while retaining generated logs.
`scripts/Assert-ServiceAccess.ps1` uses Windows `AccessCheck` with a temporary
Authenticated Users restricted token to verify query rights and reject Start/Stop,
pause, configuration changes, deletion, ACL changes, and custom controls. These
checks run on descriptor fixtures locally and the actual service descriptors in
the installation test. The migration rollback test also checks restoration of the
previous service security descriptor. It provisions
loopback addresses before starting the service. It doesn't run on
developer machines. It also checks the installed executable's versions and the
version shown in Windows installed-app settings. Build-time table validation is
read-only and can run locally.

The tests check both service accounts and SIDs, broker startup authorization
from the actual LocalService token, denial of authenticated unrelated clients
on both private RPC interfaces after install, broker recovery, and repair, both
executable versions, delayed start and recovery settings, SCM recovery after a
broker crash, and log writes through the BFD service SID.
`Test-MsiRollback.ps1` first injects an intentional failure into a temporary MSI
copy to exercise fresh-install and existing LocalSystem-account rollback, including
the delayed-start and non-crash recovery flags. Separate fixtures cover an absent
privilege policy, an empty request through SCM, a pre-existing empty registry
value, an explicit privilege list, and a restricted service SID. The empty registry
value is seeded only on a stopped test service on the disposable runner; the test
never starts that fixture. It
runs only on a disposable GitHub-hosted runner.

After MSI validation and removal, `Test-BundleInstall.ps1` installs the setup
bundle and checks runtime availability, both service accounts and executable
versions, repeated installation, repair, and removal that retains the shared
runtime. It verifies that maintenance skips an equal or newer runtime. On hosted
runners, the preinstalled runtime might already satisfy the prerequisite. The
script also supports explicit `-DisposableVm` testing on the provisioned
`BFD-WS2025` Hyper-V guest; testing from an absent runtime was validated there.

`Test-MsiUpgrade.ps1` then installs the published `v2.0.0` bundle, provisions
public authentication fixtures and custom log settings, and attempts an upgrade
with a deferred failure after service-policy mutation. It requires restoration
of the published executable bytes, old MSI registration, typed registry values,
service accounts/SIDs/privileges/recovery/ACLs, and generated logs. A subsequent
normal bundle upgrade and repair must retain those settings and start both
services with mutual RPC authentication. The workflow verifies the downloaded
baseline checksum before installation and retains `upgrade-validation.json`
with installer logs. This does not establish upgrades from every older release.
The installed-reflector loopback test separately covers legal source-port
boundaries and rejection of 7784; the installed firewall filters are inspected
independently because loopback traffic alone does not prove firewall enforcement.

To inspect the package without installing it, run:

```powershell
.\scripts\Test-Msi.ps1 `
    -Path '.\target\bundle-build\1.2.0\BfdWinService-1.2.0-x64.msi'
```

Adjust the filename for the package version. Confirm that validation reports
the x64 package's elevation requirement, service, payload, registry defaults,
firewall rules, and manifest lifecycle.

After a successful tag build, download the `BfdWinService-x64-COMMIT_SHA`
artifact. It contains only the offline setup bundle and its checksum.
`COMMIT_SHA` is the source commit. Installer test logs are uploaded separately,
including when a test fails.

### Publish a GitHub release

Pizza time comes after the release checks, dude. Pushing a version tag or
manually running the workflow on that tag publishes a
[GitHub release](https://github.com/miketheitguy/bfd-winservice/releases) after
the sanitizer, fuzz, build, hardening, and installation checks pass. The release
attaches the offline setup bundle and its SHA-256 checksum, using
`docs/releases/VERSION.md` as the release notes. Add that file before tagging and
explain the version choice and compatibility impact. Missing notes block a new
release publication.
The release title
includes the version tag, such as `BFD Windows Service v1.2.0`.

#### Tag and publish the release

Use a GitHub tag in the form `vMAJOR.MINOR.PATCH` as the release version source.
The MSI workflow accepts three numeric components without leading zeros,
prerelease identifiers, or build metadata. MSI limits the major and minor
components to 255 and the patch component to 65535.
The executable's `--version` output, Windows file and product version strings,
MSI `ProductVersion`, and installed-app `DisplayVersion` use the numeric part
of the tag, such as `1.2.0`.
Windows numeric file and product versions
append a fourth field of `0`, such as `1.2.0.0`. You do not need to commit a
matching Cargo version before releasing: the workflow stamps all three Cargo files
from the tag before running the build checks. Invalid release tags fail before
compilation.

To release a tested commit:

1. Choose the next version tag using [Choose a release version](../../CONTRIBUTING.md#choose-a-release-version).
   The commands use `v1.2.0` as an example. Keep the existing tag when retrying
   a release from the same commit.
2. Commit the tested release changes. Confirm that the commit contains the
   release workflow.
3. Create the version tag from that commit, for example:

   ```powershell
   git tag -a v1.2.0 -m "BFD Windows Service v1.2.0"
   ```

4. Push that tag:

   ```powershell
   git push origin v1.2.0
   ```

5. Wait for **Build Windows bundle** to succeed, then open the repository's
   **Releases** page. Confirm that the version's **Assets** include
   only `BfdWinService-1.2.0-x64-setup.exe` and its `.sha256` file.

Replace `1.2.0` with the chosen tag version. Only the release job receives
`contents: write`; the build job retains read-only repository access. Rerunning
the release job completes a draft or adds missing assets to an existing release.
It preserves assets already attached to a published release.
