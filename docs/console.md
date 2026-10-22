# Run BFD in a console

Cowabunga, console crew. Run a foreground session to inspect BFD output without
installing Windows services. Use an elevated PowerShell window for file and
registry setup, and keep that window open for the commands below. You'll need
the [supported Windows host and peer settings](setup.md#before-you-begin).
For SCM execution and BGP management, follow the [bundle setup guide](setup.md).

## Prepare installation files

Pack the console gear before the pizza run. For a console-only deployment, copy
the supplied files to a permanent folder. If the bundle already installed them,
you're set; skip this section. Before launching a loose executable, verify and
install the supplied Microsoft runtime from the deployment folder:

```powershell
$deploymentDirectory = (Resolve-Path 'DEPLOYMENT_DIRECTORY').Path
$runtime = Join-Path $deploymentDirectory 'VC_redist.x64.exe'
$expectedHash = (Get-Content -LiteralPath "$runtime.sha256" -Raw).Split()[0]
if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Visual C++ runtime SHA-256 checksum mismatch'
}
$signature = Get-AuthenticodeSignature -LiteralPath $runtime
if ($signature.Status -ne 'Valid' -or
    $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The runtime must have a valid Microsoft signature'
}
$runtimeKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
$installed = Get-ItemProperty -LiteralPath $runtimeKey -ErrorAction SilentlyContinue
if ($null -eq $installed -or $installed.Installed -ne 1 -or
    [version]$installed.Version.TrimStart('v','V') -lt [version]'14.51.36247.0') {
    $result = Start-Process -FilePath $runtime -ArgumentList @(
        '/install', '/quiet', '/norestart'
    ) -WindowStyle Hidden -Wait -PassThru
    if ($result.ExitCode -notin @(0, 3010)) {
        throw "Visual C++ runtime installation failed: $($result.ExitCode)"
    }
    $installed = Get-ItemProperty -LiteralPath $runtimeKey
}
if ($installed.Installed -ne 1 -or
    [version]$installed.Version.TrimStart('v','V') -lt [version]'14.51.36247.0') {
    throw 'Install the x64 Visual C++ runtime 14.51.36247.0 or newer'
}
```

Replace `DEPLOYMENT_DIRECTORY` with the supplied folder, such as
`C:\Temp\BfdWinService`. Exit code `3010` requires a restart before use; the
command suppresses automatic restarts. An equal or newer runtime can be retained
after checking its installed version. See [runtime provenance](../installer/redist/README.md)
for the pinned installer and license. Then copy the console files:

```powershell
$deploymentDirectory = (Resolve-Path 'DEPLOYMENT_DIRECTORY').Path
$installDirectory = 'C:\Program Files\BfdWinService'
New-Item -ItemType Directory -Path $installDirectory -Force
foreach ($file in @(
    'bfd-winservice.exe', 'Initialize-Logging.ps1'
)) {
    Copy-Item -LiteralPath (Join-Path $deploymentDirectory $file) `
        -Destination $installDirectory
}
Get-ChildItem -LiteralPath $installDirectory | Select-Object Name
```

Replace `DEPLOYMENT_DIRECTORY` with the folder containing the supplied files,
such as `C:\Temp\BfdWinService`. Adjust `$installDirectory` if your organization
uses another location.

PowerShell displays the destination folder and the two copied filenames.
These files support console execution. Use the bundle for service execution;
copying files doesn't create services, service identities, or access policies.

## Start and verify the console session

Take the session on a foreground mission, turtle crew. Console execution reads
the same Parameters registry values as service execution. Run it as
Administrator when using the installer-protected key. Console mode does not authorize
BGP operations; leave `BgpPeerName` and `BgpRoutingDomain` unset for foreground
execution.

Dude, stop an installed `BfdWinService` before running the same session in a
console; both processes would otherwise compete for the same addresses and
ports.

### 1. Configure the registry values

For a bundle installation, set the executable folder:

```powershell
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
```

For loose files, retain the folder you chose in
[Prepare installation files](#prepare-installation-files). Follow
[Configure the session](setup.md#2-configure-the-session) to provision the local
and peer addresses and interface index. Optionally
[provision logging defaults](logging.md#1-optional-provision-the-defaults) before
starting; rerunning that script resets existing logging settings.

### 2. Start the foreground session

Start the installed executable in the foreground:

```powershell
$exe = (Resolve-Path (Join-Path $installDirectory 'bfd-winservice.exe')).Path
& $exe --console
```

Successful engine startup includes this standard output (STDOUT) message:

```text
TIMESTAMP service started mode=console
```

`TIMESTAMP` is the current time in Unix milliseconds. Messages, including
configuration failures, go to STDOUT. Console execution doesn't register or write
the ETW provider. See [Configure file logging](logging.md#configure-file-logging) for optional file
output with ISO-8601 UTC timestamps.

### 3. Verify the handshake

For the real connection flex, configure the remote peer and confirm the console
output contains `state=Up`. This confirms BFD establishment separately from the
`service started` message.

### 4. Stop the session

Press **Ctrl+C**. The engine uses the same AdminDown announcements and BGP cleanup
as [service shutdown](protocol.md#supported-modes-and-limits).

Classical settings are read at startup. Stop execution, edit the registry, and
restart to apply changes. For S-BFD timing updates, see
[Change timing and entity availability](seamless.md#change-timing-and-entity-availability).

### Optional: Capture console output

To save STDOUT instead of displaying it, start the console process with
redirection:

```powershell
& $exe --console > 'C:\ProgramData\BfdWinService\console.log'
```

The output file contains console messages with Unix-millisecond timestamps.
This shell redirection is separate from the `LogToFile` setting.

For file output, use the [logging procedure](logging.md#configure-file-logging).
