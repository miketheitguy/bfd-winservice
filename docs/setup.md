# Set up a BFD session

Cowabunga, install crew. Use this guide to install, configure, and verify a
classical Bidirectional Forwarding Detection (BFD) session on Windows. The
offline setup bundle provisions both services, the native Microsoft Visual C++
runtime, and their security settings. The service monitors one local/peer pair.
For foreground execution, follow [Run BFD in a console](console.md).

This procedure configures classical BFD. For initiation without a handshake or
a stateless responder, use [Configure Seamless BFD](seamless.md).

The startup vibe check has two parts, dude: Windows reports `Running`, then BFD
reports `Up` after it establishes peer communication.

Choose the path for your deployment:

- For Windows services, [install the setup bundle](#install-with-the-offline-setup-bundle), then
  [configure and verify the service](#configure-and-verify-the-windows-service).
- For foreground execution, follow [Run BFD in a console](console.md).
- For removal, use the [setup bundle uninstall procedure](#remove-a-setup-bundle-installation) or
  the [legacy manual removal procedure](reference/legacy-installation.md).

## Before you begin

Gather the gear before the ninja mission starts:

- Obtain the x64 setup bundle and its `.sha256` file from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases).
- Use 64-bit Windows 10 or later, or Windows Server 2016 or later,
  on an x64 processor.
- Open **PowerShell as Administrator**. Use the same
  window throughout the service procedure so its PowerShell variables remain set.
- Choose distinct unicast `Local` and `Peer` IP literals of the same address
  family. Configure the remote peer with these addresses reversed.
- Allow the [required network traffic](protocol.md). The service doesn't create
  firewall rules or discover peers. The bundle installs the rules described in
  [installed firewall rules](reference/installation.md#installed-firewall-rules).

Get your bearings: find the interface that owns your local address:

```powershell
Get-NetIPAddress |
    Select-Object IPAddress, InterfaceAlias, InterfaceIndex
```

Find your local address in the output and use its nonzero interface index for
the default single-hop session.

## Install with the offline setup bundle

Download `BfdWinService-VERSION-x64-setup.exe` and its `.sha256` file from the
version's **Assets** on
[GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases).
`VERSION` is the release tag without its leading `v`. The bundle embeds
Microsoft's unmodified x64 Visual C++ Redistributable `14.51.36247.0` and the
service package; installation doesn't require an internet connection, .NET,
or WiX. An installed runtime of that version or newer is detected and retained.
See [runtime provenance](../installer/redist/README.md) for the download source,
checksum, signature verification, and Microsoft license terms.

In **PowerShell as Administrator**, check the checksum and install:

```powershell
$setup = (Resolve-Path 'SETUP_PATH').Path
$expectedHash = (Get-Content -LiteralPath "$setup.sha256" -Raw).Split()[0]
if ((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Setup SHA-256 checksum mismatch'
}
$log = Join-Path $env:TEMP 'BfdWinService-setup.log'
$result = Start-Process -FilePath $setup -ArgumentList @(
    '/install', '/quiet', '/norestart', '/log', ('"' + $log + '"')
) -WindowStyle Hidden -Wait -PassThru
if ($result.ExitCode -notin @(0, 3010)) {
    throw "Setup failed; inspect $log"
}
Get-Service BfdWinService, BfdBgpBroker | Select-Object Name, Status, StartType
```

Replace `SETUP_PATH` with the downloaded `.exe` path. Keep its matching
`.exe.sha256` file in the same folder. Exit code `0` indicates success; `3010`
indicates success with a restart required. The command suppresses automatic
restarts. Both services remain stopped so you can
[configure and start the session](#configure-and-start-the-installed-session) before
restarting Windows. The setup log and adjacent package logs record failures.

Run the setup executable without arguments for an interactive installation.
For repair, use the same command with `/repair` instead of `/install`.
For an upgrade from an earlier MSI installation, run the setup bundle and then
verify your retained registry settings before starting the services. Deployment
automation must use the setup executable and its switches; a standalone MSI
isn't distributed.

## Remove a setup bundle installation

In **PowerShell as Administrator**, run the setup executable with `/uninstall`:

```powershell
$result = Start-Process -FilePath 'SETUP_PATH' -ArgumentList @(
    '/uninstall', '/quiet', '/norestart'
) -WindowStyle Hidden -Wait -PassThru
if ($result.ExitCode -notin @(0, 3010)) {
    throw "Setup removal failed with exit code $($result.ExitCode)"
}
```

Replace `SETUP_PATH` with the local setup executable path. You can also remove
**BFD Windows Service** through Windows installed-app settings. Removal
uninstalls the BFD service package and retains the shared Microsoft runtime for other
applications. A failed BFD installation also retains a successfully installed
runtime. Generated service logs remain available after removal. Confirm that
`Get-Service BfdWinService,BfdBgpBroker` no longer finds either service.

## Configure and start the installed session

Turtle power starts with preflight, buddy. Like, for sure, complete these steps
before the first start:

1. [Configure the session](#2-configure-the-session), including the required
   addresses and interface index. The bundle already provisions logging defaults.
2. [Start the service](#4-start-the-service) and
   [verify startup](#5-verify-startup).
3. Configure the remote peer and [verify peer communication](#6-verify-peer-communication).

The bundle registers the manifest automatically. Use the session and logging
references to configure authentication, multihop, S-BFD, or file output.

<a id="install-the-windows-service"></a>

## Configure and verify the Windows service

### 1. Install the services

Follow [Install with the offline setup bundle](#install-with-the-offline-setup-bundle)
to provision both services and their security settings. If they're already
installed, continue with configuration. For installed files, accounts,
permissions, defaults, and recovery settings, see the
[installation inventory](reference/installation.md).

### 2. Configure the session

Bodacious sessions start with the right configuration. Dial in the required
session values:

```powershell
$localIp = 'LOCAL_IP'
$peerIp = 'PEER_IP'
$interfaceIndex = [uint32]'INTERFACE_INDEX'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'

New-Item -Path $parameters -Force
New-ItemProperty -Path $parameters -Name Local `
    -PropertyType String -Value $localIp -Force
New-ItemProperty -Path $parameters -Name Peer `
    -PropertyType String -Value $peerIp -Force
New-ItemProperty -Path $parameters -Name InterfaceIndex `
    -PropertyType DWord -Value $interfaceIndex -Force
```

Replace the following before running the commands:

- `LOCAL_IP`: your local IPv4 or IPv6 address, without a port or IPv6 scope suffix.
- `PEER_IP`: the remote peer's address, of the same address family.
- `INTERFACE_INDEX`: the index from `Get-NetIPAddress`, such as `12`.

The commands display the keys and values they create. The bundle already
provisions logging defaults; see [file logging](logging.md#configure-file-logging)
to change them. The default session is single-hop. For authentication,
multihop, or other settings, use the [configuration reference](configuration.md).

<a id="3-register-the-operational-log"></a>

### 3. Verify the Operational log

Check the log receipts before shouting Cowabunga. The bundle registers the Event
Tracing for Windows (ETW) manifest. Confirm that the provider and channel are
available:

```powershell
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

The queries display the `BFD-Service` provider and its Operational channel. If
either is missing, that's a setup bummer: repair the bundle installation before
starting BFD. Starting the executable doesn't install the manifest.

### 4. Start the service

Roll out, ninja crew, after the configuration steps are complete. Start the
provisioned service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

### 5. Verify startup

Cowabunga, verification crew. Check the Windows Service Control Manager (SCM) status:

```powershell
Get-Service BfdWinService | Select-Object Name, Status, StartType
```

Successful startup reports:

```text
Name          Status  StartType
----          ------  ---------
BfdWinService Running Automatic
```

Confirm `StartType` is `Automatic`; Windows reports delayed automatic services
with this value. SCM `Running` means configuration is valid,
sockets are open, and any configured
Border Gateway Protocol (BGP) worker has started. BFD reaches `Up` separately;
that transition triggers the first BGP status query when control is configured.

Configuration, file-log, and engine failures that end the service without a
Stop request produce a nonzero SCM service-specific exit status, and SCM restarts
the service after 10 seconds. A requested Stop always reports exit code `0`; a
failed cleanup is still recorded as event 3. For failure details, see
[Operational events](logging.md#operational-events).

The broker queries BFD session telemetry over private RPC in the background. To inspect
the authentication event independently of BFD session readiness, see
[Verify broker-to-BFD authentication](monitoring.md#verify-broker-to-bfd-authentication).
The RPC interface has no administrator-facing configuration or public query client.

### 6. Verify peer communication

Save the pizza celebration for the peer-communication receipts. After
configuring the remote peer, check the startup and handshake receipts:

```powershell
$eventFilter = @{
    LogName = 'BFD-Service/Operational'
    Id = 1, 100, 102
}
Get-WinEvent -FilterHashtable $eventFilter -MaxEvents 20 |
    Select-Object Id, LevelDisplayName
```

A successful first handshake produces entries such as:

```text
 Id LevelDisplayName
 -- ----------------
102 Information
100 Information
  1 Information
```

Event `1` confirms engine startup. Event `100` confirms valid peer communication;
event `102` confirms BFD reached `Up`. Service startup alone doesn't establish
peer communication. For other events, see [Logs and events](logging.md).
For monitoring scripts, see [Monitor service status and BFD events](monitoring.md).

### 7. Optional: Stop the service

A turtle knows when to exit with cleanup, dude. To stop the session, run:

```powershell
Stop-Service BfdWinService
```

The service reports `StopPending` during cleanup, then `Stopped`. An
administrative stop announces `AdminDown` as the role permits and releases any
BGP Stop previously requested by BFD. Cleanup can take time; see
[shutdown behavior and limits](protocol.md#supported-modes-and-limits) and
[BGP cleanup](bgp.md#provider-timeouts-and-final-cleanup).

## Installation reference

Inspect the [installed resources and firewall rules](reference/installation.md)
or the [service isolation reference](security/service-isolation.md) when you need
the deployment details.

<a id="prepare-installation-files"></a>

## Run in a console

For loose-file prerequisites and foreground execution, follow
[Run BFD in a console](console.md).

## Remove a legacy manual installation

For an older manually provisioned service, follow the
[legacy removal procedure](reference/legacy-installation.md).
