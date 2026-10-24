# Set up a BFD session

Cowabunga, install crew. Use this guide to install, configure, and verify a
classical Bidirectional Forwarding Detection (BFD) session on Windows. The
offline setup bundle provisions both services, the native Microsoft Visual C++
runtime, and their security settings. The service monitors one local/peer pair.

This procedure configures classical BFD. For initiation without a handshake or
a stateless responder, use [Configure Seamless BFD](seamless.md).

## Before you begin

Before installing:

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

Find the interface that owns your local address:

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
Deployment automation uses the setup executable and its switches.

<a id="configure-and-start-the-installed-session"></a>

## Configure and verify the Windows service

Follow these steps in order. If you have already installed the bundle, continue
with [Configure the session](#2-configure-the-session). Keep the same elevated
PowerShell window open throughout the procedure.

### 1. Install the services

Follow [Install with the offline setup bundle](#install-with-the-offline-setup-bundle)
to provision both services and their security settings. If they're already
installed, continue with configuration. For installed files, accounts,
permissions, defaults, and recovery settings, see the
[installation inventory](reference/installation.md).

### 2. Configure the session

Set the required session values:

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

### 3. Verify the Operational log

The bundle registers the Event Tracing for Windows (ETW) manifest. Confirm the
provider and channel are available:

```powershell
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

The queries display the `BFD-Service` provider and its Operational channel. If
either is missing, repair the bundle before starting BFD. Starting the
executable doesn't install the manifest.

### 4. Start the service

Record the start time for the verification queries, then start the configured
service:

```powershell
$startedAt = Get-Date
Start-Service BfdWinService
```

The command returns without output on success.

BFD starts independently. For BGP control or broker telemetry, also start the
broker; either service can start first:

```powershell
Start-Service BfdBgpBroker
```

### 5. Verify startup

Check Windows Service Control Manager (SCM) status:

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

For startup failures, inspect the
[Operational events](logging.md#operational-events). The
[installation inventory](reference/installation.md) describes SCM recovery. For
broker telemetry checks, see
[Verify broker-to-BFD authentication](monitoring.md#verify-broker-to-bfd-authentication).

### 6. Verify peer communication

After configuring the remote peer, check startup and handshake events since
`$startedAt` from step 4. If you run this query separately, set `$startedAt` to
the start time of the service run you want to verify:

```powershell
$eventFilter = @{
    LogName = 'BFD-Service/Operational'
    Id = 1, 100, 102
    StartTime = $startedAt
}
Get-WinEvent -FilterHashtable $eventFilter -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message
```

Expect event `1` for engine startup, `100` for valid peer communication, and
`102` when BFD reaches `Up`. Check their timestamps and messages against the
session you configured. Event `102` confirms that this run reached `Up` at that
time; it does not guarantee the session is still `Up`. Service startup alone
doesn't establish peer communication. For other events, see [Logs and events](logging.md).
For monitoring scripts, see [Monitor service status and BFD events](monitoring.md).

### 7. Optional: Stop the service

To stop the session, run:

```powershell
Stop-Service BfdWinService
```

The service reports `StopPending` during cleanup, then `Stopped`. An
administrative stop announces `AdminDown` as the role permits and releases any
BGP Stop previously requested by BFD. Cleanup can take time; see
[shutdown behavior and limits](protocol.md#supported-modes-and-limits) and
[BGP cleanup](bgp.md#provider-timeouts-and-final-cleanup).

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
uninstalls the BFD service package and retains the shared Microsoft runtime for
other applications. A failed BFD installation also retains a successfully
installed runtime. Generated service logs remain available after removal.
Confirm that `Get-Service BfdWinService,BfdBgpBroker` no longer finds either
service.

## Installation reference

Inspect the [installed resources and firewall rules](reference/installation.md)
or the [service isolation reference](security/service-isolation.md) when you need
the deployment details.
