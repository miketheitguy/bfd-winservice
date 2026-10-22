# Set up a BFD session

Cowabunga, install crew. Get the session ready for action. Windows systems
admins, let's get this setup rolling. Use this guide for a fresh Bidirectional
Forwarding Detection (BFD) Windows service installation or a foreground console
session. The service monitors one configured local/peer pair. Use
[Install with an MSI](#install-with-an-msi) for the package produced by GitHub
Actions. Loose files support foreground console execution; SCM operation
requires the MSI to provision both services and their security settings.

This procedure configures classical BFD. For initiation without a handshake or
a stateless responder, use [Configure Seamless BFD](seamless.md).

The startup vibe check has two parts, dude: Windows reports `Running`, then BFD
reports `Up` after it establishes peer communication.

Choose the path for your deployment:

- For Windows services, [install the MSI](#install-with-an-msi), then
  [configure and verify the service](#configure-and-verify-the-windows-service).
- For foreground execution, [prepare loose files](#prepare-installation-files)
  if needed, then
  [run in a console](#run-in-a-console).
- For removal, use the [MSI uninstall procedure](#remove-an-msi-installation) or
  the [legacy manual removal procedure](#remove-a-legacy-manual-installation).

## Before you begin

Gather the gear before the ninja mission starts. Before you send it, line up
these prerequisites:

- Obtain the x64 MSI from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases),
  or matching `bfd-winservice.exe` and `Initialize-Logging.ps1` files from your
  service maintainer for console execution.
- Use 64-bit Windows 10 or later, or Windows Server 2016 or later,
  on an x64 processor.
- Open **PowerShell as Administrator**. Use the same
  window throughout the service procedure so its PowerShell variables remain set.
- Choose distinct unicast `Local` and `Peer` IP literals of the same address
  family. Configure the remote peer with these addresses reversed.
- Allow the [required network traffic](protocol.md). The service doesn't create
  firewall rules or discover peers. The MSI installs the rules described in
  [MSI firewall rules](#msi-firewall-rules).

Get your bearings: find the interface that owns your local address:

```powershell
Get-NetIPAddress |
    Select-Object IPAddress, InterfaceAlias, InterfaceIndex
```

Find your local address in the output and use its nonzero interface index for
the default single-hop session.

## Install with an MSI

Kick shell with the installer while keeping its privilege requirements clear.
Installation, repair, and removal require administrator privileges. The MSI
requests elevation for its per-machine installation and rejects installation
sessions without the required privileges. Run command-line installation from
**PowerShell as Administrator**.

### 1. Install the package

Download `BfdWinService-VERSION-x64.msi` and its `.sha256` file from the version's
**Assets** on
[GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases).
`VERSION` is the release tag without its leading `v`. Tagged builds also provide
the `BfdWinService-x64-COMMIT_SHA` Actions artifact; `COMMIT_SHA` identifies the
source commit. Pull requests, pushes to `main`, and manual branch runs also
produce validated Actions artifacts; release publication requires a version tag.
In **PowerShell as Administrator**, install
the MSI after checking the downloaded checksum:

```powershell
$msi = (Resolve-Path 'MSI_PATH').Path
$expectedHash = (Get-Content -LiteralPath "$msi.sha256" -Raw).Split()[0]
$actualHash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw 'MSI SHA-256 checksum mismatch'
}
$log = Join-Path $env:TEMP 'BfdWinService-install.log'
$arguments = @(
    '/i', ('"' + $msi + '"'), '/qn', '/norestart',
    '/L*v', ('"' + $log + '"')
)
$result = Start-Process -FilePath msiexec.exe -ArgumentList $arguments `
    -WindowStyle Hidden -Wait -PassThru
if ($result.ExitCode -notin @(0, 3010)) {
    throw "MSI installation failed; inspect $log"
}
Get-Service BfdWinService | Select-Object Name, Status, StartType
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

Replace `MSI_PATH` with the local `.msi` path, such as
`C:\Temp\BfdWinService-1.1.0-x64.msi`. Keep its matching `.msi.sha256` file in the
same folder. Successful installation reports a **Stopped**,
**Automatic** service, which `Get-Service` also reports for delayed start, and the
registered provider/channel. Exit code `3010`
means installation succeeded and Windows requests a restart.

### 2. Configure and start the session

Turtle power starts with preflight, buddy. Like, for sure, complete these steps
before the first start:

1. [Configure the session](#2-configure-the-session), including the required
   addresses and interface index. The MSI already provisions logging defaults.
2. [Start the service](#4-start-the-service) and
   [verify startup](#5-verify-startup).
3. Configure the remote peer and [verify peer communication](#6-verify-peer-communication).

The MSI registers the manifest automatically. Use the session and logging
references to configure authentication, multihop, S-BFD, or file output.

### Installed resources and security settings

Donatello would inspect the full installation inventory, dude. The MSI installs
the following resources for all users:

- Both executables, the manifest, and logging script in
  `C:\Program Files\BfdWinService`.
- The `BfdWinService` service with display name **BFD Windows Service**,
  the LocalService account, and **Automatic (Delayed Start)** startup. The MSI
  leaves it stopped; configure it before starting the service or restarting
  Windows. Delayed start runs after boot-time services, when interface addresses
  are more likely to be assigned.
- The `BfdBgpBroker` service with **Automatic (Delayed Start)** startup and the
  LocalSystem account. BFD depends on the broker, so starting BFD also starts the
  broker. Without `BgpPeerName`, BFD doesn't open its BGP control RPC interface. The
  broker still queries BFD's private RPC status interface. Both services have their
  own enabled service SID. BFD uses restricted SID type `3`; its service SID is
  also present in the token's restricting list. The broker retains unrestricted
  SID type `1`.
- A BFD `RequiredPrivileges` allowlist containing only
  `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege`. A native commit action
  records the list after the MSI transaction succeeds; services remain stopped
  until you start them. SCM applies the list when it creates the LocalService
  process. BFD also permanently removes unused
  privileges at startup. The broker separately removes all token privileges
  except `SeChangeNotifyPrivilege` before initializing COM/MI or RPC.
- Protected service ACLs for both services: SYSTEM and Administrators have full
  control. Authenticated users can query configuration/status, enumerate
  dependents, interrogate status, and read the service ACL. They cannot Start/Stop,
  pause, reconfigure, delete, or send custom controls to either service. Use an
  elevated Administrator session for lifecycle commands. Log reads remain
  available to non-administrators under the existing log permissions.
- SCM recovery: the broker restarts five seconds after a crash. BFD restarts
  10 seconds after a crash or an unrequested failure exit, such as a local address
  that isn't assigned yet. A Stop request always ends BFD with exit code `0`, so
  recovery never restarts a service that an administrator stopped.
- The `BFD-Service` provider and enabled `BFD-Service/Operational` channel,
  with message and resource paths pointing to the installed executable.
- The Parameters key with `Multihop` DWORD `0`, `LogToFile` DWORD `0`, and
  `LogFilePath` string `C:\ProgramData\BfdWinService\trace.log` on a default
  Windows layout. The MSI path uses the machine's ProgramData location. The
  executable fallback and logging script use the literal `C:\ProgramData` path.
- The ProgramData `BfdWinService` folder, without creating or writing `trace.log`.
  Only the BFD service SID receives Modify access; shared LocalService processes
  receive no write grant. The Parameters key permits reads only by SYSTEM,
  administrators, and that service SID. BFD's write-restricted token requires
  suitable service-SID grants as well as ordinary write permission. Installed
  code remains writable only by
  SYSTEM and administrators.
- Four executable-specific UDP allow rules for classical and Seamless BFD.
- The broker's `RpcSs` service dependency for native MI. The BFD service depends
  on the broker. See [Monitor service status and BFD events](monitoring.md) for
  lifecycle queries and event-log monitoring.

### MSI firewall rules

Keep the network entrance totally tubular and check the actual rules. Four rules
allow UDP for the installed executable on Domain, Private, and Public profiles.
Remote addresses are unrestricted so multihop, anycast, and point-to-point
configurations can use their configured peers. The rules have these protocol and
port restrictions:

| Rule | Protocol / action | Direction | Local ports | Remote ports |
| --- | --- | --- | --- | --- |
| `BfdWinService - control inbound` | UDP / allow | Inbound | 3784, 4784, 7784 | 49152–65535 |
| `BfdWinService - S-BFD replies inbound` | UDP / allow | Inbound | 49152–65535 | 7784 |
| `BfdWinService - probes outbound` | UDP / allow | Outbound | 49152–65535 | 3784, 4784, 7784 |
| `BfdWinService - S-BFD replies outbound` | UDP / allow | Outbound | 7784 | 49152–65535 |

The high-port inbound rule is required for S-BFD initiators because replies
return to their source port. No BFD Echo rule is installed. Network firewalls
and organizational policy still control effective access. The private local RPC
interface uses `ncalrpc` and needs no network firewall rule.

To inspect the installed rules, run:

```powershell
Get-NetFirewallRule |
    Where-Object DisplayName -Like 'BfdWinService - *' |
    Select-Object DisplayName, Direction, Enabled, Profile
```

Firewall vibe check: confirm that the four rules are enabled. To inspect ports,
pipe the matching rules to `Get-NetFirewallPortFilter`.

### Remove an MSI installation

In Windows **Installed apps** or **Programs and Features**, select
**BFD Windows Service** and choose **Uninstall**. Windows Installer stops BFD and
the broker, removes both service registrations and installed files, unregisters the event
manifest, and removes its four firewall rules. User-generated log files remain.
It removes the ProgramData folder only when the folder is empty.

Confirm that `Get-Service BfdWinService,BfdBgpBroker` no longer finds the services and that
the provider and firewall-rule queries no longer find the installed entries.
Use Windows Installer to remove an MSI installation so its ownership records
remain consistent.

## Prepare installation files

Pack the console gear before the pizza run. For a console-only deployment, copy
the supplied files to a permanent folder. If the MSI already installed them,
you're set; skip this section:

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
These files support console execution. Use the MSI for service execution;
copying files doesn't create services, service identities, or access policies.

<a id="install-the-windows-service"></a>

## Configure and verify the Windows service

### 1. Install the services

If you haven't installed the package, follow [Install with an MSI](#install-with-an-msi)
to create both services with their accounts, service SIDs, dependencies, and
protected ACLs. If the MSI is already installed, continue with the installed paths
in this step.
The installer migrates an existing built-in service account to LocalService and
restores its previous account/SID settings if the transaction rolls back. Custom
service accounts are rejected because their passwords cannot be restored safely.
The [MSI installation check](../scripts/Test-MsiInstall.ps1) exercises actual
SCM-created service tokens on a disposable runner, including RPC authentication,
ETW delivery, and file writes. Follow this guide to verify your deployment too.
BFD's service-mode startup checks the LocalService account, its enabled service
group, and the BFD SID plus write-restricted marker in the restricting list
before loading configuration, creating sockets, or registering its local RPC interface.
Use the MSI to provision both services. With `BgpPeerName` configured, BFD startup
also requires an authenticated connection to the broker's BGP control RPC interface.

Set the installed paths for the remaining commands:

```powershell
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
$exe = (Resolve-Path (Join-Path $installDirectory 'bfd-winservice.exe')).Path
```

All session settings belong in the BFD Parameters registry key. Automatic
(Delayed Start) starts BFD and its broker dependency shortly after Windows starts;
finish configuration before starting the service. The MSI already registers the
event manifest.

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

The registry commands display the keys and values they create. The MSI already
provisions logging defaults. For a loose-file console deployment, initialize
those defaults with the supplied script:

```powershell
& (Join-Path $installDirectory 'Initialize-Logging.ps1')
```

The script creates `C:\ProgramData\BfdWinService`, displays the folder and registry
objects, and prints this settings summary:

```text
LogFilePath (REG_SZ): C:\ProgramData\BfdWinService\trace.log
LogToFile (REG_DWORD): 0
```

It doesn't create or write `trace.log`. Running it again resets `LogFilePath`
and disables file output, so omit it when retaining existing logging settings.
The default session uses single-hop.
For authentication, multihop, or other settings, see the
[registry configuration reference](configuration.md).

<a id="3-register-the-operational-log"></a>

### 3. Verify the Operational log

Check the log receipts before shouting Cowabunga. The MSI registers the Event
Tracing for Windows (ETW) manifest. Confirm that the provider and channel are
available:

```powershell
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

The queries display the `BFD-Service` provider and its Operational channel. If
either is missing, that's a setup bummer: repair the MSI installation before
starting BFD. Starting the executable doesn't install the manifest.

### 4. Start the service

Roll out, ninja crew, after the configuration steps are complete. Start the
provisioned service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

### 5. Verify startup

Cowabunga, verification crew. Check the process status separately. Check the
Windows Service Control Manager (SCM) status:

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
the initial BGP status query can also still be pending.

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

The service reports `StopPending` with advancing checkpoints during cleanup,
then `Stopped`. Stop and Shutdown initiate this status transition immediately.
The engine sets `AdminDown` and never stops a configured BGP peer; if BFD had
stopped the peer after a failure, the engine starts it again, as RFC 5882
requires while BFD is disabled. With a communicating classical peer, it continues
permitted announcements for one Detection Time, up to `MaxShutdownAnnounceMs`
(30 seconds by default), before finishing cleanup. The installer sets the Windows
preshutdown timeout to 125 seconds to cover announcements and cleanup. Other roles
or sessions without a communicating peer attempt one role-permitted notification.
See [shutdown behavior and limits](protocol.md#supported-modes-and-limits).

## Run in a console

Take the session on a foreground mission, turtle crew. Console execution reads
the same Parameters registry values as service execution. Run it as
Administrator when using the MSI-protected key. Console mode does not authorize
BGP operations; leave `BgpPeerName` and `BgpRoutingDomain` unset for foreground
execution.

Dude, stop an installed `BfdWinService` before running the same session in a
console; both processes would otherwise compete for the same addresses and
ports.

### 1. Configure the registry values

Set `$installDirectory` to the MSI installation folder or the folder from
[Prepare installation files](#prepare-installation-files). Run the commands in
[Configure the session](#2-configure-the-session) to provision the local/peer
addresses, interface index, and default logging settings.

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

<a id="remove-the-service-and-manifest"></a>

## Remove a legacy manual installation

Wrap up the old mission before the next pizza break. For an MSI installation,
use [Remove an MSI installation](#remove-an-msi-installation). The following
procedure removes services from a legacy manual installation.

Use **PowerShell as Administrator** with the installed manifest path.

### 1. Stop the service

Finish service cleanup before removing its registration:

```powershell
Stop-Service BfdWinService
Stop-Service BfdBgpBroker -ErrorAction SilentlyContinue
```

Confirm `Get-Service BfdWinService` reports `Stopped` before continuing.

### 2. Unregister the manifest

Remove the provider's manifest registration:

```powershell
$installDirectory = 'C:\Program Files\BfdWinService'
$manifest = (Resolve-Path (Join-Path $installDirectory 'BFD-Service.man')).Path
wevtutil.exe um $manifest
if ($LASTEXITCODE -ne 0) {
    throw 'BFD-Service manifest removal failed'
}
```

A successful command returns without output. For registration and removal syntax,
see Microsoft's [wevtutil commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil).

### 3. Delete the service

Remove the stopped service from SCM:

```powershell
sc.exe delete BfdWinService
if (Get-Service BfdBgpBroker -ErrorAction SilentlyContinue) {
    sc.exe delete BfdBgpBroker
}
```

The command reports successful deletion. After SCM completes deletion,
`Get-Service BfdWinService` no longer finds the service.

For another fresh installation, return to [Install with an MSI](#install-with-an-msi).
