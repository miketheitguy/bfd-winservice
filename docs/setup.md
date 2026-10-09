# Set up a BFD session

This guide is for Windows systems administrators provisioning a fresh
Bidirectional Forwarding Detection (BFD) Windows service installation or a
foreground console session. The service monitors one configured local/peer pair.
Use [Install with an MSI](#install-with-an-msi) for the package produced by
GitHub Actions. Loose files support foreground console execution; SCM operation
requires the MSI to provision both services and their security settings.

This procedure configures classical BFD. For initiation without a handshake or
a stateless responder, use [Configure Seamless BFD](seamless.md).

## Before you begin

Prepare the following:

- Obtain the x64 MSI from
  [GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases),
  or matching `bfd-winservice.exe`, `BFD-Service.man`, and
  `Initialize-Logging.ps1` files from your service maintainer.
- Use 64-bit Windows 10 or later, or a corresponding Windows Server release,
  on an x64 processor.
- Open **PowerShell as Administrator**. Use the same
  window throughout the service procedure so its PowerShell variables remain set.
- Choose distinct unicast `Local` and `Peer` IP literals of the same address
  family. Configure the remote peer with these addresses reversed.
- Allow the [required network traffic](protocol.md). The service doesn't create
  firewall rules or discover peers. The MSI installs the rules described in
  [MSI firewall rules](#msi-firewall-rules).

Find the interface that owns your local address:

```powershell
Get-NetIPAddress |
    Select-Object IPAddress, InterfaceAlias, InterfaceIndex
```

Find your local address in the output and use its nonzero interface index for
the default single-hop session.

## Install with an MSI

Installation, repair, and removal require administrator privileges. The MSI
requests elevation for its per-machine installation and rejects installation
sessions without the required privileges. Run command-line installation from
**PowerShell as Administrator**.

The MSI installs the following resources for all users:

- Both executables, the manifest, and logging script in
  `C:\Program Files\BfdWinService`.
- The `BfdWinService` service with display name **BFD Windows Service**,
  the LocalService account, and **Automatic** startup. The MSI leaves it stopped;
  configure it before starting the service or restarting Windows.
- The `BfdBgpBroker` service with **Manual** startup and the LocalSystem account.
  BFD depends on the broker, so starting BFD starts the broker even when BGP
  control is disabled. Both services have their own enabled service SID.
  SCM restarts the broker after a crash with a five-second delay.
- The `BFD-Service` provider and enabled `BFD-Service/Operational` channel,
  with message and resource paths pointing to the installed executable.
- The Parameters key with `Multihop` DWORD `0`, `LogToFile` DWORD `0`, and
  `LogFilePath` string `C:\ProgramData\BfdWinService\trace.log` on a default
  Windows layout. The logging path uses the machine's ProgramData location.
- The ProgramData `BfdWinService` folder, without creating or writing `trace.log`.
  Only the BFD service SID receives Modify access; shared LocalService processes
  receive no write grant. The Parameters key permits reads only by SYSTEM,
  administrators, and that service SID. Installed code and COM registration
  remain writable only by SYSTEM and administrators.
- Four executable-specific UDP firewall rules for classical and Seamless BFD.
- The read-only `BfdWinService.SessionState` COM Automation class and the
  `RpcSs` service dependency. [Query the current BFD state through COM](com.md)
  after configuring the service; activating the class starts a stopped service.

### 1. Install the package

Download `BfdWinService-VERSION-x64.msi` and its `.sha256` file from the version's
**Assets** on
[GitHub Releases](https://github.com/miketheitguy/bfd-winservice/releases).
`VERSION` is the release tag without its leading `v`. Tagged builds also provide
the `BfdWinService-x64-COMMIT_SHA` Actions artifact; `COMMIT_SHA` identifies the
source commit. The build workflow runs only for version tags; branch pushes
and pull requests do not trigger it. In **PowerShell as Administrator**, install
the MSI:

```powershell
$msi = (Resolve-Path 'MSI_PATH').Path
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
`C:\Temp\BfdWinService-1.1.0-x64.msi`. Successful installation reports a **Stopped**,
**Automatic** service and the registered provider/channel. Exit code `3010`
means installation succeeded and Windows requests a restart.

### 2. Configure and start the session

Before the first start, complete these steps:

1. [Enable SEHOP for the executable](#enable-sehop-for-the-executable).
   The MSI doesn't change Windows Exploit Protection policy.
2. [Configure the session](#2-configure-the-session), including the required
   addresses and interface index. The MSI already provisions logging defaults;
   omit the `Initialize-Logging.ps1` invocation if you want to retain them.
3. [Start the service](#4-start-the-service) and
   [verify startup](#5-verify-startup).
4. Configure the remote peer and [verify peer communication](#6-verify-peer-communication).

The MSI registers the manifest automatically. Use the session and logging
references to configure authentication, multihop, S-BFD, or file output.

### MSI firewall rules

All rules allow UDP for the installed executable on Domain, Private, and Public
profiles. Remote addresses are unrestricted so multihop, anycast, and
point-to-point configurations can use their configured peers. The rules have
these port restrictions:

| Rule | Direction | Local ports | Remote ports |
| --- | --- | --- | --- |
| `BfdWinService - control inbound` | Inbound | 3784, 4784, 7784 | 49152–65535 |
| `BfdWinService - S-BFD replies inbound` | Inbound | 49152–65535 | 7784 |
| `BfdWinService - probes outbound` | Outbound | 49152–65535 | 3784, 4784, 7784 |
| `BfdWinService - S-BFD replies outbound` | Outbound | 7784 | 49152–65535 |

The high-port inbound rule is required for S-BFD initiators because replies
return to their source port. No TCP or BFD Echo rule is installed. Network
firewalls and organizational policy still control effective access.

To inspect the installed rules, run:

```powershell
Get-NetFirewallRule |
    Where-Object DisplayName -Like 'BfdWinService - *' |
    Select-Object DisplayName, Direction, Enabled, Profile
```

Confirm that the four rules are enabled. To inspect ports, pipe the matching
rules to `Get-NetFirewallPortFilter`.

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

Copy the supplied files to a permanent installation folder:

```powershell
$deploymentDirectory = (Resolve-Path 'DEPLOYMENT_DIRECTORY').Path
$installDirectory = 'C:\Program Files\BfdWinService'
New-Item -ItemType Directory -Path $installDirectory -Force
foreach ($file in @(
    'bfd-winservice.exe', 'BFD-Service.man', 'Initialize-Logging.ps1'
)) {
    Copy-Item -LiteralPath (Join-Path $deploymentDirectory $file) `
        -Destination $installDirectory
}
Get-ChildItem -LiteralPath $installDirectory | Select-Object Name
```

Replace `DEPLOYMENT_DIRECTORY` with the folder containing the supplied files,
such as `C:\Temp\BfdWinService`. Adjust `$installDirectory` if your organization
uses another location.

PowerShell displays the destination folder and the three installed filenames.
Keep the executable at this path: SCM starts it here, and Event Viewer loads
event messages from it.

## Enable SEHOP for the executable

In **PowerShell as Administrator**, enable Structured Exception Handling
Overwrite Protection (SEHOP) for both installed executables:

```powershell
Set-ProcessMitigation -Name bfd-winservice.exe -Enable SEHOP
Set-ProcessMitigation -Name bfd-bgp-broker.exe -Enable SEHOP
Get-ProcessMitigation -Name bfd-winservice.exe |
    Select-Object -ExpandProperty SEHOP
```

Confirm that `Enable` is `ON`. This Windows Exploit Protection policy applies
to subsequent processes named `bfd-winservice.exe` and `bfd-bgp-broker.exe` on this
machine. If a process is already running, restart it to apply the policy.

SEHOP is a [Windows process mitigation](https://learn.microsoft.com/en-us/powershell/module/processmitigations/set-processmitigation?view=windowsserver2025-ps),
not an executable build flag. The service is x64: its exception handlers use
Windows unwind tables instead of the stack-based chain that SEHOP validates.
The supplied binary also contains EH continuation metadata and is marked
compatible with CET shadow stacks. Enforcement of those protections requires
Windows and hardware support; see [Build security](../CONTRIBUTING.md#build-security).

## Install the Windows service

Before creating or starting the service, complete
[Enable SEHOP for the executable](#enable-sehop-for-the-executable).

### 1. Install the services

Follow [Install with an MSI](#install-with-an-msi) to create both services with
their accounts, service SIDs, dependencies, protected ACLs, and COM registration.
The installer migrates an existing built-in service account to LocalService and
restores its previous account/SID settings if the transaction rolls back. Custom
service accounts are rejected because their passwords cannot be restored safely.
Do not create just the BFD service with `New-Service`: startup requires an
authenticated connection to the separately provisioned broker.

Set the installed paths for the remaining commands:

```powershell
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
$exe = (Resolve-Path (Join-Path $installDirectory 'bfd-winservice.exe')).Path
```

All session settings belong in the BFD Parameters registry key. `Automatic`
starts BFD and its broker dependency when Windows starts; finish configuration
before starting the service. The MSI already registers the event manifest.

### 2. Configure the session

Provision the required session values and the default logging settings:

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
& (Join-Path $installDirectory 'Initialize-Logging.ps1')
```

Replace the following before running the commands:

- `LOCAL_IP`: your local IPv4 or IPv6 address, without a port or IPv6 scope suffix.
- `PEER_IP`: the remote peer's address, of the same address family.
- `INTERFACE_INDEX`: the index from `Get-NetIPAddress`, such as `12`.

The registry commands display the keys and values they create. The logging
script creates `C:\ProgramData\BfdWinService`, displays the folder and registry
objects, and prints this settings summary:

```text
LogFilePath (REG_SZ): C:\ProgramData\BfdWinService\trace.log
LogToFile (REG_DWORD): 0
```

It doesn't create or write `trace.log`. The default session uses single-hop.
For authentication, multihop, or other settings, see the
[registry configuration reference](configuration.md).

### 3. Register the Operational log

Register the Event Tracing for Windows (ETW) manifest on the target machine
before starting the service:

```powershell
$manifest = (Resolve-Path (Join-Path $installDirectory 'BFD-Service.man')).Path
wevtutil.exe im $manifest "/rf:$exe" "/mf:$exe"
if ($LASTEXITCODE -ne 0) {
    throw 'BFD-Service manifest registration failed'
}
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

The queries display the `BFD-Service` provider and its Operational channel.
Use the final installed executable path: Event Viewer loads messages and
metadata from it. Starting the executable doesn't install the manifest.

### 4. Start the service

Start the provisioned service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

### 5. Verify startup

Check the Windows Service Control Manager (SCM) status:

```powershell
Get-Service BfdWinService | Select-Object Name, Status, StartType
```

Successful startup reports:

```text
Name          Status  StartType
----          ------  ---------
BfdWinService Running Automatic
```

Confirm `StartType` is `Automatic`. SCM `Running` means configuration is valid,
sockets are open, and any configured
Border Gateway Protocol (BGP) worker has started. BFD reaches `Up` separately;
the initial BGP status query can also still be pending.

Configuration, file-log, and engine failures produce a nonzero SCM
service-specific exit status. For failure details, see
[Operational events](logging.md#operational-events).

### 6. Verify peer communication

After configuring the remote peer, inspect startup and handshake events:

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
For an MSI installation, you can also [query the current state through COM](com.md).

### 7. Optional: Stop the service

To stop the session, run:

```powershell
Stop-Service BfdWinService
```

The service reports `StopPending` with advancing checkpoints during cleanup,
then `Stopped`. Stop and Shutdown initiate this status transition immediately.
The engine sets `AdminDown` and queues any configured BGP Stop. With a
communicating classical peer, it continues permitted announcements for the
detection period, capped at five seconds, before finishing cleanup. Other roles
or sessions without a communicating peer attempt one role-permitted notification.
See [shutdown behavior and limits](protocol.md#supported-modes-and-limits).

## Run in a console

Console execution reads the same Parameters registry values as service execution.
Run it as Administrator when using the MSI-protected key. Console mode does not
host COM or authorize BGP operations; leave `BgpPeerName` and `BgpRoutingDomain`
unset for foreground execution.

### 1. Configure the registry values

Run the commands in [Configure the session](#2-configure-the-session) to provision
the local/peer addresses, interface index, and default logging settings.

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

After configuring the remote peer, confirm the console output contains
`state=Up`. This confirms BFD establishment separately from the
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

## Remove the service and manifest

For an MSI installation, use [Remove an MSI installation](#remove-an-msi-installation).
The following procedure removes services from a legacy manual installation.

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

For another fresh installation, return to [Install the Windows service](#install-the-windows-service).
