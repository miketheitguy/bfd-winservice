# Set up a BFD session

This guide is for Windows systems administrators provisioning a fresh
Bidirectional Forwarding Detection (BFD) Windows service installation or a
foreground console session. The service monitors one configured local/peer pair.

This procedure configures classical BFD. For initiation without a handshake or
a stateless responder, use [Configure Seamless BFD](seamless.md).

## Before you begin

Prepare the following:

- Obtain `bfd-winservice.exe`, `BFD-Service.man`, and
  `Initialize-Logging.ps1` from the same version of the service.
- Use 64-bit Windows 10 or later, or a corresponding Windows Server release,
  on an x64 processor.
- Open **PowerShell as Administrator**. Use the same
  window throughout the service procedure so its PowerShell variables remain set.
- Choose distinct unicast `Local` and `Peer` IP literals of the same address
  family. Configure the remote peer with these addresses reversed.
- Allow the [required network traffic](protocol.md). The service doesn't create
  firewall rules or discover peers.

Find the interface that owns your local address:

```powershell
Get-NetIPAddress |
    Select-Object IPAddress, InterfaceAlias, InterfaceIndex
```

Find your local address in the output and use its nonzero interface index for
the default single-hop session.

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
Overwrite Protection (SEHOP) for the installed executable:

```powershell
Set-ProcessMitigation -Name bfd-winservice.exe -Enable SEHOP
Get-ProcessMitigation -Name bfd-winservice.exe |
    Select-Object -ExpandProperty SEHOP
```

Confirm that `Enable` is `ON`. This Windows Exploit Protection policy applies
to subsequent service and console processes named `bfd-winservice.exe` on this
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

### 1. Create the service

Create a service with the quoted absolute executable path:

```powershell
$exe = (Resolve-Path (Join-Path $installDirectory 'bfd-winservice.exe')).Path
$binaryPath = '"' + $exe + '"'
New-Service -Name BfdWinService -BinaryPathName $binaryPath `
    -DisplayName 'BFD Windows Service' -StartupType Automatic
```

PowerShell displays the new service with status `Stopped`. All session settings
belong in its Parameters registry key; the executable path contains the binary
path only. `Automatic` starts the service when Windows starts; finish the
configuration and manifest registration before starting the service.

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

### 7. Optional: Stop the service

To stop the session, run:

```powershell
Stop-Service BfdWinService
```

The service reports `StopPending` with advancing checkpoints during cleanup,
then `Stopped`. Stop and Shutdown initiate this status transition immediately.
The engine sets `AdminDown`, attempts one shutdown packet when its active/passive
role permits transmission, and waits for any configured BGP cleanup.

## Run in a console

Console execution reads the same Parameters registry values as service execution.

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

Press **Ctrl+C**. The engine sets `AdminDown`, attempts one shutdown packet when
transmission is permitted, and waits for any configured BGP cleanup.

Settings are read at startup. Stop execution, edit the registry, and restart to
apply changes.

### Optional: Capture console output

To save STDOUT instead of displaying it, start the console process with
redirection:

```powershell
& $exe --console > 'C:\ProgramData\BfdWinService\console.log'
```

The output file contains console messages with Unix-millisecond timestamps.
This shell redirection is separate from the `LogToFile` setting.

## Remove the service and manifest

Use **PowerShell as Administrator** with the installed manifest path.

### 1. Stop the service

Finish service cleanup before removing its registration:

```powershell
Stop-Service BfdWinService
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
```

The command reports successful deletion. After SCM completes deletion,
`Get-Service BfdWinService` no longer finds the service.

For another fresh installation, return to [Install the Windows service](#install-the-windows-service).
