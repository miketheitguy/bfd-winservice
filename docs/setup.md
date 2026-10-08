# Set up a BFD session

This guide is for Windows network administrators provisioning a fresh
Bidirectional Forwarding Detection (BFD) Windows service installation or a
foreground console session. The service monitors one configured local/peer pair.

## Before you begin

Prepare the following:

- Build the executable using [Build and validate the service](development.md).
- Open **PowerShell as Administrator** at the repository root. Use the same
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

## Install the Windows service

Keep the executable at a permanent installation path. The examples use the
repository's build output; adjust the executable and manifest paths if you
deploy them elsewhere.

### 1. Create the service

Create a service with the quoted absolute executable path:

```powershell
$exe = (Resolve-Path .\target\release\bfd-winservice.exe).Path
$binaryPath = '"' + $exe + '"'
New-Service -Name BfdWinService -BinaryPathName $binaryPath `
    -DisplayName 'BFD Windows Service' -StartupType Manual
```

PowerShell displays the new service with status `Stopped`. All session settings
belong in its Parameters registry key; the executable path contains the binary
path only.

### 2. Configure the session

Provision the required session values and the default logging settings:

```powershell
$localIp = 'LOCAL_IP'
$peerIp = 'PEER_IP'
$interfaceIndex = [uint32]'INTERFACE_INDEX'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'

New-Item -Path $parameters -Force | Out-Null
New-ItemProperty -Path $parameters -Name Local `
    -PropertyType String -Value $localIp -Force | Out-Null
New-ItemProperty -Path $parameters -Name Peer `
    -PropertyType String -Value $peerIp -Force | Out-Null
New-ItemProperty -Path $parameters -Name InterfaceIndex `
    -PropertyType DWord -Value $interfaceIndex -Force | Out-Null
.\scripts\Initialize-Logging.ps1
```

Replace the following before running the commands:

- `LOCAL_IP`: your local IPv4 or IPv6 address, without a port or IPv6 scope suffix.
- `PEER_IP`: the remote peer's address, of the same address family.
- `INTERFACE_INDEX`: the index from `Get-NetIPAddress`, such as `12`.

The logging script creates `C:\ProgramData\BfdWinService` and reports:

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
$manifest = (Resolve-Path .\events\BFD-Service.man).Path
wevtutil.exe im $manifest "/rf:$exe" "/mf:$exe"
if ($LASTEXITCODE -ne 0) {
    throw 'BFD-Service manifest registration failed'
}
Get-WinEvent -ListProvider 'BFD-Service'
Get-WinEvent -ListLog 'BFD-Service/Operational'
```

The queries display the `BFD-Service` provider and its Operational channel.
Use the final installed executable path: Event Viewer loads messages and
metadata from it. The manifest can come from the repository or a deployed copy.
Building or running the binary doesn't install the manifest.

### 4. Start the service

Start the provisioned service:

```powershell
Start-Service BfdWinService
```

The command returns without output on success.

### 5. Verify startup

Check the Windows Service Control Manager (SCM) status:

```powershell
Get-Service BfdWinService | Select-Object Name, Status
```

Successful startup reports:

```text
Name          Status
----          ------
BfdWinService Running
```

SCM `Running` means configuration is valid, sockets are open, and any configured
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

From the repository root, start the console process:

```powershell
.\target\release\bfd-winservice.exe --console
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
.\target\release\bfd-winservice.exe --console > .\bfd-console.log
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
$manifest = (Resolve-Path .\events\BFD-Service.man).Path
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
