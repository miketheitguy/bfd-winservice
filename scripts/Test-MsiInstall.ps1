#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-RestrictedAcl.ps1')
. (Join-Path $PSScriptRoot 'Assert-ServiceAccess.ps1')
# Installation changes SCM, HKLM, Event Log, and firewall state. Exercise it only
# on the disposable machine provided by this workflow, never the developer PC.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This installation test runs only on a GitHub-hosted Actions runner.'
}
$resolvedMsi = (Resolve-Path -LiteralPath $Path).Path
$outputDirectory = Split-Path $resolvedMsi -Parent
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
$executable = Join-Path $installDirectory 'bfd-winservice.exe'
$logDirectory = Join-Path $env:ProgramData 'BfdWinService'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
# Earlier releases registered status COM keys; upgrades and installs must leave none.
$comClass = 'HKLM:\SOFTWARE\Classes\CLSID\{E4A97D25-73E2-4E6C-9A35-281B6AE697C3}'
$comApp = 'HKLM:\SOFTWARE\Classes\AppID\{954E4BD0-8B46-4A93-B43A-35A4A40ED8F7}'
$comProgId = 'HKLM:\SOFTWARE\Classes\BfdWinService.Status.1'
$comVersionIndependentProgId = 'HKLM:\SOFTWARE\Classes\BfdWinService.Status'
$comExeApp = 'HKLM:\SOFTWARE\Classes\AppID\bfd-winservice.exe'
$serviceSid = 'S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512'
$startedAt = Get-Date
$installed = $false

function Assert-Installed {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "MSI installation test failed: $Message" }
}

function Invoke-Msi {
    param([string]$Operation, [string]$LogName)
    $log = Join-Path $outputDirectory $LogName
    $process = Start-Process -FilePath msiexec.exe -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList @($Operation, ('"' + $resolvedMsi + '"'), '/qn', '/norestart', '/L*v', ('"' + $log + '"'))
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "msiexec $Operation failed with exit code $($process.ExitCode); see $log"
    }
}

function Assert-NoComRegistration {
    foreach ($path in @($comClass, $comApp, $comProgId, $comVersionIndependentProgId, $comExeApp)) {
        Assert-Installed (-not (Test-Path -LiteralPath $path)) "Unexpected status COM registration: $path"
    }
}

function Assert-InstallationSecurity {
    $paths = @($installDirectory) + @('bfd-winservice.exe','bfd-bgp-broker.exe','BFD-Service.man','Initialize-Logging.ps1' | ForEach-Object { Join-Path $installDirectory $_ })
    foreach ($object in $paths) {
        $acl = [Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $object).Sddl)
        $flags = if ($object -eq $installDirectory) { 'ObjectInherit, ContainerInherit' } else { 'None' }
        Assert-RestrictedAcl -Descriptor $acl -ObjectName $object -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags $flags -AdditionalAccess @{$serviceSid=0x1200a9}
    }
    $acl = [Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $parameters).Sddl)
    Assert-RestrictedAcl -Descriptor $acl -ObjectName $parameters -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -ReadSid $serviceSid
    $acl = [Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $logDirectory).Sddl)
    Assert-RestrictedAcl -Descriptor $acl -ObjectName $logDirectory -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags 'ObjectInherit, ContainerInherit' -AdditionalAccess @{$serviceSid=0x1301bf}
}

function Assert-ServicePolicy {
    $service = Get-CimInstance Win32_Service -Filter "Name='BfdWinService'"
    $broker = Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'"
    Assert-Installed ($service.StartName -eq 'NT AUTHORITY\LocalService' -and $service.PathName -eq ('"' + $executable + '"')) 'BFD must use LocalService and the quoted installed executable.'
    Assert-Installed ($broker.StartName -eq 'LocalSystem' -and $broker.StartMode -eq 'Auto' -and $broker.PathName -eq ('"' + (Join-Path $installDirectory 'bfd-bgp-broker.exe') + '"')) 'The broker must use LocalSystem, automatic startup, and its own executable.'
    foreach ($installed in @($service, $broker)) {
        Assert-Installed ($installed.DelayedAutoStart -eq $true) "Expected Automatic (Delayed Start): $($installed.Name)"
    }
    foreach ($name in @('BfdWinService','BfdBgpBroker')) {
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new([BfdServiceAccess]::ReadDescriptor($name), 0)
        Assert-RestrictedAcl -Descriptor $descriptor -ObjectName $name -FullAccess 0xf01ff -ReadAccess 0x2008d -ReadSid 'S-1-5-11'
        Assert-ServiceReaderAccess -Descriptor $descriptor
        $key = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $sidType = if ($name -eq 'BfdWinService') { 3 } else { 1 }
        Assert-Installed ($key.GetValueKind('ServiceSidType') -eq 'DWord' -and $key.GetValue('ServiceSidType') -eq $sidType) "Expected restricted BFD SID and unrestricted broker SID: $name"
        # Only BFD recovers from a nonzero exit; its requested stops always exit with 0.
        $nonCrash = [int]($name -eq 'BfdWinService')
        Assert-Installed ($key.GetValue('FailureActionsOnNonCrashFailures', 0) -eq $nonCrash) "Unexpected non-crash recovery setting: $name"
        if ($name -eq 'BfdWinService') {
            Assert-Installed ($key.GetValueKind('PreshutdownTimeout') -eq 'DWord' -and $key.GetValue('PreshutdownTimeout') -eq 125000) 'BFD needs 125 seconds for bounded preshutdown cleanup.'
            $privileges = @($key.GetValue('RequiredPrivileges'))
            Assert-Installed ($key.GetValueKind('RequiredPrivileges') -eq 'MultiString' -and
                $privileges.Count -eq 2 -and
                @(Compare-Object @('SeChangeNotifyPrivilege','SeCreateGlobalPrivilege') $privileges).Count -eq 0) 'SCM must grant BFD only ChangeNotify and CreateGlobal, never SeImpersonatePrivilege.'
        } else {
            Assert-Installed ('RequiredPrivileges' -notin $key.GetValueNames()) 'The installer must leave the broker privilege policy at its existing default.'
        }
    }
    Assert-Installed ('RpcSs' -in @((Get-Service BfdBgpBroker).ServicesDependedOn.Name)) 'The MI broker must depend on RpcSs.'
    $dependencies = @((Get-Service BfdWinService).ServicesDependedOn.Name)
    Assert-Installed ($dependencies.Count -eq 1 -and $dependencies[0] -eq 'BfdBgpBroker') 'BFD must depend only on the broker; it needs no COM activation.'
    Assert-Installed (-not (Test-Path -LiteralPath (Join-Path $installDirectory 'service-policy.rollback'))) 'Installer policy snapshot was not committed.'
}

function Assert-InstalledFirewall {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *')
    $expected = @{
        'BfdWinService - control inbound' = @('UDP','Allow','Inbound','3784,4784,7784','49152-65535')
        'BfdWinService - S-BFD replies inbound' = @('UDP','Allow','Inbound','49152-65535','7784')
        'BfdWinService - probes outbound' = @('UDP','Allow','Outbound','49152-65535','3784,4784,7784')
        'BfdWinService - S-BFD replies outbound' = @('UDP','Allow','Outbound','7784','49152-65535')
    }
    Assert-Installed ($rules.Count -eq 4) 'Expected four installed BFD UDP allow rules.'
    foreach ($name in $expected.Keys) {
        $matches = @($rules | Where-Object DisplayName -CEQ $name)
        Assert-Installed ($matches.Count -eq 1) "Missing or duplicate installed firewall rule: $name"
        $rule = $matches[0]
        $application = $rule | Get-NetFirewallApplicationFilter
        $ports = $rule | Get-NetFirewallPortFilter
        $addresses = $rule | Get-NetFirewallAddressFilter
        $values = $expected[$name]
        Assert-Installed ($rule.Enabled -eq 'True' -and $rule.Profile -eq 'Any' -and
            [string]$rule.Action -ceq $values[1] -and [string]$rule.Direction -ceq $values[2]) "Unsafe installed firewall direction/action/profile: $name"
        Assert-Installed ($application.Program -eq $executable -and [string]$ports.Protocol -ceq $values[0] -and
            ($ports.LocalPort -join ',') -ceq $values[3] -and ($ports.RemotePort -join ',') -ceq $values[4] -and
            ($addresses.LocalAddress -join ',') -ceq 'Any' -and ($addresses.RemoteAddress -join ',') -ceq 'Any') "Unsafe installed firewall program/protocol/port/address scope: $name"
    }
}

function Assert-PrivateRpcRejectsUnrelatedClient {
    # The authenticated administrator runner lacks both service SIDs. It must
    # neither read BFD telemetry nor invoke any broker control operation.
    Assert-Installed ((Get-Service BfdWinService).Status -eq 'Running') 'BFD is not running.'
    Assert-Installed ((Get-Service BfdBgpBroker).Status -eq 'Running') 'Broker is not running.'
    $env:BFD_TEST_INSTALLED_BGP_RPC = '1'
    $env:BFD_TEST_INSTALLED_LOCAL_RPC = '1'
    try {
        Push-Location (Split-Path $PSScriptRoot -Parent)
        try {
            cargo test-release --lib bgp::ipc::tests::installed_broker_rejects_unrelated_rpc_caller -- --ignored --exact
            Assert-Installed ($LASTEXITCODE -eq 0) 'Broker RPC did not reject an unrelated caller with access denied.'
            cargo test-release --lib local_rpc::tests::installed_bfd_rejects_unrelated_rpc_caller -- --ignored --exact
            Assert-Installed ($LASTEXITCODE -eq 0) 'BFD status RPC did not reject an unrelated caller with access denied.'
        }
        finally { Pop-Location }
    }
    finally {
        Remove-Item Env:BFD_TEST_INSTALLED_BGP_RPC
        Remove-Item Env:BFD_TEST_INSTALLED_LOCAL_RPC
    }
}

function Get-BfdEvents {
    param([int]$Id)
    @(Get-WinEvent -FilterHashtable @{
        LogName='BFD-Service/Operational'; Id=$Id; StartTime=$startedAt
    } -ErrorAction SilentlyContinue)
}

function Assert-BrokerAuthenticatesBfd {
    param([Parameter(Mandatory)][datetime]$Since)
    # Require an event from this service start, rather than a previous successful
    # connection. This event now requires a converted session-status response.
    $deadline = (Get-Date).AddSeconds(45)
    do {
        $connections = @(Get-BfdEvents 300 | Where-Object {
            $_.TimeCreated -ge $Since -and $_.Level -eq 4 -and
            $_.Message -like '*BFD local RPC mutual service identity verified*'
        })
        if ($connections.Count -gt 0) {
            $broker = Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'"
            $processes = @(Get-CimInstance Win32_Process -Filter "Name='bfd-bgp-broker.exe'")
            Assert-Installed ($processes.Count -eq 1 -and $processes[0].ProcessId -eq $broker.ProcessId) `
                'Status RPC must run inside the broker service process without a helper.'
            Push-Location (Split-Path $PSScriptRoot -Parent)
            try {
                cargo test-release --lib runtime::privileges::tests::installed_broker_token_retains_only_change_notify -- --ignored --exact
                Assert-Installed ($LASTEXITCODE -eq 0) 'The installed broker retained privileges beyond SeChangeNotifyPrivilege.'
            }
            finally { Pop-Location }
            return
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'The installed broker did not authenticate the BFD local RPC interface within 45 seconds.'
}

Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdWinService'")) 'The runner already has BfdWinService.'
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'")) 'The runner already has BfdBgpBroker.'
Assert-Installed (-not (Test-Path -LiteralPath $installDirectory)) 'The installation folder already exists.'
Assert-Installed (-not (Test-Path -LiteralPath $logDirectory)) 'The logging folder already exists.'
try {
    Invoke-Msi '/i' 'install.log'
    $installed = $true
    $service = Get-CimInstance Win32_Service -Filter "Name='BfdWinService'"
    Assert-Installed ($service.StartMode -eq 'Auto' -and $service.State -eq 'Stopped') 'Expected an Automatic, stopped service.'
    Assert-ServicePolicy
    Assert-NoComRegistration
    foreach ($name in @('bfd-winservice.exe','bfd-bgp-broker.exe','BFD-Service.man','Initialize-Logging.ps1')) {
        Assert-Installed (Test-Path -LiteralPath (Join-Path $installDirectory $name)) "Missing installed file: $name"
    }
    Assert-InstallationSecurity
    & (Join-Path $PSScriptRoot 'Test-ExecutableVersion.ps1') -Path $executable -ExpectedVersion $ExpectedVersion
    & (Join-Path $PSScriptRoot 'Test-ExecutableVersion.ps1') -Path (Join-Path $installDirectory 'bfd-bgp-broker.exe') -ExpectedVersion $ExpectedVersion -ExpectedName 'bfd-bgp-broker'
    # Other uninstall entries may omit DisplayName; strict mode rejects missing properties.
    $uninstallEntries = @(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object {
            $displayName = $_.PSObject.Properties['DisplayName']
            $null -ne $displayName -and $displayName.Value -eq 'BFD Windows Service'
        })
    Assert-Installed ($uninstallEntries.Count -eq 1) 'Expected one BFD Windows Service uninstall entry.'
    $displayVersion = $uninstallEntries[0].PSObject.Properties['DisplayVersion']
    Assert-Installed ($null -ne $displayVersion -and $displayVersion.Value -ceq $ExpectedVersion) 'Installed DisplayVersion must match the release version.'
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters')
    try {
        Assert-Installed ($key.GetValueKind('Multihop') -eq 'DWord' -and $key.GetValue('Multihop') -eq 0) 'Multihop must default to DWORD 0.'
        Assert-Installed ($key.GetValueKind('LogToFile') -eq 'DWord' -and $key.GetValue('LogToFile') -eq 0) 'LogToFile must default to DWORD 0.'
        Assert-Installed ($key.GetValueKind('LogFilePath') -eq 'String' -and $key.GetValue('LogFilePath') -eq (Join-Path $logDirectory 'trace.log')) 'LogFilePath must contain the default absolute path.'
    }
    finally { $key.Dispose() }
    Assert-Installed (Test-Path -LiteralPath $logDirectory -PathType Container) 'Missing ProgramData logging folder.'
    $provider = Get-WinEvent -ListProvider BFD-Service
    Assert-Installed ($provider.MessageFilePath -eq $executable -and $provider.ResourceFilePath -eq $executable) 'Manifest resource paths must point to the installed executable.'
    Assert-Installed (Get-WinEvent -ListLog 'BFD-Service/Operational').IsEnabled 'Operational channel is disabled.'
    Assert-InstalledFirewall

    # Match the documented administrator provisioning before the first start.
    New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '127.0.0.240' -Force
    New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '127.0.0.241' -Force
    New-ItemProperty -Path $parameters -Name Multihop -PropertyType DWord -Value 1 -Force
    $probeStarted = Get-Date
    Start-Service BfdWinService
    Assert-Installed ((Get-CimInstance Win32_Service -Filter "Name='BfdWinService'").State -eq 'Running') 'Configured service failed to start.'
    Assert-BrokerAuthenticatesBfd -Since $probeStarted
    # Plain BFD needs no MI query. Both interfaces reject unrelated clients.
    Assert-PrivateRpcRejectsUnrelatedClient
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-BfdEvents 300 | Where-Object Message -Like '*broker*ready*').Count -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $brokerEvents = @(Get-BfdEvents 300 | Where-Object Message -Like '*broker*ready*')
    Assert-Installed ($brokerEvents.Count -gt 0 -and $brokerEvents[0].Level -eq 4 -and $brokerEvents[0].Message -like '*broker*ready*') 'No rendered broker readiness event.'
    Assert-NoComRegistration
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-BfdEvents 1).Count -eq 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    $events = @(Get-BfdEvents 1)
    Assert-Installed ($events.Count -gt 0 -and $events[0].Level -eq 4 -and $events[0].Message -like '*BFD service started*') 'No rendered Informational startup event.'
    Stop-Service BfdWinService
    Assert-Installed (-not (Test-Path -LiteralPath (Join-Path $logDirectory 'trace.log'))) 'Disabled file output wrote trace.log.'
    $deadline = (Get-Date).AddSeconds(10)
    while ((@(Get-BfdEvents 106).Count -eq 0 -or @(Get-BfdEvents 207).Count -eq 0) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    $adminEvents = @(Get-BfdEvents 106)
    $diagnostics = @(Get-BfdEvents 207)
    Assert-Installed ($adminEvents.Count -gt 0 -and $adminEvents[0].Level -eq 4) 'Missing Informational AdminDown event.'
    Assert-Installed ($diagnostics.Count -gt 0 -and $diagnostics[0].Level -eq 3) 'Missing Warning administrative diagnostic.'

    # No provider is configured, so a broker restart must not require RRAS or
    # mutate any peer. Plain BFD can restart after broker recovery.
    $beforeCrash = Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'"
    Assert-Installed ($beforeCrash.State -eq 'Running' -and $beforeCrash.PathName -eq ('"' + (Join-Path $installDirectory 'bfd-bgp-broker.exe') + '"')) 'Recovery test must target the installed broker.'
    & taskkill.exe /PID $beforeCrash.ProcessId /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not terminate the disposable-runner broker for recovery validation.' }
    $deadline = (Get-Date).AddSeconds(25)
    do {
        $recovered = Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'"
        if ($recovered.State -eq 'Running' -and $recovered.ProcessId -ne $beforeCrash.ProcessId) { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    Assert-Installed ($recovered.State -eq 'Running' -and $recovered.ProcessId -ne $beforeCrash.ProcessId) 'SCM did not restart the crashed broker.'
    Start-Service BfdWinService
    Assert-PrivateRpcRejectsUnrelatedClient
    Stop-Service BfdWinService

    $customLog = Join-Path $logDirectory 'custom.log'
    New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value $customLog -Force
    Invoke-Msi '/fomus' 'repair.log'
    Assert-NoComRegistration
    Assert-InstallationSecurity
    Assert-ServicePolicy
    Assert-InstalledFirewall
    $settings = Get-ItemProperty -Path $parameters
    Assert-Installed ($settings.Multihop -eq 1 -and $settings.LogToFile -eq 1 -and $settings.LogFilePath -eq $customLog) 'Repair reset administrator settings.'
    $probeStarted = Get-Date
    Start-Service BfdWinService
    Assert-Installed ((Get-Service BfdWinService).Status -eq 'Running') 'Service failed to start after repair.'
    Assert-BrokerAuthenticatesBfd -Since $probeStarted
    Assert-PrivateRpcRejectsUnrelatedClient
    Stop-Service BfdWinService
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $text = if (Test-Path -LiteralPath $customLog) { Get-Content -LiteralPath $customLog -Raw } else { '' }
        if ($text -match 'event_id=106 level=Information') { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    Assert-Installed ($text -match '(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z .*event_id=106 level=Information') 'Missing UTC file event after repair.'
    Write-Output 'Installation, service accounts/SIDs, mutual local RPC authentication, broker authorization/recovery, protected ACLs, versions, firewall, rendered ETW, file logging, and repair checks passed.'
}
finally {
    if ($installed) { Invoke-Msi '/x' 'uninstall.log' }
}
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdWinService'")) 'Service remained after uninstall.'
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'")) 'Broker remained after uninstall.'
Assert-Installed (-not (Test-Path -LiteralPath (Join-Path $installDirectory 'bfd-bgp-broker.exe'))) 'Broker executable remained after uninstall.'
Assert-Installed (-not (Test-Path -LiteralPath $executable)) 'Executable remained after uninstall.'
foreach ($path in @($comClass, $comApp, $comProgId, $comVersionIndependentProgId, $comExeApp)) {
    Assert-Installed (-not (Test-Path -LiteralPath $path)) "Status COM registration exists after uninstall: $path"
}
Assert-Installed (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *').Count -eq 0) 'Firewall rules remained after uninstall.'
Assert-Installed (@(Get-WinEvent -ListProvider BFD-Service -ErrorAction SilentlyContinue).Count -eq 0) 'Event provider remained after uninstall.'
Assert-Installed (Test-Path -LiteralPath $customLog) 'Uninstall removed user-generated logs.'
Write-Output 'Uninstall removed the service, payload, event provider, and firewall rules while retaining logs.'
