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
$comClass = 'HKLM:\SOFTWARE\Classes\CLSID\{4B19A10F-8CD1-46F1-A1EA-6C68ECBA7657}'
$comApp = 'HKLM:\SOFTWARE\Classes\AppID\{EBF04871-D193-4CDF-ABBC-DCD7D220224B}'
$comProgId = 'HKLM:\SOFTWARE\Classes\BfdWinService.SessionState'
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

function Assert-ComRegistration {
    $mappings = @(
        [pscustomobject]@{ Path=$comClass; Name='AppID'; Value='{EBF04871-D193-4CDF-ABBC-DCD7D220224B}' },
        [pscustomobject]@{ Path=$comApp; Name='LocalService'; Value='BfdWinService' },
        [pscustomobject]@{ Path=$comExeApp; Name='AppID'; Value='{EBF04871-D193-4CDF-ABBC-DCD7D220224B}' },
        [pscustomobject]@{ Path="$comProgId\CLSID"; Name=''; Value='{4B19A10F-8CD1-46F1-A1EA-6C68ECBA7657}' }
    )
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        foreach ($mapping in $mappings) {
            $key = $registry.OpenSubKey($mapping.Path.Substring('HKLM:\'.Length))
            Assert-Installed ($null -ne $key) "Missing 64-bit HKLM COM registration: $($mapping.Path)"
            try {
                Assert-Installed ($mapping.Name -in $key.GetValueNames() -and
                    $key.GetValueKind($mapping.Name) -eq [Microsoft.Win32.RegistryValueKind]::String -and
                    $key.GetValue($mapping.Name) -ceq $mapping.Value) `
                    "Expected REG_SZ '$($mapping.Name)' = '$($mapping.Value)' at $($mapping.Path)."
            }
            finally { $key.Dispose() }
        }
    }
    finally { $registry.Dispose() }
}

function Assert-InstallationSecurity {
    $paths = @($installDirectory) + @('bfd-winservice.exe','bfd-bgp-broker.exe','BFD-Service.man','Initialize-Logging.ps1' | ForEach-Object { Join-Path $installDirectory $_ })
    foreach ($object in $paths) {
        $acl = [Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $object).Sddl)
        $flags = if ($object -eq $installDirectory) { 'ObjectInherit, ContainerInherit' } else { 'None' }
        Assert-RestrictedAcl -Descriptor $acl -ObjectName $object -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags $flags -AdditionalAccess @{$serviceSid=0x1200a9}
    }
    foreach ($object in @($comClass, "$comClass\ProgID", $comProgId, "$comProgId\CLSID", $comApp, $comExeApp)) {
        $acl = [Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath $object).Sddl)
        Assert-RestrictedAcl -Descriptor $acl -ObjectName $object -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -AdditionalAccess @{$serviceSid=0x20019}
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
    Assert-Installed ($broker.StartName -eq 'LocalSystem' -and $broker.StartMode -eq 'Manual' -and $broker.PathName -eq ('"' + (Join-Path $installDirectory 'bfd-bgp-broker.exe') + '"')) 'The broker must use LocalSystem, demand startup, and its own executable.'
    foreach ($name in @('BfdWinService','BfdBgpBroker')) {
        $key = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        Assert-Installed ($key.GetValueKind('ServiceSidType') -eq 'DWord' -and $key.GetValue('ServiceSidType') -eq 1) "Missing enabled service SID: $name"
        Assert-Installed ('RpcSs' -in @((Get-Service $name).ServicesDependedOn.Name)) "Missing RpcSs dependency: $name"
    }
    Assert-Installed ('BfdBgpBroker' -in @((Get-Service BfdWinService).ServicesDependedOn.Name)) 'BFD must depend on the broker.'
    Assert-Installed (-not (Test-Path -LiteralPath (Join-Path $installDirectory 'service-policy.rollback'))) 'Installer policy snapshot was not committed.'
}

function Assert-BrokerRejectsUnrelatedClient {
    # The runner is an administrator, but lacks the BFD service SID. It must not
    # gain BGP control through a shared account or administrator group membership.
    Assert-Installed ((Get-Service BfdBgpBroker).Status -eq 'Running') 'Broker is not running.'
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'BfdWinService.Bgp.v1', [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        $denied = $false
        try { $pipe.Connect(1000) }
        catch [UnauthorizedAccessException] { $denied = $true }
        Assert-Installed $denied 'An unrelated process could connect to the privileged BGP pipe.'
    }
    finally { $pipe.Dispose() }
}

function Get-BfdEvents {
    param([int]$Id)
    @(Get-WinEvent -FilterHashtable @{
        LogName='BFD-Service/Operational'; Id=$Id; StartTime=$startedAt
    } -ErrorAction SilentlyContinue)
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
    Assert-ComRegistration
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
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *')
    Assert-Installed ($rules.Count -eq 4) 'Expected four installed firewall rules.'
    foreach ($rule in $rules) {
        $application = $rule | Get-NetFirewallApplicationFilter
        $ports = $rule | Get-NetFirewallPortFilter
        Assert-Installed ($rule.Enabled -eq 'True' -and $rule.Action -eq 'Allow' -and $rule.Profile -eq 'Any') 'Firewall rule must allow traffic on all profiles.'
        Assert-Installed ($application.Program -eq $executable -and $ports.Protocol -eq 'UDP') 'Firewall rule must be scoped to the executable and UDP.'
    }

    # Match the documented administrator provisioning before the first start.
    New-ItemProperty -Path $parameters -Name Local -PropertyType String -Value '127.0.0.240' -Force
    New-ItemProperty -Path $parameters -Name Peer -PropertyType String -Value '127.0.0.241' -Force
    New-ItemProperty -Path $parameters -Name Multihop -PropertyType DWord -Value 1 -Force
    Set-ProcessMitigation -Name bfd-winservice.exe -Enable SEHOP
    Set-ProcessMitigation -Name bfd-bgp-broker.exe -Enable SEHOP
    Start-Service BfdWinService
    Assert-Installed ((Get-CimInstance Win32_Service -Filter "Name='BfdWinService'").State -eq 'Running') 'Configured service failed to start.'
    # BFD startup performs a read-only pipe probe: reaching Running proves that
    # the real LocalService/service-SID token passed the broker's authorization.
    Assert-BrokerRejectsUnrelatedClient
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-BfdEvents 300).Count -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $brokerEvents = @(Get-BfdEvents 300)
    Assert-Installed ($brokerEvents.Count -gt 0 -and $brokerEvents[0].Level -eq 4 -and $brokerEvents[0].Message -like '*broker*ready*') 'No rendered broker readiness event.'
    $session = New-Object -ComObject BfdWinService.SessionState
    try {
        Assert-Installed ($session.State -eq 1 -and $session.StateName -ceq 'Down' -and $session.GetState() -eq 1) 'Automation must report Down without an established peer.'
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) }
    $deadline = (Get-Date).AddSeconds(10)
    while (@(Get-BfdEvents 1).Count -eq 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    $events = @(Get-BfdEvents 1)
    Assert-Installed ($events.Count -gt 0 -and $events[0].Level -eq 4 -and $events[0].Message -like '*BFD service started*') 'No rendered Informational startup event.'
    $retainedSession = New-Object -ComObject BfdWinService.SessionState
    try {
        Stop-Service BfdWinService
        $disconnected = $false
        try { [void]$retainedSession.GetState() } catch { $disconnected = $true }
        Assert-Installed $disconnected 'A retained COM object must fail after service Stop instead of returning stale state.'
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($retainedSession) }
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
    # mutate any peer. Starting BFD again rechecks the real service token/pipe.
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
    Assert-BrokerRejectsUnrelatedClient
    Stop-Service BfdWinService

    $customLog = Join-Path $logDirectory 'custom.log'
    New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value $customLog -Force
    Invoke-Msi '/fomus' 'repair.log'
    Assert-ComRegistration
    Assert-InstallationSecurity
    Assert-ServicePolicy
    $settings = Get-ItemProperty -Path $parameters
    Assert-Installed ($settings.Multihop -eq 1 -and $settings.LogToFile -eq 1 -and $settings.LogFilePath -eq $customLog) 'Repair reset administrator settings.'
    # Activate the stopped service through COM after repair, exercising LocalService.
    $session = New-Object -ComObject BfdWinService.SessionState
    try {
        Assert-Installed ($session.GetState() -eq 1 -and $session.StateName -ceq 'Down') 'COM activation failed after repair.'
        Assert-Installed ((Get-Service BfdWinService).Status -eq 'Running') 'COM did not start the configured service.'
    }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) }
    Stop-Service BfdWinService
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $text = if (Test-Path -LiteralPath $customLog) { Get-Content -LiteralPath $customLog -Raw } else { '' }
        if ($text -match 'event_id=106 level=Information') { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    Assert-Installed ($text -match '(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z .*event_id=106 level=Information') 'Missing UTC file event after repair.'
    Write-Output 'Installation, service accounts/SIDs, broker authorization/recovery, protected ACLs, versions, COM activation, firewall, rendered ETW, file logging, and repair checks passed.'
}
finally {
    if ($installed) { Invoke-Msi '/x' 'uninstall.log' }
}
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdWinService'")) 'Service remained after uninstall.'
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdBgpBroker'")) 'Broker remained after uninstall.'
Assert-Installed (-not (Test-Path -LiteralPath (Join-Path $installDirectory 'bfd-bgp-broker.exe'))) 'Broker executable remained after uninstall.'
Assert-Installed (-not (Test-Path -LiteralPath $executable)) 'Executable remained after uninstall.'
foreach ($path in @($comClass, $comApp, $comProgId, $comExeApp)) {
    Assert-Installed (-not (Test-Path -LiteralPath $path)) "COM registration remained after uninstall: $path"
}
Assert-Installed (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *').Count -eq 0) 'Firewall rules remained after uninstall.'
Assert-Installed (@(Get-WinEvent -ListProvider BFD-Service -ErrorAction SilentlyContinue).Count -eq 0) 'Event provider remained after uninstall.'
Assert-Installed (Test-Path -LiteralPath $customLog) 'Uninstall removed user-generated logs.'
Write-Output 'Uninstall removed the service, payload, COM registration, event provider, and firewall rules while retaining logs.'
