#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
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

function Get-BfdEvents {
    param([int]$Id)
    @(Get-WinEvent -FilterHashtable @{
        LogName='BFD-Service/Operational'; Id=$Id; StartTime=$startedAt
    } -ErrorAction SilentlyContinue)
}

Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdWinService'")) 'The runner already has BfdWinService.'
Assert-Installed (-not (Test-Path -LiteralPath $installDirectory)) 'The installation folder already exists.'
Assert-Installed (-not (Test-Path -LiteralPath $logDirectory)) 'The logging folder already exists.'
try {
    Invoke-Msi '/i' 'install.log'
    $installed = $true
    $service = Get-CimInstance Win32_Service -Filter "Name='BfdWinService'"
    Assert-Installed ($service.StartMode -eq 'Auto' -and $service.State -eq 'Stopped') 'Expected an Automatic, stopped service.'
    Assert-Installed ($service.StartName -eq 'LocalSystem' -and $service.PathName -eq ('"' + $executable + '"')) 'SCM account or quoted executable path is incorrect.'
    foreach ($name in @('bfd-winservice.exe','BFD-Service.man','Initialize-Logging.ps1')) {
        Assert-Installed (Test-Path -LiteralPath (Join-Path $installDirectory $name)) "Missing installed file: $name"
    }
    & (Join-Path $PSScriptRoot 'Test-ExecutableVersion.ps1') -Path $executable -ExpectedVersion $ExpectedVersion
    $uninstallEntries = @(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object DisplayName -EQ 'BFD Windows Service')
    Assert-Installed ($uninstallEntries.Count -eq 1 -and $uninstallEntries[0].DisplayVersion -ceq $ExpectedVersion) 'Installed DisplayVersion must match the release version.'
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
    Start-Service BfdWinService
    Assert-Installed ((Get-CimInstance Win32_Service -Filter "Name='BfdWinService'").State -eq 'Running') 'Configured service failed to start.'
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

    $customLog = Join-Path $logDirectory 'custom.log'
    New-ItemProperty -Path $parameters -Name LogToFile -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path $parameters -Name LogFilePath -PropertyType String -Value $customLog -Force
    Invoke-Msi '/fomus' 'repair.log'
    $settings = Get-ItemProperty -Path $parameters
    Assert-Installed ($settings.Multihop -eq 1 -and $settings.LogToFile -eq 1 -and $settings.LogFilePath -eq $customLog) 'Repair reset administrator settings.'
    Start-Service BfdWinService
    Stop-Service BfdWinService
    $deadline = (Get-Date).AddSeconds(10)
    do {
        $text = if (Test-Path -LiteralPath $customLog) { Get-Content -LiteralPath $customLog -Raw } else { '' }
        if ($text -match 'event_id=106 level=Information') { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    Assert-Installed ($text -match '(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z .*event_id=106 level=Information') 'Missing UTC file event after repair.'
    Write-Output 'Installation, version, configuration, firewall, rendered ETW, file logging, and repair checks passed.'
}
finally {
    if ($installed) { Invoke-Msi '/x' 'uninstall.log' }
}
Assert-Installed ($null -eq (Get-CimInstance Win32_Service -Filter "Name='BfdWinService'")) 'Service remained after uninstall.'
Assert-Installed (-not (Test-Path -LiteralPath $executable)) 'Executable remained after uninstall.'
Assert-Installed (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *').Count -eq 0) 'Firewall rules remained after uninstall.'
Assert-Installed (@(Get-WinEvent -ListProvider BFD-Service -ErrorAction SilentlyContinue).Count -eq 0) 'Event provider remained after uninstall.'
Assert-Installed (Test-Path -LiteralPath $customLog) 'Uninstall removed user-generated logs.'
Write-Output 'Uninstall removed the service, payload, event provider, and firewall rules while retaining logs.'
