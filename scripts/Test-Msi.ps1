#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($resolvedPath, 0)

function Get-MsiRows {
    param([string]$Query, [string[]]$Columns)
    $view = $database.OpenView($Query)
    try {
        [void]$view.Execute()
        while ($record = $view.Fetch()) {
            try {
                $values = [ordered]@{}
                for ($index = 0; $index -lt $Columns.Count; $index++) {
                    $values[$Columns[$index]] = $record.GetType().InvokeMember(
                        'StringData', [Reflection.BindingFlags]::GetProperty,
                        $null, $record, @($index + 1))
                }
                [pscustomobject]$values
            }
            finally {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
            }
        }
    }
    finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Assert-Package {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "MSI validation failed: $Message" }
}

try {
    $summary = $database.SummaryInformation(0)
    try {
        Assert-Package ($summary.Property(7) -eq 'x64;1033') 'Expected an x64 MSI.'
        $summaryFlags = [int]($summary.Property(15))
        Assert-Package (($summaryFlags -band 8) -eq 0) 'Package must request elevation rather than declare that elevated privileges are unnecessary.'
    }
    finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
    }
    $properties = @(Get-MsiRows 'SELECT `Property`, `Value` FROM `Property`' @('Name','Value'))
    $allUsers = @($properties | Where-Object Name -EQ 'ALLUSERS')
    Assert-Package ($allUsers.Count -eq 1 -and $allUsers[0].Value -eq '1') 'Package must require per-machine installation (ALLUSERS=1).'
    Assert-Package (@($properties | Where-Object Name -EQ 'Privileged').Count -eq 0) 'Windows Installer must determine installation privileges.'
    $conditions = @(Get-MsiRows 'SELECT `Condition`, `Description` FROM `LaunchCondition`' @('Condition','Message'))
    $privilegeConditions = @($conditions | Where-Object Condition -EQ 'Privileged')
    Assert-Package ($privilegeConditions.Count -eq 1 -and $privilegeConditions[0].Message -like 'Administrator privileges are required*') 'Expected an administrator privilege launch condition with a clear failure message.'
    $executeSequence = @(Get-MsiRows 'SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`' @('Action','Sequence'))
    $launch = @($executeSequence | Where-Object Action -EQ 'LaunchConditions')
    $initialize = @($executeSequence | Where-Object Action -EQ 'InstallInitialize')
    Assert-Package ($launch.Count -eq 1 -and $initialize.Count -eq 1 -and [int]$launch[0].Sequence -gt 0 -and [int]$launch[0].Sequence -lt [int]$initialize[0].Sequence) 'Silent installation must check privileges before changing the machine.'
    $uiLaunch = @(Get-MsiRows 'SELECT `Sequence` FROM `InstallUISequence` WHERE `Action` = ''LaunchConditions''' @('Sequence'))
    Assert-Package ($uiLaunch.Count -eq 1 -and [int]$uiLaunch[0].Sequence -gt 0) 'Interactive installation must check privileges.'
    $services = @(Get-MsiRows 'SELECT `Name`, `DisplayName`, `ServiceType`, `StartType`, `StartName`, `Arguments`, `Component_` FROM `ServiceInstall`' @('Name','DisplayName','Type','Start','Account','Arguments','Component'))
    Assert-Package ($services.Count -eq 1) 'Expected one service.'
    $service = $services[0]
    Assert-Package ($service.Name -eq 'BfdWinService' -and $service.DisplayName -eq 'BFD Windows Service') 'Service names differ from documentation.'
    Assert-Package ($service.Type -eq '16' -and $service.Start -eq '2' -and $service.Account -eq 'LocalSystem') 'Expected an Automatic LocalSystem own-process service.'
    Assert-Package ([string]::IsNullOrEmpty($service.Arguments)) 'Service command line must have no console or configuration arguments.'
    $controls = @(Get-MsiRows 'SELECT `Event`, `Wait` FROM `ServiceControl`' @('Event','Wait'))
    Assert-Package ($controls.Count -eq 1 -and $controls[0].Event -eq '162' -and $controls[0].Wait -eq '1') 'Service must stop on install/removal, uninstall cleanly, and await cleanup.'
    $files = @(Get-MsiRows 'SELECT `File`, `FileName`, `Component_` FROM `File`' @('Id','Name','Component'))
    Assert-Package ($files.Count -eq 3) 'Expected the executable, manifest, and logging script.'
    foreach ($name in @('bfd-winservice.exe','BFD-Service.man','Initialize-Logging.ps1')) {
        Assert-Package (@($files | Where-Object { ($_.Name -split '\|')[-1] -eq $name }).Count -eq 1) "Missing payload: $name"
    }
    $components = @(Get-MsiRows 'SELECT `Component`, `Attributes`, `KeyPath` FROM `Component`' @('Id','Attributes','KeyPath'))
    foreach ($component in $components) {
        Assert-Package (([int]$component.Attributes -band 256) -ne 0) "Non-x64 component: $($component.Id)"
    }
    Assert-Package (@($components | Where-Object { $_.Id -eq $service.Component -and $_.KeyPath -eq 'ServiceExe' }).Count -eq 1) 'SCM must use the installed executable key path.'
    $registry = @(Get-MsiRows 'SELECT `Root`, `Key`, `Name`, `Value`, `Component_` FROM `Registry`' @('Root','Key','Name','Value','Component'))
    $defaults = @{ Multihop='#0'; LogToFile='#0'; LogFilePath='[LOGFOLDER]trace.log' }
    Assert-Package ($registry.Count -eq $defaults.Count) 'Unexpected registry payload.'
    foreach ($name in $defaults.Keys) {
        $rows = @($registry | Where-Object Name -EQ $name)
        Assert-Package ($rows.Count -eq 1) "Missing registry default: $name"
        $row = $rows[0]
        Assert-Package ($row.Root -eq '2' -and $row.Key -eq 'SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters' -and $row.Value -eq $defaults[$name]) "Incorrect type, path, or default: $name"
        $component = @($components | Where-Object Id -EQ $row.Component)[0]
        Assert-Package (([int]$component.Attributes -band 128) -ne 0) "Default must preserve existing configuration: $name"
    }
    $manifest = @(Get-MsiRows 'SELECT `File`, `Component_` FROM `Wix4EventManifest`' @('File','Component'))
    Assert-Package ($manifest.Count -eq 1 -and $manifest[0].File -eq '[#EventManifest]' -and $manifest[0].Component -eq 'ManifestComponent') 'Expected installed-manifest registration.'
    $manifestPaths = @(Get-MsiRows 'SELECT `File`, `Name`, `Value` FROM `Wix4XmlFile`' @('File','Name','Value'))
    foreach ($name in @('messageFileName','resourceFileName')) {
        Assert-Package (@($manifestPaths | Where-Object { $_.File -eq '[#EventManifest]' -and $_.Name -eq $name -and $_.Value -eq '[#ServiceExe]' }).Count -eq 1) "Manifest must resolve $name from the installed executable."
    }
    $rules = @(Get-MsiRows 'SELECT `Wix5FirewallException`, `Port`, `RemotePort`, `Protocol`, `Program`, `Direction`, `Profile`, `Attributes`, `Action`, `Enabled` FROM `Wix5FirewallException`' @('Id','LocalPort','RemotePort','Protocol','Program','Direction','Profile','Attributes','Action','Enabled'))
    $expectedRules = @{
        ControlInbound = @('3784,4784,7784','49152-65535','1')
        SbfdReplyInbound = @('49152-65535','7784','1')
        ProbeOutbound = @('49152-65535','3784,4784,7784','2')
        SbfdReplyOutbound = @('7784','49152-65535','2')
    }
    Assert-Package ($rules.Count -eq $expectedRules.Count) 'Expected four scoped firewall rules.'
    foreach ($id in $expectedRules.Keys) {
        $rows = @($rules | Where-Object Id -EQ $id)
        Assert-Package ($rows.Count -eq 1) "Missing firewall rule: $id"
        $row = $rows[0]
        $expected = $expectedRules[$id]
        Assert-Package ($row.LocalPort -eq $expected[0] -and $row.RemotePort -eq $expected[1] -and $row.Direction -eq $expected[2]) "Incorrect firewall ports or direction: $id"
        Assert-Package ($row.Protocol -eq '17' -and $row.Program -eq '[#ServiceExe]' -and $row.Profile -eq '2147483647' -and $row.Attributes -eq '0' -and $row.Action -eq '1' -and $row.Enabled -eq '1') "Rule must allow UDP for this executable on all profiles and fail installation on error: $id"
    }
    $actions = @(Get-MsiRows 'SELECT `Action` FROM `CustomAction`' @('Name'))
    foreach ($name in @('Wix4RegisterEventManifest_X64','Wix4UnregisterEventManifest_X64','Wix4RollbackRegisterEventManifest_X64','Wix4RollbackUnregisterEventManifest_X64','Wix5SchedFirewallExceptionsInstall_X64','Wix5SchedFirewallExceptionsUninstall_X64','Wix5RollbackFirewallExceptionsInstall_X64','Wix5RollbackFirewallExceptionsUninstall_X64')) {
        Assert-Package (@($actions | Where-Object Name -EQ $name).Count -eq 1) "Missing transactional x64 action: $name"
    }
    Write-Output "Validated x64 MSI elevation, service, payload, registry defaults, firewall rules, and manifest lifecycle: $resolvedPath"
}
finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
