#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-RestrictedAcl.ps1')
. (Join-Path $PSScriptRoot 'Assert-StatusComPermission.ps1')
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
    $productVersions = @($properties | Where-Object Name -EQ 'ProductVersion')
    Assert-Package ($productVersions.Count -eq 1 -and $productVersions[0].Value -match '^\d+\.\d+\.\d+$') 'Expected one three-part ProductVersion.'
    $productVersion = $productVersions[0].Value
    if ($ExpectedVersion) {
        Assert-Package ($productVersion -ceq $ExpectedVersion) "ProductVersion must match $ExpectedVersion."
    }
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
    $services = @(Get-MsiRows 'SELECT `ServiceInstall`, `Name`, `DisplayName`, `ServiceType`, `StartType`, `StartName`, `Arguments`, `Component_`, `Dependencies` FROM `ServiceInstall`' @('Id','Name','DisplayName','Type','Start','Account','Arguments','Component','Dependencies'))
    Assert-Package ($services.Count -eq 2) 'Expected the BFD service and BGP broker.'
    $service = @($services | Where-Object Name -EQ 'BfdWinService')[0]
    Assert-Package ($service.Name -eq 'BfdWinService' -and $service.DisplayName -eq 'BFD Windows Service') 'Service names differ from documentation.'
    Assert-Package ($service.Type -eq '16' -and $service.Start -eq '2' -and $service.Account -eq 'NT AUTHORITY\LocalService') 'Expected an Automatic LocalService own-process service.'
    Assert-Package ([string]::IsNullOrEmpty($service.Arguments)) 'Service command line must have no console or configuration arguments.'
    Assert-Package ($service.Dependencies -ceq 'BfdBgpBroker[~]RpcSs[~][~]') 'BFD must depend on the broker and RPC service for COM activation.'
    $broker = @($services | Where-Object Name -EQ 'BfdBgpBroker')[0]
    Assert-Package ($broker.Type -eq '16' -and $broker.Start -eq '2' -and $broker.Account -eq 'LocalSystem' -and $broker.Dependencies -ceq 'RpcSs[~][~]' -and [string]::IsNullOrEmpty($broker.Arguments)) 'Expected an Automatic, own-process LocalSystem BGP broker.'
    $controls = @(Get-MsiRows 'SELECT `Event`, `Wait` FROM `ServiceControl`' @('Event','Wait'))
    Assert-Package ($controls.Count -eq 2 -and @($controls | Where-Object { $_.Event -ne '162' -or $_.Wait -ne '1' }).Count -eq 0) 'Both services must stop on install/removal, uninstall cleanly, and await cleanup.'
    $files = @(Get-MsiRows 'SELECT `File`, `FileName`, `Component_`, `Version` FROM `File`' @('Id','Name','Component','Version'))
    Assert-Package ($files.Count -eq 4) 'Expected both executables, manifest, and logging script.'
    foreach ($name in @('bfd-winservice.exe','bfd-bgp-broker.exe','BFD-Service.man','Initialize-Logging.ps1')) {
        Assert-Package (@($files | Where-Object { ($_.Name -split '\|')[-1] -eq $name }).Count -eq 1) "Missing payload: $name"
    }
    $serviceFiles = @($files | Where-Object Id -EQ 'ServiceExe')
    Assert-Package ($serviceFiles.Count -eq 1 -and $serviceFiles[0].Version -ceq "$productVersion.0") 'Packaged executable version must match ProductVersion with a zero fourth field.'
    $brokerFiles = @($files | Where-Object Id -EQ 'BrokerExe')
    Assert-Package ($brokerFiles.Count -eq 1 -and $brokerFiles[0].Version -ceq "$productVersion.0") 'Broker executable version must match ProductVersion.'
    $components = @(Get-MsiRows 'SELECT `Component`, `Attributes`, `KeyPath` FROM `Component`' @('Id','Attributes','KeyPath'))
    foreach ($component in $components) {
        Assert-Package (([int]$component.Attributes -band 256) -ne 0) "Non-x64 component: $($component.Id)"
    }
    Assert-Package (@($components | Where-Object { $_.Id -eq $service.Component -and $_.KeyPath -eq 'ServiceExe' }).Count -eq 1) 'SCM must use the installed executable key path.'
    Assert-Package (@($components | Where-Object { $_.Id -eq $broker.Component -and $_.KeyPath -eq 'BrokerExe' }).Count -eq 1) 'Broker SCM entry must use the broker executable key path.'
    $directories = @(Get-MsiRows 'SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`' @('Id','Parent','Name'))
    Assert-Package (@($directories | Where-Object { $_.Id -eq 'INSTALLFOLDER' -and $_.Parent -eq 'ProgramFiles64Folder' -and ($_.Name -split '\|')[-1] -eq 'BfdWinService' }).Count -eq 1) 'Application must default to the machine Program Files directory.'
    $registry = @(Get-MsiRows 'SELECT `Registry`, `Root`, `Key`, `Name`, `Value`, `Component_` FROM `Registry`' @('Id','Root','Key','Name','Value','Component'))
    Assert-Package (@($registry | Where-Object Root -NE '2').Count -eq 0) 'All registry entries must use HKLM.'
    $defaults = @{ Multihop='#0'; LogToFile='#0'; LogFilePath='[LOGFOLDER]trace.log' }
    $statusRegistry = @(Get-StatusComRegistryValues)
    Assert-Package ($registry.Count -eq ($defaults.Count + 1 + $statusRegistry.Count)) 'Expected registry defaults, the security marker, and status COM registration.'
    $policy = @($registry | Where-Object Id -EQ 'ParametersPolicyValue')
    Assert-Package ($policy.Count -eq 1 -and $policy[0].Component -eq 'ParametersSecurityComponent' -and $policy[0].Root -eq '2' -and $policy[0].Key -eq 'SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters' -and $policy[0].Name -eq '_InstallerPolicy' -and $policy[0].Value -eq '#1') 'Missing repairable Parameters security component.'
    $policyComponent = @($components | Where-Object Id -EQ 'ParametersSecurityComponent')[0]
    Assert-Package (([int]$policyComponent.Attributes -band 128) -eq 0 -and $policyComponent.KeyPath -eq 'ParametersPolicyValue') 'Parameters security must be reapplied independently of preserved defaults.'
    foreach ($name in $defaults.Keys) {
        $rows = @($registry | Where-Object Name -EQ $name)
        Assert-Package ($rows.Count -eq 1) "Missing registry default: $name"
        $row = $rows[0]
        Assert-Package ($row.Root -eq '2' -and $row.Key -eq 'SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters' -and $row.Value -eq $defaults[$name]) "Incorrect type, path, or default: $name"
        $component = @($components | Where-Object Id -EQ $row.Component)[0]
        Assert-Package (([int]$component.Attributes -band 128) -ne 0) "Default must preserve existing configuration: $name"
    }
    foreach ($entry in $statusRegistry) {
        $rows = @($registry | Where-Object Id -EQ $entry.Id)
        Assert-Package ($rows.Count -eq 1) "Missing status COM registry entry: $($entry.Id)"
        $row = $rows[0]
        Assert-Package ($row.Key -ceq $entry.Key -and $row.Name -ceq $entry.Name) "Incorrect status COM registry path: $($entry.Id)"
        if ($entry.Type -eq 'binary') {
            Assert-Package ($row.Value.StartsWith('#x')) 'COM security descriptors must use REG_BINARY.'
            Assert-StatusComPermission -Descriptor (ConvertFrom-StatusPermissionHex $row.Value) -ObjectName $entry.Id -AccessMask ([int]$entry.Value)
        } else {
            $expectedValue = if ($entry.Type -eq 'integer') { '#' + $entry.Value } else { $entry.Value }
            Assert-Package ($row.Value -ceq $expectedValue) "Incorrect COM registry value: $($entry.Id)"
        }
        $component = @($components | Where-Object Id -EQ $row.Component)[0]
        Assert-Package (([int]$component.Attributes -band 128) -eq 0) 'COM registration must be repairable.'
    }
    $permissions = @(Get-MsiRows 'SELECT `LockObject`, `Table`, `SDDLText`, `Condition` FROM `MsiLockPermissionsEx`' @('Object','Table','Sddl','Condition'))
    Assert-Package ($permissions.Count -eq 14) 'Expected explicit permissions for folders, files, parameters, services, and five COM registration roots.'
    $serviceSid = 'S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512'
    foreach ($permission in $permissions) {
        Assert-Package ([string]::IsNullOrEmpty($permission.Condition)) 'Installation security must apply unconditionally.'
        $acl = [Security.AccessControl.RawSecurityDescriptor]::new($permission.Sddl)
        switch ($permission.Table) {
            'CreateFolder' {
                Assert-Package ($permission.Object -in @('INSTALLFOLDER','LOGFOLDER')) 'Unexpected folder ACL.'
                $access = if ($permission.Object -eq 'LOGFOLDER') { 0x1301bf } else { 0x1200a9 }
                Assert-RestrictedAcl -Descriptor $acl -ObjectName $permission.Object -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags 'ObjectInherit, ContainerInherit' -AdditionalAccess @{$serviceSid=$access}
            }
            'File' {
                Assert-Package (@($files | Where-Object Id -EQ $permission.Object).Count -eq 1) 'File ACL must target an installed payload.'
                Assert-RestrictedAcl -Descriptor $acl -ObjectName $permission.Object -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -AdditionalAccess @{$serviceSid=0x1200a9}
            }
            'Registry' {
                $secured = @($registry | Where-Object Id -EQ $permission.Object)
                Assert-Package ($secured.Count -eq 1 -and $secured[0].Root -eq '2') 'Registry ACL must target machine-wide registration or parameters.'
                if ($secured[0].Id -eq 'ParametersPolicyValue') {
                    Assert-RestrictedAcl -Descriptor $acl -ObjectName $permission.Object -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -ReadSid $serviceSid
                } else {
                    Assert-Package ($secured[0].Id -in @('StatusClassName','StatusProgIdName','StatusVersionIndependentProgIdName','StatusAppName','StatusExeAppId')) 'Unexpected registry ACL target.'
                    Assert-RestrictedAcl -Descriptor $acl -ObjectName $permission.Object -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -AdditionalAccess @{'S-1-5-19'=0x20019}
                }
            }
            'ServiceInstall' {
                Assert-Package (@($services | Where-Object Id -EQ $permission.Object).Count -eq 1) 'Service ACL must target an installed service.'
                Assert-RestrictedAcl -Descriptor $acl -ObjectName $permission.Object -FullAccess 0xf01ff -ReadAccess 0x2008d -ReadSid 'S-1-5-11'
            }
            default { throw "Unexpected permission target: $($permission.Table)" }
        }
    }
    Assert-Package (@($permissions | Where-Object Table -EQ 'CreateFolder').Count -eq 2 -and @($permissions | Where-Object Table -EQ 'File').Count -eq 4) 'Missing folder or file protection.'
    Assert-Package (@($permissions | Where-Object Table -EQ 'ServiceInstall').Count -eq 2) 'Both services must restrict Start/Stop to SYSTEM and administrators.'
    $securedKeys = @($permissions | Where-Object Table -EQ 'Registry' | ForEach-Object {
        $id = $_.Object
        ($registry | Where-Object Id -EQ $id).Key
    } | Sort-Object -Unique)
    $expectedKeys = @('SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters') + @(
        $statusRegistry | Where-Object Id -In @('StatusClassName','StatusProgIdName','StatusVersionIndependentProgIdName','StatusAppName','StatusExeAppId') | Select-Object -ExpandProperty Key)
    Assert-Package (@(Compare-Object $expectedKeys $securedKeys).Count -eq 0) 'Parameters and all COM registration roots must have protected ACLs.'
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
    $actions = @(Get-MsiRows 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' @('Name','Type','Source','Target'))
    $recovery = @(Get-MsiRows 'SELECT `ServiceName`, `Component_`, `NewService`, `FirstFailureActionType`, `SecondFailureActionType`, `ThirdFailureActionType`, `ResetPeriodInDays`, `RestartServiceDelayInSeconds` FROM `Wix4ServiceConfig`' @('Service','Component','New','First','Second','Third','ResetDays','DelaySeconds'))
    Assert-Package ($recovery.Count -eq 2) 'Expected recovery actions for both services.'
    foreach ($expected in @(@('BfdBgpBroker','BrokerComponent','5'), @('BfdWinService','ServiceComponent','10'))) {
        $rows = @($recovery | Where-Object Service -EQ $expected[0])
        Assert-Package ($rows.Count -eq 1 -and $rows[0].Component -eq $expected[1] -and $rows[0].New -eq '1' -and $rows[0].First -eq 'restart' -and $rows[0].Second -eq 'restart' -and $rows[0].Third -eq 'restart' -and $rows[0].ResetDays -eq '1' -and $rows[0].DelaySeconds -eq $expected[2]) "$($expected[0]) must restart after a failure with a $($expected[2])-second delay."
    }
    $policyActions = @{
        PrepareServicePolicy=@(3090,'--prepare-install')
        ConfigureServicePolicy=@(3090,'--configure-install')
        RollbackServicePolicy=@(3410,'--rollback-install')
        CommitServicePolicy=@(3602,'--commit-install')
    }
    foreach ($name in $policyActions.Keys) {
        $rows = @($actions | Where-Object Name -EQ $name)
        Assert-Package ($rows.Count -eq 1 -and [int]$rows[0].Type -eq $policyActions[$name][0] -and $rows[0].Source -eq 'BrokerExe' -and $rows[0].Target -ceq $policyActions[$name][1]) "Expected elevated transactional fixed-target service action: $name"
    }
    $sequence = @(Get-MsiRows 'SELECT `Action`, `Sequence`, `Condition` FROM `InstallExecuteSequence`' @('Name','Sequence','Condition'))
    $previous = 0
    foreach ($name in @('InstallFiles','RollbackServicePolicy','PrepareServicePolicy','InstallServices','ConfigureServicePolicy','CommitServicePolicy','StartServices')) {
        $row = @($sequence | Where-Object Name -EQ $name)[0]
        Assert-Package ([int]$row.Sequence -gt $previous) "Service provisioning has an unsafe action order: $name"
        if ($policyActions.ContainsKey($name)) { Assert-Package ($row.Condition -ceq 'NOT REMOVE~="ALL"') 'Service provisioning must apply on install/repair, never uninstall.' }
        $previous = [int]$row.Sequence
    }
    foreach ($name in @('Wix4RegisterEventManifest_X64','Wix4UnregisterEventManifest_X64','Wix4RollbackRegisterEventManifest_X64','Wix4RollbackUnregisterEventManifest_X64','Wix5SchedFirewallExceptionsInstall_X64','Wix5SchedFirewallExceptionsUninstall_X64','Wix5RollbackFirewallExceptionsInstall_X64','Wix5RollbackFirewallExceptionsUninstall_X64')) {
        Assert-Package (@($actions | Where-Object Name -EQ $name).Count -eq 1) "Missing transactional x64 action: $name"
    }
    Write-Output "Validated x64 MSI version $productVersion, elevation, services, payload, local administrator COM registration, protected ACLs, registry defaults, firewall rules, and manifest lifecycle: $resolvedPath"
}
finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
