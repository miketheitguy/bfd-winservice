#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [Parameter(Mandatory)][string]$PreviousPath,
    [Parameter(Mandatory)][string]$PreviousVersion,
    [switch]$DisposableVm
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$hostedRunner = $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted'
$authorizedVm = $DisposableVm -and $env:COMPUTERNAME -eq 'BFD-WS2025' -and
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters')
if (-not $hostedRunner -and -not $authorizedVm) {
    throw 'Upgrade tests require a GitHub-hosted runner or the explicit disposable BFD-WS2025 VM.'
}
if (Get-Service BfdWinService,BfdBgpBroker -ErrorAction SilentlyContinue) {
    throw 'Upgrade tests require a machine without an existing BFD installation.'
}
if ([version]$ExpectedVersion -le [version]$PreviousVersion) {
    throw 'The upgrade version must be newer than the published baseline.'
}
$setup = (Resolve-Path -LiteralPath $Path).Path
$previous = (Resolve-Path -LiteralPath $PreviousPath).Path
$msi = (Resolve-Path -LiteralPath $MsiPath).Path
$outputDirectory = Split-Path $setup -Parent
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
$logDirectory = Join-Path $env:ProgramData 'BfdWinService'
$sentinel = Join-Path $logDirectory 'upgrade-preserved.log'
$fixture = Join-Path $outputDirectory ("upgrade-rollback-$([guid]::NewGuid()).msi")
$cleanupSetup = $previous
$installed = $false

function Invoke-Setup {
    param([string]$Installer, [string]$Operation, [string]$LogName)
    $log = Join-Path $outputDirectory $LogName
    $process = Start-Process -FilePath $Installer -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList @($Operation,'/quiet','/norestart','/log',('"'+$log+'"'))
    if ($process.ExitCode -notin @(0,3010)) { throw "Setup $Operation failed: $($process.ExitCode); see $log" }
}
function Assert-Version {
    param([string]$Version)
    foreach ($name in @('bfd-winservice','bfd-bgp-broker')) {
        & (Join-Path $PSScriptRoot 'Test-ExecutableVersion.ps1') `
            -Path (Join-Path $installDirectory "$name.exe") -ExpectedVersion $Version -ExpectedName $name
    }
    $entries = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object {
            $p = $_.PSObject.Properties['DisplayName']
            $kind = $_.PSObject.Properties['WindowsInstaller']
            $null -ne $p -and $p.Value -eq 'BFD Windows Service' -and $null -ne $kind -and $kind.Value -eq 1
        })
    if ($entries.Count -ne 1 -or $entries[0].DisplayVersion -cne $Version) {
        throw 'The upgrade did not leave exactly one matching MSI product registration.'
    }
    if (Test-Path -LiteralPath (Join-Path $installDirectory 'service-policy.rollback')) {
        throw 'An upgrade left the service-policy snapshot behind.'
    }
}
function Get-Configuration {
    $key = Get-Item -LiteralPath $parameters
    $values = @(foreach ($name in ($key.GetValueNames() | Sort-Object)) {
        [ordered]@{Name=$name;Kind=[string]$key.GetValueKind($name);Value=$key.GetValue($name)}
    })
    ConvertTo-Json -InputObject $values -Depth 8 -Compress
}
function Get-ServicePolicy {
    $policy = @(foreach ($name in @('BfdWinService','BfdBgpBroker')) {
        $key = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
        $descriptor = (& sc.exe sdshow $name | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Cannot read $name service ACL." }
        $values = @(foreach ($value in @('Start','DelayedAutoStart','ServiceSidType','RequiredPrivileges',
            'FailureActions','FailureActionsOnNonCrashFailures','PreshutdownTimeout','DependOnService')) {
            [ordered]@{Name=$value;Present=$value -in $key.GetValueNames();Value=$key.GetValue($value)}
        })
        [ordered]@{Name=$name;Account=$service.StartName;Path=$service.PathName;Acl=$descriptor;Values=$values}
    })
    ConvertTo-Json -InputObject $policy -Depth 10 -Compress
}
function Assert-Preserved {
    if ((Get-Configuration) -cne $script:configuration -or
        (Get-ServicePolicy) -cne $script:servicePolicy -or
        (Get-Content -LiteralPath $sentinel -Raw) -cne $script:sentinelText) {
        throw 'Upgrade or rollback changed administrator settings, service policy, or generated logs.'
    }
}
function Assert-UpgradedFirewall {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *')
    if ($rules.Count -ne 5) { throw 'Upgrade did not replace the four-rule firewall policy with five rules.' }
    foreach ($name in @('BfdWinService - S-BFD requests inbound','BfdWinService - S-BFD replies outbound')) {
        $rule = @($rules | Where-Object DisplayName -CEQ $name)
        if ($rule.Count -ne 1) { throw "Missing upgraded reflector rule: $name" }
        $ports = $rule[0] | Get-NetFirewallPortFilter
        if (($ports.LocalPort -join ',') -cne '7784' -or ($ports.RemotePort -join ',') -cne '1-7783,7785-65535') {
            throw "Incorrect upgraded reflector ports: $name"
        }
    }
}

try {
    $installed = $true
    Invoke-Setup $previous '/install' 'upgrade-baseline-install.log'
    Assert-Version $PreviousVersion
    foreach ($value in @(@('Local','127.0.0.240'),@('Peer','127.0.0.241'),
        @('Auth','meticulous-sha1'),@('AuthKey','upgrade-fixture-key'),
        @('LogFilePath',(Join-Path $logDirectory 'upgrade-custom.log')))) {
        $null = New-ItemProperty -LiteralPath $parameters -Name $value[0] -PropertyType String -Value $value[1] -Force
    }
    foreach ($value in @(@('Multihop',1),@('LogToFile',1),@('AuthKeyId',23))) {
        $null = New-ItemProperty -LiteralPath $parameters -Name $value[0] -PropertyType DWord -Value $value[1] -Force
    }
    # Public fixture material only; never copy real deployment credentials here.
    Set-Content -LiteralPath $sentinel -Value 'BFD upgrade log preservation fixture' -Encoding UTF8
    $configuration = Get-Configuration
    $servicePolicy = Get-ServicePolicy
    $sentinelText = Get-Content -LiteralPath $sentinel -Raw
    $hashes = @('bfd-winservice.exe','bfd-bgp-broker.exe' | ForEach-Object {
        (Get-FileHash -LiteralPath (Join-Path $installDirectory $_) -Algorithm SHA256).Hash
    })

    # Fail after deferred service-policy mutation, inside the major-upgrade
    # transaction. This must restore the actual published product, not a stub.
    & (Join-Path $PSScriptRoot 'New-MsiRollbackFixture.ps1') -Path $msi -Destination $fixture
    $rollbackLog = Join-Path $outputDirectory 'upgrade-failed-rollback.log'
    $failed = Start-Process msiexec.exe -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        '/i',('"'+$fixture+'"'),'/qn','/norestart','/L*v',('"'+$rollbackLog+'"'))
    if ($failed.ExitCode -ne 1603 -or -not (Select-String -LiteralPath $rollbackLog -SimpleMatch 'ForceRollbackTest' -Quiet)) {
        throw 'The failed-upgrade fixture did not reach its deferred failure action.'
    }
    Assert-Version $PreviousVersion
    Assert-Preserved
    $restoredHashes = @('bfd-winservice.exe','bfd-bgp-broker.exe' | ForEach-Object {
        (Get-FileHash -LiteralPath (Join-Path $installDirectory $_) -Algorithm SHA256).Hash
    })
    if (@(Compare-Object $hashes $restoredHashes).Count -ne 0) { throw 'Rollback did not restore both published executable bytes.' }

    Invoke-Setup $setup '/install' 'upgrade-install.log'
    $cleanupSetup = $setup
    Assert-Version $ExpectedVersion
    Assert-UpgradedFirewall
    Assert-Preserved
    Invoke-Setup $setup '/repair' 'upgrade-repair.log'
    Assert-Version $ExpectedVersion
    Assert-UpgradedFirewall
    Assert-Preserved
    $since = Get-Date
    Start-Service BfdWinService
    $deadline = (Get-Date).AddSeconds(45)
    do {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName='BFD-Service/Operational';Id=300;StartTime=$since
        } -ErrorAction SilentlyContinue | Where-Object Message -Like '*BFD local RPC mutual service identity verified*')
        if ($events.Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    if ($events.Count -eq 0) { throw 'Upgraded services did not mutually authenticate through local RPC.' }
    Stop-Service BfdWinService
    Stop-Service BfdBgpBroker
    Assert-Preserved
    Invoke-Setup $setup '/uninstall' 'upgrade-uninstall.log'
    $installed = $false
    if (Get-Service BfdWinService,BfdBgpBroker -ErrorAction SilentlyContinue) { throw 'Upgrade uninstall left a service installed.' }
    if ((Get-Content -LiteralPath $sentinel -Raw) -cne $sentinelText) { throw 'Upgrade uninstall removed a generated log.' }
    [ordered]@{PreviousVersion=$PreviousVersion;Version=$ExpectedVersion;FailedUpgradeRestoredPublishedBytes=$true;
        ConfigurationPreserved=$true;ServicePolicyPreserved=$true;LogsPreserved=$true;Repair=$true;MutualRpcAuthentication=$true} |
        ConvertTo-Json | Set-Content (Join-Path $outputDirectory 'upgrade-validation.json') -Encoding UTF8
    Write-Output 'Published-version rollback, bundle upgrade, settings/log/policy preservation, repair, RPC authentication, and removal passed.'
} finally {
    if ($installed) { Invoke-Setup $cleanupSetup '/uninstall' 'upgrade-cleanup.log' }
}
