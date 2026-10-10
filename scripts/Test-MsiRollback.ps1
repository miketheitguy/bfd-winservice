#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This rollback test runs only on a GitHub-hosted Actions runner.'
}
$resolvedMsi = (Resolve-Path -LiteralPath $Path).Path
$outputDirectory = Split-Path $resolvedMsi -Parent
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
foreach ($name in @('BfdWinService','BfdBgpBroker')) {
    if (Get-Service $name -ErrorAction SilentlyContinue) { throw "Rollback runner already has $name." }
}
if (Test-Path -LiteralPath $installDirectory) { throw 'Rollback runner already has the installation folder.' }
$testMsi = Join-Path $env:RUNNER_TEMP ('BfdRollback-' + [Guid]::NewGuid().ToString('N') + '.msi')
& (Join-Path $PSScriptRoot 'New-MsiRollbackFixture.ps1') -Path $resolvedMsi -Destination $testMsi

try {
    foreach ($migration in @($false, $true)) {
        if ($migration) {
            # Emulate a stopped, pre-existing LocalSystem service without a service
            # SID. The executable is never started during either rollback test.
            $fixtureExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
            New-Service -Name BfdWinService -BinaryPathName ('"' + $fixtureExe + '"') -StartupType Manual | Out-Null
            & sc.exe sidtype BfdWinService none | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the migration SID fixture.' }
        }
        $label = if ($migration) { 'migration' } else { 'fresh' }
        $log = Join-Path $outputDirectory "rollback-$label.log"
        $process = Start-Process -FilePath msiexec.exe -WindowStyle Hidden -Wait -PassThru `
            -ArgumentList @('/i', ('"' + $testMsi + '"'), '/qn', '/norestart', '/L*v', ('"' + $log + '"'))
        if ($process.ExitCode -ne 1603) { throw "Expected intentional MSI failure, got $($process.ExitCode); see $log" }
        $text = Get-Content -LiteralPath $log -Raw
        if ($text -notmatch 'ForceRollbackTest' -or $text -notmatch 'RollbackServicePolicy') {
            throw "The MSI did not reach account provisioning and rollback; see $log"
        }
        if (Get-Service BfdBgpBroker -ErrorAction SilentlyContinue) { throw 'Rollback left the newly installed broker.' }
        if (Test-Path -LiteralPath (Join-Path $installDirectory 'service-policy.rollback')) { throw 'Rollback left its service policy snapshot.' }
        if (Test-Path -LiteralPath (Join-Path $installDirectory 'bfd-bgp-broker.exe')) { throw 'Rollback left the broker executable.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='BfdWinService'"
        if ($migration) {
            if ($null -eq $service -or $service.StartName -ne 'LocalSystem' -or $service.State -ne 'Stopped') {
                throw 'Rollback did not restore the existing service account.'
            }
            $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService'
            if ($key.GetValue('ServiceSidType', 0) -ne 0) { throw 'Rollback did not restore the previous service SID setting.' }
            if ($key.GetValue('DelayedAutostart', 0) -ne 0) { throw 'Rollback did not restore the previous delayed-start setting.' }
            if ($key.GetValue('FailureActionsOnNonCrashFailures', 0) -ne 0) { throw 'Rollback did not restore the previous non-crash recovery setting.' }
            # GitHub's Windows 2025 runner uses the 10-second Windows default.
            if ($key.GetValue('PreshutdownTimeout', 10000) -ne 10000) { throw 'Rollback did not restore the previous preshutdown timeout.' }
            & sc.exe delete BfdWinService | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not remove the migration fixture.' }
        } elseif ($null -ne $service) { throw 'Rollback left the newly installed BFD service.' }
    }
    Write-Output 'Fresh-install and existing-account migration rollback checks passed.'
}
finally {
    # Only fixed fixture services on the disposable runner are removed.
    foreach ($name in @('BfdWinService','BfdBgpBroker')) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            Stop-Service $name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $name | Out-Null
        }
    }
    Remove-Item -LiteralPath $testMsi -ErrorAction SilentlyContinue
}
