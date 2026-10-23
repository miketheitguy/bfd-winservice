#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$DisposableVm)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Service-TestRecovery.ps1')
$hostedRunner = $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted'
$authorizedVm = $DisposableVm -and $env:COMPUTERNAME -eq 'BFD-WS2025' -and
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters')
if (-not $hostedRunner -and -not $authorizedVm) {
    throw 'Privilege policy tests require a GitHub-hosted runner or the explicit disposable BFD-WS2025 VM.'
}
$names = @('BfdWinService', 'BfdBgpBroker')
foreach ($name in $names) {
    if ((Get-Service $name).Status -ne 'Stopped') { throw "Service must be stopped: $name" }
    $policy = @((Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $name)).RequiredPrivileges)
    if ($policy.Count -ne 1 -or $policy[0] -cne 'SeChangeNotifyPrivilege') {
        throw "Expected the installed minimum privilege policy before testing: $name"
    }
}
function Set-TestPolicy([string]$Name, [string]$Privileges) {
    & sc.exe privs $Name $Privileges | Write-Output
    if ($LASTEXITCODE -ne 0) { throw "Cannot set test privilege policy: $Name" }
}
try {
    foreach ($name in $names) {
        Invoke-WithoutNonCrashRecovery -Name $name -DisposableVm:$DisposableVm -Action {
            Set-TestPolicy $name 'SeChangeNotifyPrivilege/SeImpersonatePrivilege'
            $started = Get-Date
            $rejected = $false
            try { Start-Service $name -ErrorAction Stop } catch { $rejected = $true }
            if (-not $rejected -or (Get-Service $name).Status -ne 'Stopped') {
                throw "Service accepted an excessive SCM privilege policy: $name"
            }
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName='BFD-Service/Operational'; StartTime=$started
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -like '*service token must contain only enabled SeChangeNotifyPrivilege*'
            })
            if ($events.Count -eq 0) { throw "Missing token-validation rejection diagnostic: $name" }
            Set-TestPolicy $name 'SeChangeNotifyPrivilege'
        }
        Start-Service $name
        if ((Get-Service $name).Status -ne 'Running') { throw "Service did not recover with the minimum policy: $name" }
        Stop-Service $name
        Write-Output "Verified privilege rejection and recovery: $name"
    }
} finally {
    foreach ($name in $names) {
        Stop-Service $name -ErrorAction SilentlyContinue
        Set-TestPolicy $name 'SeChangeNotifyPrivilege'
    }
}
Write-Output 'Both services rejected excessive SCM privileges and recovered with the installed minimum.'
