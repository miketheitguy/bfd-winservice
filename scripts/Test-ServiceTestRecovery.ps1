#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Service-TestRecovery.ps1')

# These state-model fixtures never open or change a real service. The guarded
# MSI tests exercise the same helper with real SCM policy and rejected starts.
function Assert-ServiceRecoveryTestHost { param([switch]$DisposableVm) }
function Get-Service { param([string]$Name) [pscustomobject]@{Status=$script:state} }
function Get-ServiceTestRecoveryFlag { param([string]$Name) $script:flag }
function Set-ServiceTestRecoveryFlag {
    param([string]$Name, [int]$Value)
    $script:writes.Add($Value)
    $script:flag = $Value
    if ($script:failDisable -and $Value -eq 0) { throw 'fixture-disable-failure' }
}
function Reset-Fixture([int]$Flag) {
    $script:flag = $Flag
    $script:state = 'Stopped'
    $script:writes = [Collections.Generic.List[int]]::new()
    $script:failDisable = $false
}
function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Recovery isolation fixture failed: $Message" }
}

Reset-Fixture 1
$result = Invoke-WithoutNonCrashRecovery BfdWinService -Action {
    Assert-Fixture ($script:flag -eq 0) 'Expected-startup action ran with recovery enabled.'
    42
}
Assert-Fixture ($result -eq 42 -and $script:flag -eq 1 -and
    ($script:writes -join ',') -ceq '0,1') 'Success did not restore enabled recovery.'

Reset-Fixture 1
$caught = $false
try {
    Invoke-WithoutNonCrashRecovery BfdWinService -Action { throw 'fixture-action-failure' }
} catch { $caught = $_.Exception.Message -ceq 'fixture-action-failure' }
Assert-Fixture ($caught -and $script:flag -eq 1) 'Action failure lost its error or recovery policy.'

Reset-Fixture 0
Invoke-WithoutNonCrashRecovery BfdBgpBroker -Action {
    Assert-Fixture ($script:flag -eq 0) 'Disabled recovery changed inside the action.'
}
Assert-Fixture ($script:flag -eq 0 -and $script:writes.Count -eq 0) 'Disabled policy was enabled.'

Reset-Fixture 1
$script:failDisable = $true
$caught = $false
$script:actionRan = $false
try {
    Invoke-WithoutNonCrashRecovery BfdWinService -Action { $script:actionRan = $true }
} catch { $caught = $_.Exception.Message -ceq 'fixture-disable-failure' }
Assert-Fixture ($caught -and -not $script:actionRan -and $script:flag -eq 1) `
    'A partial suppression failure ran the action or left recovery disabled.'

Reset-Fixture 1
$script:state = 'Running'
$caught = $false
try { Invoke-WithoutNonCrashRecovery BfdWinService -Action { throw 'unexpected-action' } }
catch { $caught = $_.Exception.Message -like '*requires a stopped service*' }
Assert-Fixture ($caught -and $script:writes.Count -eq 0) 'A running service was modified.'

Reset-Fixture 1
Invoke-WithoutNonCrashRecovery BfdWinService -Action {
    Invoke-WithoutNonCrashRecovery BfdWinService -Action {
        Assert-Fixture ($script:flag -eq 0) 'Nested action enabled recovery.'
    }
    Assert-Fixture ($script:flag -eq 0) 'Nested return enabled recovery too early.'
}
Assert-Fixture ($script:flag -eq 1 -and ($script:writes -join ',') -ceq '0,1') `
    'Nested isolation did not restore the outer policy.'

Reset-Fixture 1
$caught = $false
try { Invoke-WithoutNonCrashRecovery UnrelatedService -Action { throw 'unexpected-action' } }
catch { $caught = $_.FullyQualifiedErrorId -like 'ParameterArgumentValidationError*' }
Assert-Fixture ($caught -and $script:writes.Count -eq 0) 'An unrelated service was accepted.'
Write-Output 'Validated seven recovery isolation fixtures: success, failure, disabled policy, partial suppression, running service, nesting, and service allowlist.'
