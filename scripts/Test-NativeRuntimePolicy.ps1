#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-NativeRuntime.ps1')
foreach ($toolset in @('14.50.1', '14.51.36231', '14.51.36247', '14.51.36247.0')) {
    Assert-NativeRuntime -Toolset $toolset -RuntimeVersion '14.51.36247.0'
}
foreach ($pair in @(
    @('14.51.36247.1','14.51.36247.0'),
    @('14.51.36248','14.51.36247.0'),
    @('14.52.1','14.51.36247.0'),
    @('15.0.1','14.51.36247.0'),
    @('14.51','14.51.36247.0'),
    @('','14.51.36247.0'),
    @('14.51.36231','unknown')
)) {
    $rejected = $false
    try { Assert-NativeRuntime -Toolset $pair[0] -RuntimeVersion $pair[1] }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Unsafe native runtime pair was accepted: $($pair -join ' / ')" }
}
Write-Output 'Native runtime policy accepts compatible versions and rejects newer or missing toolset receipts.'
