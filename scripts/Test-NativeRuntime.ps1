#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$RuntimeVersion
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-NativeRuntime.ps1')
$resolved = (Resolve-Path -LiteralPath $Path).Path
$info = [Diagnostics.FileVersionInfo]::GetVersionInfo($resolved)
$match = [regex]::Match([string]$info.Comments, '\ANative MSVC toolset: (?<version>[0-9]+(?:\.[0-9]+){2,3})\z')
if (-not $match.Success) { throw "Executable has no native MSVC toolset receipt: $resolved" }
$toolset = $match.Groups['version'].Value
Assert-NativeRuntime -Toolset $toolset -RuntimeVersion $RuntimeVersion
Write-Output ("Validated native MSVC {0} against bundled x64 runtime {1}: {2}" -f $toolset, $RuntimeVersion, $resolved)
