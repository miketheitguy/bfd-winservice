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
$match = [regex]::Match([string]$info.Comments, '\ANative MSVC toolset: (?<version>[0-9]+(?:\.[0-9]+){2,3}); CRT: (?<crt>[0-9]+(?:\.[0-9]+){3})\z')
if (-not $match.Success) { throw "Executable has no native MSVC toolset receipt: $resolved" }
$toolset = $match.Groups['version'].Value
$crt = $match.Groups['crt'].Value
Assert-NativeRuntime -Toolset $toolset -CrtVersion $crt -RuntimeVersion $RuntimeVersion
Write-Output ("Validated native MSVC {0} / CRT {1} against bundled x64 runtime {2}: {3}" -f $toolset, $crt, $RuntimeVersion, $resolved)
