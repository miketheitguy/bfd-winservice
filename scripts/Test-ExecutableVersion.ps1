#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$ExpectedVersion,
    [ValidateSet('bfd-winservice','bfd-bgp-broker')][string]$ExpectedName = 'bfd-winservice'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$info = [Diagnostics.FileVersionInfo]::GetVersionInfo($resolvedPath)
if ($info.FileVersion -cne $ExpectedVersion -or $info.ProductVersion -cne $ExpectedVersion) {
    throw "Executable file and product versions must match ${ExpectedVersion}: $resolvedPath"
}
$fileVersion = '{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart
$productVersion = '{0}.{1}.{2}.{3}' -f $info.ProductMajorPart, $info.ProductMinorPart, $info.ProductBuildPart, $info.ProductPrivatePart
if ($fileVersion -cne "$ExpectedVersion.0" -or $productVersion -cne "$ExpectedVersion.0") {
    throw "Executable numeric versions must match $ExpectedVersion.0: $resolvedPath"
}
if ([IO.Path]::GetFileNameWithoutExtension($resolvedPath) -cne $ExpectedName) {
    throw "Executable name must match ${ExpectedName}: $resolvedPath"
}
Write-Output "Validated executable version ${ExpectedVersion}: $resolvedPath"
