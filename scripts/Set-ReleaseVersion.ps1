#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Tag,
    [string]$RepositoryRoot = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tagMatch = [regex]::Match($Tag, '\Av(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)\z')
if (-not $tagMatch.Success) {
    throw 'Release tags must use vMAJOR.MINOR.PATCH without leading zeros, prerelease, or build metadata.'
}
foreach ($limit in @(
    @{ Name = 'major'; Maximum = 255 },
    @{ Name = 'minor'; Maximum = 255 },
    @{ Name = 'patch'; Maximum = 65535 }
)) {
    [uint64]$component = 0
    if (-not [uint64]::TryParse($tagMatch.Groups[$limit.Name].Value, [ref]$component) -or
        $component -gt $limit.Maximum) {
        throw 'Release tag exceeds MSI version limits (255.255.65535).'
    }
}
$version = $Tag.Substring(1)
$packageNamePattern = '(?m)^[ \t]*name[ \t]*=[ \t]*"bfd-winservice"[ \t]*(?:#[^\r\n]*)?\r?$'
$versionPattern = [regex]::new('(?m)^(?<before>[ \t]*version[ \t]*=[ \t]*")[^"\r\n]+(?<after>"[ \t]*(?:#[^\r\n]*)?\r?)$')
$updates = [Collections.Generic.List[object]]::new()
foreach ($file in @(
    @{ Name = 'Cargo.toml'; Header = '\[package\]' },
    @{ Name = 'Cargo.lock'; Header = '\[\[package\]\]' }
)) {
    $path = Join-Path $RepositoryRoot $file.Name
    $text = [IO.File]::ReadAllText($path)
    $sectionPattern = '(?ms)^' + $file.Header + '[ \t]*\r?\n.*?(?=^\[|\z)'
    $packages = @([regex]::Matches($text, $sectionPattern) |
        Where-Object { [regex]::IsMatch($_.Value, $packageNamePattern) })
    if ($packages.Count -ne 1 -or $versionPattern.Matches($packages[0].Value).Count -ne 1) {
        throw "Expected one bfd-winservice package with a quoted version in $($file.Name)."
    }
    $package = $packages[0]
    $replacement = $versionPattern.Replace($package.Value, {
        param($match)
        $match.Groups['before'].Value + $version + $match.Groups['after'].Value
    }, 1)
    $updates.Add(@{
        Path = $path
        Text = $text.Substring(0, $package.Index) + $replacement +
            $text.Substring($package.Index + $package.Length)
    })
}

# Validate both files before writing; preserve dependencies, comments, and line endings.
$encoding = [Text.UTF8Encoding]::new($false)
foreach ($update in $updates) {
    [IO.File]::WriteAllText($update.Path, $update.Text, $encoding)
}
Write-Output $version
