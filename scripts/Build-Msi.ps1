#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    # Accept the WiX 7 OSMF EULA for extension restore and package compilation.
    [switch]$AcceptWixEula = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$previousRollForward = $env:DOTNET_ROLL_FORWARD
Push-Location $repositoryRoot
try {
    # WiX 7 targets .NET 8; allow a later installed runtime.
    $env:DOTNET_ROLL_FORWARD = 'Major'
    $metadataText = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
    $metadata = $metadataText | ConvertFrom-Json
    $package = @($metadata.packages | Where-Object name -EQ 'bfd-winservice')[0]
    $version = $package.version
    if ($version -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
        throw 'MSI builds require a three-part numeric Cargo package version.'
    }
    $parts = $version.Split('.')
    if ([uint64]$parts[0] -gt 255 -or [uint64]$parts[1] -gt 255 -or [uint64]$parts[2] -gt 65535) {
        throw 'Cargo version exceeds MSI version limits (255.255.65535).'
    }
    if ($env:GITHUB_REF_TYPE -eq 'tag' -and $env:GITHUB_REF_NAME -ne "v$version") {
        throw "The release tag must match the Cargo version: v$version"
    }
    if (-not $SkipBuild) {
        & cargo build --locked --release
        if ($LASTEXITCODE -ne 0) { throw 'The release executable build failed.' }
    }
    $executable = Join-Path $repositoryRoot 'target\x86_64-pc-windows-msvc\release\bfd-winservice.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Release executable not found: $executable"
    }
    foreach ($name in @('bfd-winservice','bfd-bgp-broker')) {
        & (Join-Path $PSScriptRoot 'Test-ExecutableVersion.ps1') -Path (Join-Path (Split-Path $executable -Parent) "$name.exe") -ExpectedVersion $version -ExpectedName $name
    }
    & dotnet tool restore --tool-manifest .config/dotnet-tools.json
    if ($LASTEXITCODE -ne 0) { throw 'WiX tool restore failed.' }
    $toolManifest = Get-Content .config/dotnet-tools.json -Raw | ConvertFrom-Json
    $eulaArguments = @()
    if ($AcceptWixEula) {
        $eulaArguments = @('-acceptEula', 'wix7')
    }
    foreach ($extension in @('WixToolset.Util.wixext', 'WixToolset.Firewall.wixext')) {
        & dotnet tool run wix -- extension add "$extension/$($toolManifest.tools.wix.version)" @eulaArguments
        if ($LASTEXITCODE -ne 0) { throw "WiX extension restore failed: $extension" }
    }
    $outputDirectory = Join-Path $repositoryRoot 'target\installer'
    New-Item -ItemType Directory -Path $outputDirectory -Force
    $msi = Join-Path $outputDirectory "BfdWinService-$version-x64.msi"
    & dotnet tool run wix -- build installer/Package.wxs -arch x64 -pdbtype none `
        @eulaArguments `
        -d "RepositoryRoot=$repositoryRoot" -d "ProductVersion=$version" `
        -ext "WixToolset.Util.wixext/$($toolManifest.tools.wix.version)" `
        -ext "WixToolset.Firewall.wixext/$($toolManifest.tools.wix.version)" `
        -intermediatefolder (Join-Path $outputDirectory 'intermediate') -out $msi
    if ($LASTEXITCODE -ne 0) { throw 'WiX MSI build failed.' }
    & (Join-Path $PSScriptRoot 'Test-Msi.ps1') -Path $msi -ExpectedVersion $version
    $hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path $msi -Leaf)" | Set-Content -LiteralPath "$msi.sha256" -Encoding ascii
    Write-Output "MSI: $msi"
}
finally {
    $env:DOTNET_ROLL_FORWARD = $previousRollForward
    Pop-Location
}
