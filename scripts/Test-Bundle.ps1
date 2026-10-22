#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [switch]$AcceptWixEula = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repositoryRoot = Split-Path $PSScriptRoot -Parent
& (Join-Path $PSScriptRoot 'Test-VcRedist.ps1') -RepositoryRoot $repositoryRoot
$metadata = Get-Content (Join-Path $repositoryRoot 'installer\redist\VC_redist.x64.json') -Raw | ConvertFrom-Json
$toolManifest = Get-Content (Join-Path $repositoryRoot '.config\dotnet-tools.json') -Raw | ConvertFrom-Json
$resolvedBundle = (Resolve-Path -LiteralPath $Path).Path
$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$validationRoot = Join-Path $repositoryRoot 'target\bundle-validation'
$directory = Join-Path $validationRoot ([guid]::NewGuid().ToString())
$previousRollForward = $env:DOTNET_ROLL_FORWARD
function Assert-Bundle {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Setup bundle validation failed: $Message" }
}
try {
    $env:DOTNET_ROLL_FORWARD = 'Major'
    $eulaArguments = @()
    if ($AcceptWixEula) { $eulaArguments = @('-acceptEula','wix7') }
    $payloadDirectory = Join-Path $directory 'payloads'
    $baDirectory = Join-Path $directory 'ba'
    Push-Location $repositoryRoot
    try {
        & dotnet tool run wix -- burn extract $resolvedBundle -o $payloadDirectory -oba $baDirectory @eulaArguments
        if ($LASTEXITCODE -ne 0) { throw 'Could not extract the setup bundle for validation.' }
    } finally { Pop-Location }
    $document = [xml](Get-Content (Join-Path $baDirectory 'manifest.xml') -Raw)
    $ns = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $ns.AddNamespace('b','http://wixtoolset.org/schemas/v4/2008/Burn')
    $manifest = $document.DocumentElement
    Assert-Bundle ($manifest.GetAttribute('EngineVersion') -ceq ($toolManifest.tools.wix.version + '.0')) 'Expected the pinned WiX engine.'
    Assert-Bundle ($manifest.GetAttribute('Win64') -ceq 'yes') 'Expected a native x64 bootstrapper.'
    $registration = $manifest.SelectSingleNode('b:Registration',$ns)
    Assert-Bundle ($registration.GetAttribute('Version') -ceq $ExpectedVersion -and
        $registration.GetAttribute('Scope') -ceq 'perMachine') 'Incorrect bundle version or scope.'
    $packages = @($manifest.SelectNodes('b:Chain/*',$ns))
    Assert-Bundle ($packages.Count -eq 2 -and $packages[0].LocalName -ceq 'ExePackage' -and
        $packages[0].GetAttribute('Id') -ceq 'VcRedistX64' -and
        $packages[1].LocalName -ceq 'MsiPackage' -and
        $packages[1].GetAttribute('Id') -ceq 'BfdServiceMsi') 'Microsoft runtime must precede the BFD MSI.'
    $runtime = $packages[0]
    $msi = $packages[1]
    foreach ($package in $packages) {
        Assert-Bundle ($package.GetAttribute('Vital') -ceq 'yes' -and
            $package.GetAttribute('Scope') -ceq 'perMachine') 'Both packages must be vital and per-machine.'
    }
    Assert-Bundle ($runtime.GetAttribute('Permanent') -ceq 'yes' -and
        $runtime.GetAttribute('InstallArguments') -ceq '/install /quiet /norestart' -and
        $runtime.GetAttribute('DetectCondition') -ceq "VcRuntimeInstalled = 1 AND VcRuntimeVersion >= v$($metadata.FileVersion)") 'Unsafe shared runtime installation or detection policy.'
    Assert-Bundle ($msi.GetAttribute('Version') -ceq $ExpectedVersion -and
        $msi.GetAttribute('Permanent') -ceq 'no') 'The BFD MSI must match the bundle version and support removal.'
    $exitCodes = @($runtime.SelectNodes('b:ExitCode',$ns))
    Assert-Bundle ($exitCodes.Count -eq 2 -and
        $exitCodes[0].GetAttribute('Code') -ceq '0' -and $exitCodes[0].GetAttribute('Type') -ceq '1' -and
        $exitCodes[1].GetAttribute('Code') -ceq '3010' -and $exitCodes[1].GetAttribute('Type') -ceq '3') 'Runtime failures must propagate; only success and reboot-required are accepted.'
    foreach ($entry in @(@('FindVcRuntimeInstalled','Installed'),@('FindVcRuntimeVersion','Version'))) {
        $search = $manifest.SelectSingleNode("b:RegistrySearch[@Id='$($entry[0])']",$ns)
        Assert-Bundle ($null -ne $search -and $search.GetAttribute('Root') -ceq 'HKLM' -and
            $search.GetAttribute('Win64') -ceq 'yes' -and $search.GetAttribute('Value') -ceq $entry[1] -and
            $search.GetAttribute('Key') -ceq 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64') 'Runtime detection must inspect the native x64 registration.'
    }
    $payloads = @($manifest.SelectNodes('b:Payload',$ns))
    Assert-Bundle ($payloads.Count -eq 2 -and @($payloads | Where-Object {
        $_.GetAttribute('Packaging') -cne 'embedded' -or $_.HasAttribute('DownloadUrl')
    }).Count -eq 0) 'Both packages must be embedded for offline installation.'
    $runtimeFile = Join-Path $payloadDirectory 'WixAttachedContainer\VC_redist.x64.exe'
    Assert-Bundle ((Get-FileHash $runtimeFile -Algorithm SHA256).Hash -ieq $metadata.Sha256) 'Embedded Microsoft installer was modified.'
    $msiFile = Join-Path $payloadDirectory ('WixAttachedContainer\' + (Split-Path $resolvedMsi -Leaf))
    Assert-Bundle ((Get-FileHash $msiFile -Algorithm SHA256).Hash -ceq
        (Get-FileHash $resolvedMsi -Algorithm SHA256).Hash) 'Embedded MSI differs from the validated private payload.'
    Write-Output "Validated offline setup ${ExpectedVersion}: original Microsoft installer, runtime detection, package order, failure handling, and shared runtime retention."
} finally {
    $env:DOTNET_ROLL_FORWARD = $previousRollForward
    $resolvedDirectory = [IO.Path]::GetFullPath($directory)
    $resolvedRoot = [IO.Path]::GetFullPath($validationRoot)
    if (-not $resolvedDirectory.StartsWith($resolvedRoot + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected bundle validation cleanup path.'
    }
    if (Test-Path -LiteralPath $resolvedDirectory) { Remove-Item -LiteralPath $resolvedDirectory -Recurse -Force }
}
