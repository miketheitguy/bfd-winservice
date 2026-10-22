#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$directory = Join-Path $RepositoryRoot 'installer\redist'
$metadata = Get-Content -LiteralPath (Join-Path $directory 'VC_redist.x64.json') -Raw | ConvertFrom-Json
if ($metadata.FileName -cne 'VC_redist.x64.exe' -or $metadata.Architecture -cne 'x64' -or
    $metadata.DownloadUrl -cne 'https://aka.ms/vc14/vc_redist.x64.exe') {
    throw 'Unexpected Visual C++ Redistributable provenance.'
}
$resolved = [uri]$metadata.ResolvedDownloadUrl
if ($resolved.Scheme -cne 'https' -or $resolved.Host -cne 'download.visualstudio.microsoft.com') {
    throw 'The pinned redistributable URL must use the Microsoft download host over HTTPS.'
}
$path = Join-Path $directory $metadata.FileName
$file = Get-Item -LiteralPath $path
if ($file.Length -ne $metadata.SizeBytes) { throw 'Visual C++ Redistributable size mismatch.' }
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -cne $metadata.Sha256) { throw 'Visual C++ Redistributable SHA-256 mismatch.' }
$checksum = (Get-Content -LiteralPath "$path.sha256" -Raw).Trim()
if ($checksum -cne "$hash  VC_redist.x64.exe") { throw 'Visual C++ Redistributable checksum file mismatch.' }
if ($file.VersionInfo.FileVersion -cne $metadata.FileVersion -or
    $file.VersionInfo.ProductVersion -cne $metadata.ProductVersion) {
    throw 'Visual C++ Redistributable version mismatch.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $path
if ($signature.Status -ne 'Valid' -or
    $signature.SignerCertificate.Subject -cne $metadata.SignerSubject -or
    $signature.SignerCertificate.Subject -notmatch '(^|, )O=Microsoft Corporation(,|$)' -or
    $signature.SignerCertificate.Thumbprint -cne $metadata.SignerThumbprint) {
    throw 'Visual C++ Redistributable Microsoft signature verification failed.'
}
Write-Output "Validated Microsoft Visual C++ Redistributable x64 $($metadata.FileVersion): $hash"
