#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-DocumentationLinks.ps1')

$repository = Split-Path $PSScriptRoot -Parent
$files = @(git -C $repository -c core.quotepath=false ls-files -- '*.md')
if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) {
    throw 'Could not enumerate tracked Markdown files.'
}
Assert-DocumentationLinks -Root $repository -Files $files
