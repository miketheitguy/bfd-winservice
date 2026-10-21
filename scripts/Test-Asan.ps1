#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments)][string[]]$CargoArguments = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repositoryRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repositoryRoot
try {
    & (Join-Path $PSScriptRoot 'Initialize-Asan.ps1')
    $logDirectory = Join-Path $repositoryRoot 'target\asan'
    $null = New-Item -ItemType Directory -Path $logDirectory -Force
    $metadataPath = Join-Path $logDirectory 'build.jsonl'
    & cargo asan --no-run --message-format=json @CargoArguments > $metadataPath
    if ($LASTEXITCODE -ne 0) { throw 'ASan compilation failed.' }

    # Use Cargo's active build records so stale objects from an older local
    # build cannot provide false evidence of native instrumentation.
    $records = Get-Content -LiteralPath $metadataPath | ForEach-Object { $_ | ConvertFrom-Json }
    $nativeBuilds = @($records | Where-Object {
        $_.reason -eq 'build-script-executed' -and
        @($_.env | Where-Object { $_[0] -ceq 'BFD_NATIVE_ASAN' }).Count -gt 0
    })
    if ($nativeBuilds.Count -eq 0) { throw 'Cargo supplied no native sanitizer build record.' }
    $dumpbin = (Get-Command dumpbin.exe -CommandType Application -ErrorAction Stop).Source
    $nativeLog = Join-Path $logDirectory 'native-instrumentation.log'
    Set-Content -LiteralPath $nativeLog -Value 'Native ASan instrumentation' -Encoding utf8
    foreach ($build in $nativeBuilds) {
        $setting = @($build.env | Where-Object { $_[0] -ceq 'BFD_NATIVE_ASAN' })
        if ($setting.Count -ne 1 -or $setting[0][1] -cne '1') {
            throw 'The ASan build did not enable native RPC instrumentation.'
        }
        $symbols = & $dumpbin /nologo /symbols (Join-Path $build.out_dir 'client.obj')
        if ($LASTEXITCODE -ne 0 -or -not ($symbols -match '__asan_')) {
            throw 'The native RPC client object has no emitted ASan instrumentation.'
        }
        $symbols | Add-Content -LiteralPath $nativeLog -Encoding utf8
    }
    Write-Host 'Verified emitted ASan hooks in the native RPC client.'
    & cargo asan @CargoArguments 2>&1 | Tee-Object -FilePath (Join-Path $logDirectory 'tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'ASan tests failed.' }
} finally {
    Pop-Location
}
