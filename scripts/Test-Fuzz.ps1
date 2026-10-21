#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('all','packet','session','reflector')][string]$Target = 'all',
    [ValidateRange(1,86400)][int]$Seconds = 10,
    [ValidateRange(1,2147483647)][int]$Runs = 10000,
    [string]$FuzzTool,
    [string]$InputFile,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$saved = @{}
foreach ($name in @('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_NET_OFFLINE',
    'RUSTUP_TOOLCHAIN','CXX_x86_64_pc_windows_msvc',
    'CXXFLAGS_x86_64_pc_windows_msvc','CL','_CL_')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $repositoryRoot
try {
    if ($saved.RUSTFLAGS -or $saved.CARGO_ENCODED_RUSTFLAGS) {
        throw 'Clear custom RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS before running this wrapper.'
    }
    & (Join-Path $PSScriptRoot 'Initialize-Asan.ps1')
    if (-not $FuzzTool) {
        $localTool = Join-Path $repositoryRoot 'target\fuzz-tools\bin\cargo-fuzz.exe'
        $FuzzTool = if (Test-Path -LiteralPath $localTool -PathType Leaf) { $localTool }
            else { (Get-Command cargo-fuzz.exe -CommandType Application -ErrorAction Stop).Source }
    }
    $FuzzTool = (Resolve-Path -LiteralPath $FuzzTool).Path
    $toolVersion = & $FuzzTool fuzz --version
    if ($LASTEXITCODE -ne 0 -or $toolVersion -cne 'cargo-fuzz 0.13.2') {
        throw 'This wrapper requires cargo-fuzz 0.13.2.'
    }
    $fetchArguments = @('fetch','--locked','--manifest-path','fuzz/Cargo.toml')
    if ($Offline) { $fetchArguments += '--offline' }
    & cargo @fetchArguments
    if ($LASTEXITCODE -ne 0) { throw 'Could not fetch the locked fuzz dependencies.' }
    $lockHash = (Get-FileHash -LiteralPath fuzz/Cargo.lock -Algorithm SHA256).Hash
    $env:CARGO_NET_OFFLINE = 'true'
    $output = Join-Path $repositoryRoot 'target\fuzz'
    $corpus = Join-Path $output 'corpus'
    $null = New-Item -ItemType Directory -Path $output -Force
    if ($InputFile) {
        if ($Target -eq 'all') { throw 'Select one target when replaying an input file.' }
        $InputFile = (Resolve-Path -LiteralPath $InputFile).Path
    } else {
        & cargo run --locked --offline --manifest-path fuzz/Cargo.toml --no-default-features `
            --target-dir $output --example seed_corpus -- $corpus
        if ($LASTEXITCODE -ne 0) { throw 'Corpus generation failed.' }
    }

    # cargo-fuzz sets RUSTFLAGS, which otherwise masks the configured target
    # hardening flags. Forward those flags without changing production config.
    $targetConfig = & cargo -Z unstable-options config get target.x86_64-pc-windows-msvc.rustflags --format=json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read the configured Windows hardening flags.' }
    $flags = ($targetConfig | ConvertFrom-Json).target.'x86_64-pc-windows-msvc'.rustflags
    if (-not $flags -or $flags.Count % 2 -ne 0 -or
        @($flags | Where-Object { $_ -match '\s' }).Count -ne 0) {
        throw 'Expected individual target flags without embedded whitespace.'
    }
    $fuzzFlags = @()
    for ($index = 0; $index -lt $flags.Count; $index += 2) {
        if ($flags[$index + 1] -notin @('ehcont-guard=yes','link-arg=/GUARD:EHCONT')) {
            $fuzzFlags += $flags[$index], $flags[$index + 1]
        }
    }
    $env:RUSTFLAGS = $fuzzFlags -join ' '
    $activeToolchain = ((& rustup show active-toolchain) -split '\s+')[0]
    if ($LASTEXITCODE -ne 0 -or -not $activeToolchain) {
        throw 'Cannot identify the repository-selected Rust toolchain.'
    }
    $env:RUSTUP_TOOLCHAIN = $activeToolchain
    $env:CL = $null
    $env:_CL_ = $null
    $env:CXX_x86_64_pc_windows_msvc = (Get-Command cl.exe -CommandType Application).Source
    # These flags apply only to libfuzzer-sys's C++ engine. Its pinned upstream
    # sources have MSVC narrowing/shadowing/unused-parameter warnings; retain
    # /W4 diagnostics without /WX rather than suppressing those categories.
    # /sdl promotes C4146 to an error for libFuzzer's intentional unsigned
    # negation, so disable only that upstream diagnostic after enabling /sdl.
    # Its portable fopen/putenv calls need the CRT compatibility definitions;
    # these affect this test-only C++ dependency, not maintained RPC C.
    # Maintained RPC C keeps its independent /W4 /WX policy in rpc/build.rs.
    $env:CXXFLAGS_x86_64_pc_windows_msvc = '/TP /EHsc /MD /GS /guard:cf /guard:ehcont /sdl /wd4146 /W4 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS'
    $targets = if ($Target -eq 'all') { @('packet','session','reflector') } else { @($Target) }
    foreach ($name in $targets) {
        $artifactDirectory = Join-Path $output "artifacts\$name"
        $null = New-Item -ItemType Directory -Path $artifactDirectory -Force
        $inputPath = if ($InputFile) { $InputFile } else { Join-Path $corpus $name }
        $runCount = if ($InputFile) { 1 } else { $Runs }
        $maxLength = if ($name -eq 'session') { 1 + 32 * 64 } else { 256 }
        $artifactPrefix = $artifactDirectory.Replace('\', '/') + '/'
        $engineArguments = @("-runs=$runCount", "-max_total_time=$Seconds", "-max_len=$maxLength",
            '-timeout=5', '-rss_limit_mb=2048', "-artifact_prefix=$artifactPrefix")
        # Run outside the checkout so Cargo does not inherit the repository's
        # global build-std setting. cargo-fuzz documents build-std as
        # incompatible with sanitizer-coverage instrumentation.
        Push-Location ([System.IO.Path]::GetTempPath())
        try {
            $logPath = Join-Path $output "$name.log"
            & $FuzzTool fuzz run $name $inputPath --fuzz-dir (Join-Path $repositoryRoot 'fuzz') `
                --dev --no-cfg-fuzzing --target-dir $output -- @engineArguments 2>&1 |
                Tee-Object -FilePath $logPath
            $fuzzExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($fuzzExitCode -ne 0) { throw "Fuzz target $name failed; preserve the crash artifact before retrying." }
        if (Select-String -LiteralPath $logPath -SimpleMatch `
                'WARNING: no interesting inputs were found so far. Is the code instrumented for coverage?' -Quiet) {
            throw "Fuzz target $name ran without coverage feedback."
        }
    }
    if ((Get-FileHash -LiteralPath fuzz/Cargo.lock -Algorithm SHA256).Hash -cne $lockHash) {
        throw 'The fuzz build unexpectedly changed its dependency lockfile.'
    }
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
