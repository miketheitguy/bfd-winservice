#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$vcvars = $env:BFD_VCVARS64_PATH
if (-not $vcvars) {
    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $locator = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $locator -PathType Leaf)) {
        throw 'Install the Visual Studio C++ Build Tools or set BFD_VCVARS64_PATH.'
    }
    $installation = & $locator -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath -utf8
    if ($LASTEXITCODE -ne 0 -or -not $installation) {
        throw 'No Visual Studio installation with the x64 C++ tools was found.'
    }
    $vcvars = Join-Path ([string]$installation).Trim() 'VC\Auxiliary\Build\vcvars64.bat'
}
$vcvars = (Resolve-Path -LiteralPath $vcvars).Path
if ($vcvars.Contains('"')) { throw 'The MSVC setup path must not contain a quote.' }

# Capture setup output internally; export only compiler/SDK values, never the
# complete environment, which can contain credentials in developer and CI hosts.
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
$start.Arguments = '/d /u /s /c ""{0}" >nul && set"' -f $vcvars
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.StandardOutputEncoding = [Text.Encoding]::Unicode
$process = [Diagnostics.Process]::Start($start)
try {
    $discardError = $process.StandardError.ReadToEndAsync()
    $setup = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    $null = $discardError.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw 'MSVC environment setup failed; repair the selected C++ Build Tools.' }
} finally {
    $process.Dispose()
}
foreach ($line in $setup -split '\r?\n') {
    $parts = $line.Split(@('='), 2)
    if ($parts.Count -eq 2 -and $parts[0] -in @(
        'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCToolsInstallDir',
        'VSINSTALLDIR', 'WindowsSdkDir', 'WindowsSDKVersion'
    )) {
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}
$env:BFD_VCVARS64_PATH = $vcvars
$compiler = (Get-Command cl.exe -CommandType Application -ErrorAction Stop).Source
$runtime = Join-Path (Split-Path $compiler) 'clang_rt.asan_dynamic-x86_64.dll'
if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) {
    throw 'The selected x64 MSVC toolset lacks its ASan runtime. Install the C++ AddressSanitizer component.'
}
Write-Host "ASan uses the runtime beside the selected compiler: $compiler"
