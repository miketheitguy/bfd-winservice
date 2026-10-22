#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ExpectedVersion,
    [switch]$DisposableVm
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Never mutate a developer workstation to test an installer. The VM alternative
# is limited to the explicitly provisioned disposable BFD test machine.
$hostedRunner = $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted'
$authorizedVm = $DisposableVm -and $env:COMPUTERNAME -eq 'BFD-WS2025' -and
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters')
if (-not $hostedRunner -and -not $authorizedVm) {
    throw 'Bundle installation tests require a GitHub-hosted runner or the explicit disposable BFD-WS2025 VM.'
}
if (Get-Service BfdWinService,BfdBgpBroker -ErrorAction SilentlyContinue) {
    throw 'Bundle tests require a machine without an existing BFD installation.'
}
$resolved = (Resolve-Path -LiteralPath $Path).Path
$directory = Split-Path $resolved -Parent
$runtimeMetadata = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'installer\redist\VC_redist.x64.json') -Raw | ConvertFrom-Json
$minimumRuntime = [version]$runtimeMetadata.FileVersion
$runtimeKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
$installed = $false

function Invoke-Setup {
    param([string]$Operation, [string]$LogName)
    $log = Join-Path $directory $LogName
    $result = Start-Process -FilePath $resolved -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList @($Operation,'/quiet','/norestart','/log',('"'+$log+'"'))
    if ($result.ExitCode -notin @(0,3010)) { throw "Setup $Operation failed with $($result.ExitCode); see $log" }
    return $log
}
function Assert-Runtime {
    $runtime = Get-ItemProperty -LiteralPath $runtimeKey
    if ($runtime.Installed -ne 1 -or [version]$runtime.Version.TrimStart('v','V') -lt $minimumRuntime) {
        throw 'The native x64 Visual C++ runtime is missing or older than the bundled prerequisite.'
    }
    return $runtime.Version
}
function Assert-Bfd {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='BfdWinService' OR Name='BfdBgpBroker'")
    if ($services.Count -ne 2 -or @($services | Where-Object State -ne 'Stopped').Count -ne 0) {
        throw 'Both services must be installed and remain stopped for configuration.'
    }
    foreach ($name in @('bfd-winservice','bfd-bgp-broker')) {
        $file = Get-Item -LiteralPath (Join-Path $env:ProgramFiles "BfdWinService\$name.exe")
        if ($file.VersionInfo.ProductVersion -cne $ExpectedVersion) { throw 'Unexpected installed BFD version.' }
    }
    $bfd = $services | Where-Object Name -eq 'BfdWinService'
    $broker = $services | Where-Object Name -eq 'BfdBgpBroker'
    if ($bfd.StartName -ne 'NT AUTHORITY\LocalService' -or $broker.StartName -ne 'LocalSystem') {
        throw 'Bundle installation changed the service accounts.'
    }
}
try {
    $initialRuntime = if (Test-Path -LiteralPath $runtimeKey) { (Get-ItemProperty $runtimeKey).Version } else { $null }
    $installed = $true
    $installLog = Invoke-Setup '/install' 'bundle-install.log'
    Assert-Bfd
    $runtime = Assert-Runtime
    foreach ($operation in @(@('/install','bundle-repeat.log'),@('/repair','bundle-repair.log'))) {
        $log = Invoke-Setup $operation[0] $operation[1]
        Assert-Bfd
        if ((Assert-Runtime) -cne $runtime) { throw 'Maintenance changed the shared runtime version.' }
        if (-not (Select-String -LiteralPath $log -Pattern 'Planned package: VcRedistX64,.*execute: None' -Quiet)) {
            throw 'An equal or newer runtime must be detected and skipped during maintenance.'
        }
    }
    $null = Invoke-Setup '/uninstall' 'bundle-uninstall.log'
    $installed = $false
    if (Get-Service BfdWinService,BfdBgpBroker -ErrorAction SilentlyContinue) { throw 'Bundle uninstall left BFD services installed.' }
    if ((Assert-Runtime) -cne $runtime) { throw 'Bundle uninstall removed or changed the shared runtime.' }
    [ordered]@{Version=$ExpectedVersion;InitialRuntime=$initialRuntime;InstalledRuntime=$runtime;RepeatInstall=$true;Repair=$true;RuntimeRetainedAfterUninstall=$true} |
        ConvertTo-Json | Set-Content (Join-Path $directory 'bundle-install-validation.json') -Encoding UTF8
    Write-Output 'Bundle installation, runtime detection, repeated install, repair, service accounts, and shared runtime retention passed.'
} finally {
    if ($installed) { $null = Invoke-Setup '/uninstall' 'bundle-cleanup.log' }
}
