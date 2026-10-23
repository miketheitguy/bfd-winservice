#Requires -Version 5.1
# Helpers for guarded disposable installation tests; dot-sourcing changes nothing.
function Assert-ServiceRecoveryTestHost {
    param([switch]$DisposableVm)
    $hostedRunner = $env:GITHUB_ACTIONS -eq 'true' -and
        $env:RUNNER_ENVIRONMENT -eq 'github-hosted'
    $authorizedVm = $DisposableVm -and $env:COMPUTERNAME -eq 'BFD-WS2025' -and
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters')
    if (-not $hostedRunner -and -not $authorizedVm) {
        throw 'Recovery isolation requires a hosted runner or the disposable BFD-WS2025 VM.'
    }
}

function Get-ServiceTestRecoveryFlag {
    param([Parameter(Mandatory)][string]$Name)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SYSTEM\CurrentControlSet\Services\$Name")
    if ($null -eq $key) { throw "Service registry key is missing: $Name" }
    try {
        $value = $key.GetValue('FailureActionsOnNonCrashFailures', 0)
        if ($value -isnot [int] -or $value -notin @(0, 1)) {
            throw "Invalid non-crash recovery flag: $Name"
        }
        return [int]$value
    } finally { $key.Dispose() }
}

function Set-ServiceTestRecoveryFlag {
    param([Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet(0, 1)][int]$Value)
    # Use SCM to change policy; registry access is only for readback.
    & sc.exe failureflag $Name $Value | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Get-ServiceTestRecoveryFlag $Name) -ne $Value) {
        throw "Could not set/read back non-crash recovery for $Name to $Value."
    }
}

function Invoke-WithoutNonCrashRecovery {
    param(
        [Parameter(Mandatory)][ValidateSet('BfdWinService', 'BfdBgpBroker')][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$DisposableVm
    )
    Assert-ServiceRecoveryTestHost -DisposableVm:$DisposableVm
    if ((Get-Service $Name).Status -ne 'Stopped') {
        throw "Expected startup-failure fixture requires a stopped service: $Name"
    }
    $original = Get-ServiceTestRecoveryFlag $Name
    try {
        # A reported nonzero startup exit otherwise queues an SCM restart that
        # survives a subsequent manual start/stop. Crash recovery is unchanged.
        if ($original -ne 0) { Set-ServiceTestRecoveryFlag $Name 0 }
        & $Action
    } finally {
        if ((Get-ServiceTestRecoveryFlag $Name) -ne $original) {
            Set-ServiceTestRecoveryFlag $Name $original
        }
        if ((Get-ServiceTestRecoveryFlag $Name) -ne $original) {
            throw "Non-crash recovery was not restored: $Name"
        }
    }
}

function Write-ServiceTestDiagnostics {
    param([Parameter(Mandatory)][datetime]$Since,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$Failure)
    # Collect before uninstall erases services/provider registration. Never dump
    # registry settings, authentication material, command lines, or environments.
    try {
        $names = @('BfdWinService', 'BfdBgpBroker')
        $services = @(Get-CimInstance Win32_Service `
            -Filter "Name='BfdWinService' OR Name='BfdBgpBroker'" |
            Select-Object Name, DisplayName, State, ProcessId, ExitCode,
                ServiceSpecificExitCode, CheckPoint, WaitHint, StartMode)
        $displayNames = @($services | ForEach-Object DisplayName) + $names
        $scm = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $Since
        } -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {
            $_.Properties.Count -gt 0 -and $_.Properties[0].Value -in $displayNames
        } | Select-Object @{Name='Utc'; Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, Id, Message)
        $bfd = @(Get-WinEvent -FilterHashtable @{
            LogName = 'BFD-Service/Operational'; Id = @(1, 2, 3, 300, 301); StartTime = $Since
        } -MaxEvents 100 -ErrorAction SilentlyContinue |
            Select-Object @{Name='Utc'; Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, Id, ProcessId, Message)
        $diagnosticsPath = Join-Path $OutputDirectory 'service-test-diagnostics.json'
        [ordered]@{
            CapturedUtc = [datetime]::UtcNow.ToString('o')
            Failure = [ordered]@{
                Id = $Failure.FullyQualifiedErrorId
                Message = $Failure.Exception.Message
                ExceptionType = $Failure.Exception.GetType().FullName
                HResult = $Failure.Exception.HResult
            }
            Services = $services; ScmEvents = $scm; BfdEvents = $bfd
        } | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $diagnosticsPath -Encoding UTF8
    } catch {
        Write-Warning "Could not collect service test diagnostics: $($_.Exception.Message)"
    }
}
