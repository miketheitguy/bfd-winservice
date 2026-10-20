#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This rollback test runs only on a GitHub-hosted Actions runner.'
}
. (Join-Path $PSScriptRoot 'Assert-ServiceAccess.ps1')
. (Join-Path $PSScriptRoot 'Assert-RollbackPrivileges.ps1')
# This fixed-target helper runs only behind the disposable-runner guard above.
# An explicit empty MULTI_SZ must be passed through SCM, not a direct registry write.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class BfdRollbackPrivileges {
    [StructLayout(LayoutKind.Sequential)]
    private struct RequiredPrivileges { public IntPtr Names; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2W(IntPtr service, uint level, ref RequiredPrivileges info);
    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
    public static void Set(string[] names) {
        IntPtr manager = OpenSCManagerW(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr service = OpenServiceW(manager, "BfdWinService", 2);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                IntPtr text = Marshal.StringToHGlobalUni(String.Join("\0", names) + "\0");
                try {
                    RequiredPrivileges info = new RequiredPrivileges { Names = text };
                    if (!ChangeServiceConfig2W(service, 6, ref info))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                } finally { Marshal.FreeHGlobal(text); }
            } finally { CloseServiceHandle(service); }
        } finally { CloseServiceHandle(manager); }
    }
}
'@
$resolvedMsi = (Resolve-Path -LiteralPath $Path).Path
$outputDirectory = Split-Path $resolvedMsi -Parent
$installDirectory = Join-Path $env:ProgramFiles 'BfdWinService'
foreach ($name in @('BfdWinService','BfdBgpBroker')) {
    if (Get-Service $name -ErrorAction SilentlyContinue) { throw "Rollback runner already has $name." }
}
if (Test-Path -LiteralPath $installDirectory) { throw 'Rollback runner already has the installation folder.' }
# Earlier releases registered status COM roots; the package must never create them.
$comRoots = @(
    'HKLM:\SOFTWARE\Classes\CLSID\{E4A97D25-73E2-4E6C-9A35-281B6AE697C3}',
    'HKLM:\SOFTWARE\Classes\AppID\{954E4BD0-8B46-4A93-B43A-35A4A40ED8F7}',
    'HKLM:\SOFTWARE\Classes\BfdWinService.Status.1',
    'HKLM:\SOFTWARE\Classes\BfdWinService.Status',
    'HKLM:\SOFTWARE\Classes\AppID\bfd-winservice.exe'
)
foreach ($path in $comRoots) {
    if (Test-Path -LiteralPath $path) { throw "Rollback runner already has status COM registration: $path" }
}
$testMsi = Join-Path $env:RUNNER_TEMP ('BfdRollback-' + [Guid]::NewGuid().ToString('N') + '.msi')
& (Join-Path $PSScriptRoot 'New-MsiRollbackFixture.ps1') -Path $resolvedMsi -Destination $testMsi

try {
    foreach ($label in @('fresh','default','empty','explicit','restricted')) {
        $migration = $label -ne 'fresh'
        if ($migration) {
            # Emulate a stopped, pre-existing LocalSystem service with the fixture's
            # previous SID policy. The executable is never started by these tests.
            $fixtureExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
            New-Service -Name BfdWinService -BinaryPathName ('"' + $fixtureExe + '"') -StartupType Manual | Out-Null
            $oldSidType = if ($label -eq 'restricted') { 3 } else { 0 }
            $fixtureSidType = if ($label -eq 'restricted') { 'restricted' } else { 'none' }
            & sc.exe sidtype BfdWinService $fixtureSidType | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the migration SID fixture.' }
            if ($label -eq 'empty') { [BfdRollbackPrivileges]::Set([string[]]@()) }
            if ($label -eq 'explicit') {
                [BfdRollbackPrivileges]::Set([string[]]@('SeChangeNotifyPrivilege','SeImpersonatePrivilege'))
            }
            $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService'
            $oldPrivilegePresent = 'RequiredPrivileges' -in $key.GetValueNames()
            $oldPrivilegeKind = [Microsoft.Win32.RegistryValueKind]::Unknown
            $oldPrivileges = [string[]]@()
            if ($oldPrivilegePresent) {
                $oldPrivilegeKind = $key.GetValueKind('RequiredPrivileges')
                $oldPrivileges = [string[]]$key.GetValue('RequiredPrivileges')
            }
            Assert-RollbackPrivilegeFixture -Label $label -Present $oldPrivilegePresent -Kind $oldPrivilegeKind -Values $oldPrivileges
            $oldDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new([BfdServiceAccess]::ReadDescriptor('BfdWinService'), 0)
            $oldSecurity = $oldDescriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        }
        $log = Join-Path $outputDirectory "rollback-$label.log"
        $process = Start-Process -FilePath msiexec.exe -WindowStyle Hidden -Wait -PassThru `
            -ArgumentList @('/i', ('"' + $testMsi + '"'), '/qn', '/norestart', '/L*v', ('"' + $log + '"'))
        if ($process.ExitCode -ne 1603) { throw "Expected intentional MSI failure, got $($process.ExitCode); see $log" }
        $text = Get-Content -LiteralPath $log -Raw
        if ($text -notmatch 'ForceRollbackTest' -or $text -notmatch 'RollbackServicePolicy') {
            throw "The MSI did not reach account provisioning and rollback; see $log"
        }
        if (Get-Service BfdBgpBroker -ErrorAction SilentlyContinue) { throw 'Rollback left the newly installed broker.' }
        if (Test-Path -LiteralPath (Join-Path $installDirectory 'service-policy.rollback')) { throw 'Rollback left its service policy snapshot.' }
        if (Test-Path -LiteralPath (Join-Path $installDirectory 'bfd-bgp-broker.exe')) { throw 'Rollback left the broker executable.' }
        foreach ($path in $comRoots) {
            if (Test-Path -LiteralPath $path) { throw "Rollback created status COM registration: $path" }
        }
        if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object DisplayName -Like 'BfdWinService - *').Count -ne 0) {
            throw 'Rollback left a BFD firewall rule.'
        }
        $service = Get-CimInstance Win32_Service -Filter "Name='BfdWinService'"
        if ($migration) {
            if ($null -eq $service -or $service.StartName -ne 'LocalSystem' -or $service.State -ne 'Stopped') {
                throw 'Rollback did not restore the existing service account.'
            }
            $restoredDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new([BfdServiceAccess]::ReadDescriptor('BfdWinService'), 0)
            if ($restoredDescriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All) -cne $oldSecurity) {
                throw 'Rollback did not restore the previous service permissions.'
            }
            $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService'
            $restoredPrivilegePresent = 'RequiredPrivileges' -in $key.GetValueNames()
            if ($restoredPrivilegePresent -ne $oldPrivilegePresent) { throw "Rollback changed absent versus explicit privileges: $label" }
            if ($oldPrivilegePresent) {
                $restoredPrivileges = [string[]]$key.GetValue('RequiredPrivileges')
                if ($key.GetValueKind('RequiredPrivileges') -ne $oldPrivilegeKind -or
                    $restoredPrivileges.Count -ne $oldPrivileges.Count -or
                    ($restoredPrivileges -join [char]0) -cne ($oldPrivileges -join [char]0)) {
                    throw "Rollback changed the explicit privilege list: $label"
                }
            }
            if ($key.GetValue('ServiceSidType', 0) -ne $oldSidType) { throw 'Rollback did not restore the previous service SID setting.' }
            if ($key.GetValue('DelayedAutostart', 0) -ne 0) { throw 'Rollback did not restore the previous delayed-start setting.' }
            if ($key.GetValue('FailureActionsOnNonCrashFailures', 0) -ne 0) { throw 'Rollback did not restore the previous non-crash recovery setting.' }
            # GitHub's Windows 2025 runner uses the 10-second Windows default.
            if ($key.GetValue('PreshutdownTimeout', 10000) -ne 10000) { throw 'Rollback did not restore the previous preshutdown timeout.' }
            & sc.exe delete BfdWinService | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not remove the migration fixture.' }
        } elseif ($null -ne $service) { throw 'Rollback left the newly installed BFD service.' }
    }
    Write-Output 'Fresh-install, default/explicit-empty/explicit-list privileges, and restricted-SID rollback checks passed, including registry/firewall cleanup.'
}
finally {
    # Only fixed fixture services on the disposable runner are removed.
    foreach ($name in @('BfdWinService','BfdBgpBroker')) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            Stop-Service $name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $name | Out-Null
        }
    }
    Remove-Item -LiteralPath $testMsi -ErrorAction SilentlyContinue
}
