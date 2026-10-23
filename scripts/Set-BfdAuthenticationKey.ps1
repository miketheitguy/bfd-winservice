#Requires -Version 5.1
<#
.SYNOPSIS
Stores and verifies a machine-scope DPAPI BFD key.
.DESCRIPTION
Run as Administrator on the BFD server after installing or repairing the bundle.
Stop BfdWinService and configure Auth first. The default prompt accepts ASCII;
use -Hex for binary keys. Key accepts a SecureString for automation. No salt or
optional entropy is used. Read-back decryption must match the supplied key.
The script does not start or stop services.
#>
[CmdletBinding()]
param([Security.SecureString]$Key, [switch]$Hex)

function ConvertFrom-BfdSecureKey {
    param([Parameter(Mandatory)][Security.SecureString]$Key, [switch]$Hex)
    $count = $Key.Length
    $limit = if ($Hex) { 40 } else { 20 }
    if ($count -eq 0 -or $count -gt $limit -or ($Hex -and $count % 2 -ne 0)) {
        throw 'Enter 1-20 ASCII bytes or 1-20 bytes as hexadecimal pairs.'
    }
    $length = if ($Hex) { $count / 2 } else { $count }
    $bytes = [byte[]]::new($length)
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
        for ($i = 0; $i -lt $count; $i++) {
            $code = [int][Runtime.InteropServices.Marshal]::ReadInt16($bstr, $i * 2)
            if ($Hex) {
                $nibble = if ($code -ge 48 -and $code -le 57) { $code - 48 }
                    elseif ($code -ge 65 -and $code -le 70) { $code - 55 }
                    elseif ($code -ge 97 -and $code -le 102) { $code - 87 }
                    else { throw 'The key must contain hexadecimal pairs without separators.' }
                $index = [int][Math]::Floor($i / 2)
                $bytes[$index] = ($bytes[$index] -shl 4) -bor $nibble
            } else {
                if ($code -lt 0 -or $code -gt 127) { throw 'The key must be ASCII; use -Hex for binary keys.' }
                $bytes[$i] = $code
            }
        }
        return ,$bytes
    } catch {
        [Array]::Clear($bytes, 0, $bytes.Length)
        throw
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
}

function Assert-BfdKeyAcl {
    param([Parameter(Mandatory)][Microsoft.Win32.RegistryKey]$Registry)
    $acl = [Security.AccessControl.RawSecurityDescriptor]::new($Registry.GetAccessControl().Sddl)
    $grants = @{
        'S-1-5-18' = 0xf003f
        'S-1-5-32-544' = 0xf003f
        'S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512' = 0x20019
    }
    if ($null -eq $acl.Owner -or $acl.Owner.Value -ne 'S-1-5-18' -or
        ($acl.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or
        $null -eq $acl.DiscretionaryAcl -or $acl.DiscretionaryAcl.Count -ne 3) {
        throw 'Registry key protection differs from BFD policy; repair the setup bundle first.'
    }
    foreach ($ace in $acl.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.AceType -ne 'AccessAllowed' -or
            $ace.AceFlags -ne [Security.AccessControl.AceFlags]::ContainerInherit -or
            -not $grants.ContainsKey($ace.SecurityIdentifier.Value) -or
            $ace.AccessMask -ne $grants[$ace.SecurityIdentifier.Value]) {
            throw 'Registry key protection differs from BFD policy; repair the setup bundle first.'
        }
        $grants.Remove($ace.SecurityIdentifier.Value)
    }
}

function Write-BfdProtectedKey {
    # Separate from the fixed-HKLM entry point so native tests can use unique HKCU
    # fixtures without installing, stopping, or reconfiguring a service.
    param(
        [Parameter(Mandatory)][Microsoft.Win32.RegistryKey]$Secrets,
        [Parameter(Mandatory)][Security.SecureString]$Key,
        [Parameter(Mandatory)][ValidateSet(16,20)][int]$MaximumBytes,
        [switch]$Hex
    )
    Add-Type -AssemblyName System.Security
    $plain = $null
    $verified = $null
    $old = $null
    $hadOld = 'AuthKeyDpapi' -in $Secrets.GetValueNames()
    if ($hadOld) {
        if ($Secrets.GetValueKind('AuthKeyDpapi') -ne [Microsoft.Win32.RegistryValueKind]::Binary) {
            throw 'Secrets\AuthKeyDpapi must be REG_BINARY.'
        }
        $old = [byte[]]$Secrets.GetValue('AuthKeyDpapi')
    }
    try {
        $plain = ConvertFrom-BfdSecureKey -Key $Key -Hex:$Hex
        if ($plain.Length -gt $MaximumBytes) { throw 'The key exceeds the configured authentication mode limit.' }
        $cipher = [Security.Cryptography.ProtectedData]::Protect(
            $plain, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        try {
            $Secrets.SetValue('AuthKeyDpapi', $cipher, [Microsoft.Win32.RegistryValueKind]::Binary)
            $stored = [byte[]]$Secrets.GetValue('AuthKeyDpapi')
            $verified = [Security.Cryptography.ProtectedData]::Unprotect(
                $stored, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $difference = $plain.Length -bxor $verified.Length
            for ($i = 0; $i -lt [Math]::Min($plain.Length, $verified.Length); $i++) {
                $difference = $difference -bor ($plain[$i] -bxor $verified[$i])
            }
            if ($difference -ne 0) { throw 'The stored DPAPI key did not pass read-back verification.' }
        } catch {
            # Restore the previous encrypted value after a failed replacement.
            if ($hadOld) { $Secrets.SetValue('AuthKeyDpapi', $old, [Microsoft.Win32.RegistryValueKind]::Binary) }
            else { $Secrets.DeleteValue('AuthKeyDpapi', $false) }
            throw
        }
    } finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($null -ne $verified) { [Array]::Clear($verified, 0, $verified.Length) }
    }
}

function Invoke-BfdKeyProvisioning {
    param([Security.SecureString]$Key, [switch]$Hex)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script in PowerShell as Administrator on the BFD server.'
    }
    if ((Get-Service -Name BfdWinService).Status -ne 'Stopped') {
        throw 'Stop BfdWinService before changing its authentication key.'
    }
    $parameters = $null
    $secrets = $null
    $prompted = $false
    try {
        $parameters = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters')
        if ($null -eq $parameters) { throw 'Install or repair the setup bundle before provisioning a key.' }
        Assert-BfdKeyAcl -Registry $parameters
        $secrets = $parameters.OpenSubKey('Secrets', $true)
        if ($null -eq $secrets) { throw 'Install or repair the setup bundle to create the protected Secrets key.' }
        Assert-BfdKeyAcl -Registry $secrets
        if ($parameters.GetValueKind('Auth') -ne [Microsoft.Win32.RegistryValueKind]::String) {
            throw 'Configure Auth as REG_SZ before provisioning a key.'
        }
        $maximum = switch ($parameters.GetValue('Auth')) {
            'simple-password' { 16 }
            'meticulous-md5' { 16 }
            'keyed-sha1' { 20 }
            'meticulous-sha1' { 20 }
            default { throw 'Configure a supported authenticated Auth mode before provisioning a key.' }
        }
        if ($null -eq $Key) {
            $Key = Read-Host -Prompt 'BFD authentication key (not echoed)' -AsSecureString
            $prompted = $true
        }
        Write-BfdProtectedKey -Secrets $secrets -Key $Key -MaximumBytes $maximum -Hex:$Hex
        Write-Output 'Verified Secrets\AuthKeyDpapi (REG_BINARY). Restart BfdWinService to apply.'
    } finally {
        if ($prompted) { $Key.Dispose() }
        if ($null -ne $secrets) { $secrets.Dispose() }
        if ($null -ne $parameters) { $parameters.Dispose() }
    }
}

# Dot-sourcing exposes fixture-testable helpers without executing provisioning.
if ($MyInvocation.InvocationName -ne '.') { Invoke-BfdKeyProvisioning -Key $Key -Hex:$Hex }
