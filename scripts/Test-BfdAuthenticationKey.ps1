#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Set-BfdAuthenticationKey.ps1')
$fixturePath = 'Software\bfd-key-provisioning-test-' + [guid]::NewGuid().ToString('N')
$parameters = $null
$secrets = $null
try {
    $parameters = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($fixturePath)
    $secrets = $parameters.CreateSubKey('Secrets')
    foreach ($case in @(@('ASCII-test-key',$false), @('00ff8041',$true))) {
        $parameters.SetValue('AuthKey', 'legacy-test-key')
        $parameters.SetValue('AuthKeyHex', 'abcd')
        $secure = ConvertTo-SecureString $case[0] -AsPlainText -Force
        try {
            Write-BfdProtectedKey -Secrets $secrets -Key $secure -MaximumBytes 20 -Hex:$case[1]
        } finally { $secure.Dispose() }
        if ($parameters.GetValue('AuthKey') -cne 'legacy-test-key' -or $parameters.GetValue('AuthKeyHex') -cne 'abcd') {
            throw 'Provisioning changed unrelated registry values.'
        }
        if ($secrets.GetValueKind('AuthKeyDpapi') -ne 'Binary') { throw 'DPAPI must be stored as REG_BINARY.' }
        $plain = [Security.Cryptography.ProtectedData]::Unprotect(
            [byte[]]$secrets.GetValue('AuthKeyDpapi'), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $expected = if ($case[1]) { [byte[]]@(0,255,128,65) } else { [Text.Encoding]::ASCII.GetBytes($case[0]) }
        try {
            if ([Convert]::ToBase64String($plain) -cne [Convert]::ToBase64String($expected)) {
                throw 'Provisioning changed the test key encoding.'
            }
        } finally {
            [Array]::Clear($plain, 0, $plain.Length)
            [Array]::Clear($expected, 0, $expected.Length)
        }
    }
    $before = [Convert]::ToBase64String([byte[]]$secrets.GetValue('AuthKeyDpapi'))
    foreach ($case in @(@('abc',$true,20), @('0g',$true,20), @([string][char]0x100,$false,20), @('12345678901234567',$false,16))) {
        $parameters.SetValue('AuthKey', 'legacy-test-key')
        $parameters.SetValue('AuthKeyHex', 'abcd')
        $secure = ConvertTo-SecureString $case[0] -AsPlainText -Force
        $rejected = $false
        try {
            Write-BfdProtectedKey -Secrets $secrets -Key $secure -MaximumBytes $case[2] -Hex:$case[1]
        } catch { $rejected = $true }
        finally { $secure.Dispose() }
        if (-not $rejected -or $parameters.GetValue('AuthKey') -cne 'legacy-test-key' -or
            $parameters.GetValue('AuthKeyHex') -cne 'abcd' -or
            [Convert]::ToBase64String([byte[]]$secrets.GetValue('AuthKeyDpapi')) -cne $before) {
            throw 'Failed provisioning changed the previous encrypted or unrelated values.'
        }
    }
    Write-Output 'DPAPI ASCII/binary provisioning, read-back verification, unrelated-value preservation, and failure preservation passed.'
} finally {
    if ($null -ne $secrets) { $secrets.Dispose() }
    if ($null -ne $parameters) { $parameters.Dispose() }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($fixturePath, $false)
}
