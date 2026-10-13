#Requires -Version 5.1
# Shared by source, MSI, and disposable-runner registration checks.
function Assert-StatusComPermission {
    param(
        [Parameter(Mandatory)][Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][int]$AccessMask
    )

    $protected = [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if (($Descriptor.ControlFlags -band $protected) -eq 0 -or
        $null -eq $Descriptor.Owner -or $Descriptor.Owner.Value -ne 'S-1-5-18' -or
        $null -eq $Descriptor.DiscretionaryAcl -or $Descriptor.DiscretionaryAcl.Count -ne 2) {
        throw "Expected SYSTEM ownership and protected SYSTEM/Administrators COM permissions: $ObjectName"
    }
    $trustees = @{'S-1-5-18' = $true; 'S-1-5-32-544' = $true}
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceType -ne 'AccessAllowed' -or $ace.AceFlags -ne 'None' -or
            -not $trustees.ContainsKey($ace.SecurityIdentifier.Value) -or
            $ace.AccessMask -ne $AccessMask) {
            throw "Unexpected trustee, remote rights, or mask in COM permissions: $ObjectName"
        }
        $trustees.Remove($ace.SecurityIdentifier.Value)
    }
    if ($trustees.Count -ne 0) { throw "Missing COM access grant: $ObjectName" }
}

function ConvertFrom-StatusPermissionHex {
    param([Parameter(Mandatory)][string]$Value)
    $hex = $Value -replace '^#x', ''
    if ($hex -notmatch '^(?:[0-9a-fA-F]{2})+$') { throw 'Expected a binary COM security descriptor.' }
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($hex.Substring(2 * $index, 2), 16)
    }
    [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
}

function Get-StatusComRegistryValues {
    $clsid = '{E4A97D25-73E2-4E6C-9A35-281B6AE697C3}'
    $appid = '{954E4BD0-8B46-4A93-B43A-35A4A40ED8F7}'
    $class = "SOFTWARE\Classes\CLSID\$clsid"
    $app = "SOFTWARE\Classes\AppID\$appid"
    $progid = 'SOFTWARE\Classes\BfdWinService.Status.1'
    $independent = 'SOFTWARE\Classes\BfdWinService.Status'
    @(
        @('StatusClassName', $class, '', 'BFD Windows Service status', 'string'),
        @('StatusClassAppId', $class, 'AppID', $appid, 'string'),
        @('StatusClassProgId', "$class\ProgID", '', 'BfdWinService.Status.1', 'string'),
        @('StatusClassVersionIndependentProgId', "$class\VersionIndependentProgID", '', 'BfdWinService.Status', 'string'),
        @('StatusProgIdName', $progid, '', 'BFD Windows Service status', 'string'),
        @('StatusProgIdClsid', "$progid\CLSID", '', $clsid, 'string'),
        @('StatusVersionIndependentProgIdName', $independent, '', 'BFD Windows Service status', 'string'),
        @('StatusVersionIndependentProgIdClsid', "$independent\CLSID", '', $clsid, 'string'),
        @('StatusVersionIndependentProgIdCurVer', "$independent\CurVer", '', 'BfdWinService.Status.1', 'string'),
        @('StatusAppName', $app, '', 'BFD Windows Service status', 'string'),
        @('StatusAppService', $app, 'LocalService', 'BfdWinService', 'string'),
        @('StatusAppAuthenticationLevel', $app, 'AuthenticationLevel', '5', 'integer'),
        @('StatusAppAccessPermission', $app, 'AccessPermission', '3', 'binary'),
        @('StatusAppLaunchPermission', $app, 'LaunchPermission', '11', 'binary'),
        @('StatusExeAppId', 'SOFTWARE\Classes\AppID\bfd-winservice.exe', 'AppID', $appid, 'string')
    ) | ForEach-Object {
        [pscustomobject]@{Id=$_[0]; Key=$_[1]; Name=$_[2]; Value=$_[3]; Type=$_[4]}
    }
}
