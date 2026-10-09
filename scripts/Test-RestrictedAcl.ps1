#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-RestrictedAcl.ps1')

# These fixtures inspect descriptors only; no file or registry ACL is changed.
$file = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)'
$folder = 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)'
$registry = 'O:SYG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)'
$cases = @(
    @{Sddl=$file; Full=0x1f01ff; Read=0x1200a9; Flags='None'},
    @{Sddl=$folder; Full=0x1f01ff; Read=0x1200a9; Flags='ObjectInherit, ContainerInherit'},
    @{Sddl=$registry; Full=0xf003f; Read=0x20019; Flags='ContainerInherit'}
)
foreach ($case in $cases) {
    Assert-RestrictedAcl -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($case.Sddl)) -ObjectName 'valid fixture' -FullAccess $case.Full -ReadAccess $case.Read -InheritanceFlags $case.Flags
}
$unsafeDescriptors = @(
    $file.Replace('D:P', 'D:'),                         # Inherited grants could permit writes.
    $file.Replace('O:SY', 'O:BU'),                      # Users could change the DACL as owner.
    $file.Replace('(A;;FRFX;;;BU)', '(A;;FA;;;BU)'),     # Users could replace installed code.
    $file.Replace('(A;;FRFX;;;BU)', '(A;;FRFX;;;WD)'),   # Unexpected principal.
    $file.Replace('(A;;FA;;;BA)', '(A;;FA;;;SY)'),       # Duplicate trustee hides a missing grant.
    $file.Replace('(A;;FA;;;BA)', ''),                  # Administrator access is missing.
    $file.Replace('(A;;FRFX;;;BU)', '(D;;FRFX;;;BU)'),   # A deny ACE does not satisfy the read grant.
    $file.Replace('(A;;FRFX;;;BU)', '(A;IO;FRFX;;;BU)'), # Inherit-only ACE does not secure this object.
    'O:SYG:SYD:PNO_ACCESS_CONTROL',                     # Null DACL grants unrestricted access.
    $registry.Replace('KR;;;BU', 'KA;;;BU')
)
foreach ($sddl in $unsafeDescriptors) {
    # A malformed fixture must fail the test, not count as an ACL rejection.
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $rejected = $false
    try {
        $isRegistry = $sddl -eq $unsafeDescriptors[-1]
        $full = if ($isRegistry) { 0xf003f } else { 0x1f01ff }
        $read = if ($isRegistry) { 0x20019 } else { 0x1200a9 }
        $flags = if ($isRegistry) { 'ContainerInherit' } else { 'None' }
        Assert-RestrictedAcl -Descriptor $descriptor -ObjectName 'unsafe fixture' -FullAccess $full -ReadAccess $read -InheritanceFlags $flags
    }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Security validation accepted an unsafe descriptor: $sddl" }
}
$serviceSid = 'S-1-5-80-1071555646-3639003188-2623042311-1024194528-3093158512'
$logFolder = $folder + "(A;OICI;0x1301bf;;;$serviceSid)"
$parameters = $registry.Replace(';;;BU', ";;;$serviceSid")
Assert-RestrictedAcl -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($logFolder)) -ObjectName 'service log fixture' -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags 'ObjectInherit, ContainerInherit' -AdditionalAccess @{$serviceSid=0x1301bf}
Assert-RestrictedAcl -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($parameters)) -ObjectName 'service configuration fixture' -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -ReadSid $serviceSid
foreach ($sddl in @($logFolder.Replace('0x1301bf', 'FA'), $logFolder.Replace($serviceSid, 'S-1-5-19'))) {
    $rejected = $false
    try {
        Assert-RestrictedAcl -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($sddl)) -ObjectName 'unsafe service log fixture' -FullAccess 0x1f01ff -ReadAccess 0x1200a9 -InheritanceFlags 'ObjectInherit, ContainerInherit' -AdditionalAccess @{$serviceSid=0x1301bf}
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Service log permissions accepted excessive access or a shared account grant.' }
}
Write-Output 'Protected ACL validation passed, including service-specific configuration and log permissions.'
