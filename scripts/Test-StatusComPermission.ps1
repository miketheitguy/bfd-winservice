#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-StatusComPermission.ps1')

foreach ($mask in @(3, 11)) {
    $valid = "O:SYG:SYD:P(A;;$mask;;;SY)(A;;$mask;;;BA)"
    Assert-StatusComPermission -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($valid)) -ObjectName 'valid' -AccessMask $mask
    # Reject legacy execute-only grants (which permit remote callers), remote
    # bits, additional trustees, missing grants, and mutable inherited ACLs.
    $unsafeDescriptors = @(
        'O:SYG:SYD:P(A;;1;;;SY)(A;;1;;;BA)',
        'O:SYG:SYD:P(A;;7;;;SY)(A;;7;;;BA)',
        'O:SYG:SYD:P(A;;31;;;SY)(A;;31;;;BA)',
        "O:SYG:SYD:P(A;;$mask;;;SY)(A;;$mask;;;BA)(A;;$mask;;;BU)",
        "O:SYG:SYD:P(A;;$mask;;;SY)(A;;$mask;;;AU)",
        "O:SYG:SYD:P(A;;$mask;;;SY)(A;;$mask;;;SY)",
        "O:SYG:SYD:P(A;;$mask;;;SY)",
        "O:BAG:SYD:P(A;;$mask;;;SY)(A;;$mask;;;BA)",
        "O:SYG:SYD:(A;;$mask;;;SY)(A;;$mask;;;BA)",
        "O:SYG:SYD:P(A;CI;$mask;;;SY)(A;CI;$mask;;;BA)",
        'O:SYG:SYD:NO_ACCESS_CONTROL'
    )
    foreach ($sddl in $unsafeDescriptors) {
        $rejected = $false
        try {
            Assert-StatusComPermission -Descriptor ([Security.AccessControl.RawSecurityDescriptor]::new($sddl)) -ObjectName 'unsafe' -AccessMask $mask
        } catch { $rejected = $true }
        if (-not $rejected) { throw "COM permission test accepted unsafe descriptor: $sddl" }
    }
}
Write-Output 'Validated local-only SYSTEM/Administrators COM permissions and rejection of unsafe descriptors.'
