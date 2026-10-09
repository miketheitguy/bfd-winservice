#Requires -Version 5.1
# Shared by package inspection and the disposable runner's installation test.
function Assert-RestrictedAcl {
    param(
        [Parameter(Mandatory)][Security.AccessControl.RawSecurityDescriptor]$Descriptor,
        [Parameter(Mandatory)][string]$ObjectName,
        [Parameter(Mandatory)][int]$FullAccess,
        [Parameter(Mandatory)][int]$ReadAccess,
        [Security.AccessControl.AceFlags]$InheritanceFlags = 'None',
        [string]$ReadSid = 'S-1-5-32-545',
        [hashtable]$AdditionalAccess = @{}
    )

    $protected = [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if (($Descriptor.ControlFlags -band $protected) -eq 0 -or
        $null -eq $Descriptor.Owner -or $Descriptor.Owner.Value -ne 'S-1-5-18' -or
        $null -eq $Descriptor.DiscretionaryAcl -or $Descriptor.DiscretionaryAcl.Count -ne (3 + $AdditionalAccess.Count)) {
        throw "Expected SYSTEM ownership and a protected DACL with exactly the required grants: $ObjectName"
    }
    $grants = @{'S-1-5-18' = $FullAccess; 'S-1-5-32-544' = $FullAccess; $ReadSid = $ReadAccess}
    foreach ($sid in $AdditionalAccess.Keys) {
        if ($grants.ContainsKey($sid)) { throw "Duplicate expected trustee: $sid" }
        $grants[$sid] = $AdditionalAccess[$sid]
    }
    foreach ($ace in $Descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceType -ne 'AccessAllowed' -or $ace.AceFlags -ne $InheritanceFlags -or
            -not $grants.ContainsKey($ace.SecurityIdentifier.Value) -or
            $ace.AccessMask -ne $grants[$ace.SecurityIdentifier.Value]) {
            throw "ACL differs from the required service and administrator permissions: $ObjectName"
        }
        $grants.Remove($ace.SecurityIdentifier.Value)
    }
    if ($grants.Count -ne 0) { throw "Missing required access grant: $ObjectName" }
}
