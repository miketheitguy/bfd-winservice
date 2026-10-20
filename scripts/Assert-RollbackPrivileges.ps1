#Requires -Version 5.1
# Validates captured fixture data without reading or changing service policy.
function Assert-RollbackPrivilegeFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('default','scm-empty','empty','explicit','restricted')][string]$Label,
        [Parameter(Mandatory)][bool]$Present,
        [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::Unknown,
        [AllowEmptyCollection()][AllowEmptyString()][string[]]$Values = @()
    )

    if ($Present -and $Kind -ne [Microsoft.Win32.RegistryValueKind]::MultiString) {
        throw "SCM created a non-MULTI_SZ fixture privilege policy: $Kind"
    }
    # RegistryKey.GetValue can expose a double-NUL empty MULTI_SZ as one empty
    # string. Accept either empty representation here, without normalizing the
    # captured array used to check exact preservation after rollback.
    $empty = $Values.Count -eq 0 -or ($Values.Count -eq 1 -and $Values[0] -ceq '')
    $valid = switch ($Label) {
        'default' { -not $Present }
        'scm-empty' { -not $Present }
        'empty' { $Present -and $empty }
        'explicit' {
            $Present -and $Values.Count -eq 2 -and
                $Values[0] -ceq 'SeChangeNotifyPrivilege' -and
                $Values[1] -ceq 'SeImpersonatePrivilege'
        }
        'restricted' { $true }
    }
    if (-not $valid) {
        $details = ConvertTo-Json -InputObject @($Values) -Compress
        throw "Invalid $Label privilege fixture: present=$Present; kind=$Kind; values=$details"
    }
}
