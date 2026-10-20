#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-RollbackPrivileges.ps1')

$cases = @(
    @{ Label = 'default'; Present = $false; Values = [string[]]@(); Valid = $true },
    @{ Label = 'scm-empty'; Present = $false; Kind = 'Unknown'; Values = [string[]]@(); Valid = $true },
    @{ Label = 'scm-empty'; Present = $true; Values = [string[]]@(); Valid = $false },
    @{ Label = 'scm-empty'; Present = $true; Values = [string[]]@(''); Valid = $false },
    @{ Label = 'scm-empty'; Present = $true; Values = [string[]]@('SeChangeNotifyPrivilege'); Valid = $false },
    @{ Label = 'restricted'; Present = $false; Values = [string[]]@(); Valid = $true },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@(); Valid = $true },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@(''); Valid = $true },
    @{ Label = 'empty'; Present = $false; Values = [string[]]@(); Valid = $false },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@('SeChangeNotifyPrivilege'); Valid = $false },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@('', 'SeImpersonatePrivilege'); Valid = $false },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@('SeImpersonatePrivilege', ''); Valid = $false },
    @{ Label = 'empty'; Present = $true; Values = [string[]]@('', ''); Valid = $false },
    @{ Label = 'default'; Present = $true; Values = [string[]]@(''); Valid = $false },
    @{ Label = 'explicit'; Present = $true; Values = [string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege'); Valid = $true },
    @{ Label = 'explicit'; Present = $false; Values = [string[]]@(); Valid = $false },
    @{ Label = 'explicit'; Present = $true; Values = [string[]]@('SeChangeNotifyPrivilege'); Valid = $false },
    @{ Label = 'explicit'; Present = $true; Values = [string[]]@('SeChangeNotifyPrivilege', 'SeDebugPrivilege'); Valid = $false },
    @{ Label = 'empty'; Present = $true; Kind = 'String'; Values = [string[]]@(''); Valid = $false }
)

foreach ($case in $cases) {
    $kind = if ($case.ContainsKey('Kind')) { $case.Kind } else { 'MultiString' }
    $before = $case.Values.Clone()
    $rejected = $false
    try {
        Assert-RollbackPrivilegeFixture -Label $case.Label -Present $case.Present -Kind $kind -Values $case.Values
    } catch { $rejected = $true }
    if ($rejected -eq $case.Valid) {
        throw "Unexpected fixture validation result: $(ConvertTo-Json -InputObject $case -Compress)"
    }
    if ($before.Count -ne $case.Values.Count -or
        ($before -join [char]0) -cne ($case.Values -join [char]0)) {
        throw 'Fixture validation changed the raw privilege list needed for rollback comparison.'
    }
}
Write-Output "Validated $($cases.Count) rollback privilege fixtures, including absent SCM-empty-request versus explicit-empty policies and both empty MULTI_SZ representations."
