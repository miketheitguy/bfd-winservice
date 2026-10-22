#Requires -Version 5.1
function Assert-NativeRuntime {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Toolset,
        [Parameter(Mandatory)][AllowEmptyString()][string]$CrtVersion,
        [Parameter(Mandatory)][string]$RuntimeVersion
    )
    $pattern = '\A[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\z'
    if ($Toolset -notmatch $pattern -or $CrtVersion -notmatch $pattern -or $RuntimeVersion -notmatch $pattern) {
        throw 'Native toolset and runtime versions must contain three or four numeric components.'
    }
    # Normalize missing revisions before comparison (Version uses -1 for them).
    $native = [version]$Toolset
    $runtime = [version]$RuntimeVersion
    $crt = [version]$CrtVersion
    $native = [version]::new($native.Major, $native.Minor, $native.Build, [Math]::Max(0, $native.Revision))
    $runtime = [version]::new($runtime.Major, $runtime.Minor, $runtime.Build, [Math]::Max(0, $runtime.Revision))
    $crt = [version]::new($crt.Major, $crt.Minor, $crt.Build, [Math]::Max(0, $crt.Revision))
    if ($native.Major -ne 14 -or $runtime.Major -ne 14 -or $crt.Major -ne 14 -or $native -gt $runtime -or $crt -gt $runtime) {
        throw "Bundled x64 runtime $runtime does not cover native MSVC toolset $native and CRT $crt. Refresh the pinned runtime or build with a compatible toolset."
    }
}
