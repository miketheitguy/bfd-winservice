#Requires -Version 5.1
function Assert-NativeRuntime {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Toolset,
        [Parameter(Mandatory)][string]$RuntimeVersion
    )
    $pattern = '\A[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\z'
    if ($Toolset -notmatch $pattern -or $RuntimeVersion -notmatch $pattern) {
        throw 'Native toolset and runtime versions must contain three or four numeric components.'
    }
    # Normalize missing revisions before comparison (Version uses -1 for them).
    $native = [version]$Toolset
    $runtime = [version]$RuntimeVersion
    $native = [version]::new($native.Major, $native.Minor, $native.Build, [Math]::Max(0, $native.Revision))
    $runtime = [version]::new($runtime.Major, $runtime.Minor, $runtime.Build, [Math]::Max(0, $runtime.Revision))
    if ($native.Major -ne 14 -or $runtime.Major -ne 14 -or $native -gt $runtime) {
        throw "Bundled x64 runtime $runtime does not cover native MSVC toolset $native. Refresh the pinned runtime or build with a compatible toolset."
    }
}
