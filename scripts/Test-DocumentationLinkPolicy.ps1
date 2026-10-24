#Requires -Version 7.0
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-DocumentationLinks.ps1')

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('bfd-doc-links-' + [guid]::NewGuid())
[void](New-Item -ItemType Directory -Path $fixtureRoot)
try {
    Set-Content -LiteralPath (Join-Path $fixtureRoot 'target file.md') -Value @'
# Target `name`
## Repeat
## Repeat
<a id="compatibility-anchor"></a>
```markdown
## Example only
```
<!-- <a id="comment-only"></a> -->
'@
    Set-Content -LiteralPath (Join-Path $fixtureRoot 'source.md') -Value @'
# Source
[heading](target%20file.md#target-name)
[duplicate](<target file.md#repeat-1>)
[explicit](target%20file.md#compatibility-anchor)
[self](#source)
[reference][details]
[details]: target%20file.md#repeat
[external](https://invalid.example/absent#anchor)
`[literal](missing.md)`
``[literal with ` inside](missing.md)``
```markdown
[example](missing.md)
```
~~~markdown
[example](missing.md)
~~~
<!-- [comment](missing.md) -->
'@
    Assert-DocumentationLinks -Root $fixtureRoot -Files @('source.md', 'target file.md')
    foreach ($case in @(
        @{ Link = '[missing](absent.md)'; Reason = 'missing target' },
        @{ Link = '[missing](target%20file.md#absent)'; Reason = 'missing Markdown anchor' },
        @{ Link = '[example](target%20file.md#example-only)'; Reason = 'missing Markdown anchor' },
        @{ Link = '[comment](target%20file.md#comment-only)'; Reason = 'missing Markdown anchor' },
        @{ Link = '[details]: absent.md'; Reason = 'missing target' },
        @{ Link = '[outside](../outside.md)'; Reason = 'link leaves repository' }
    )) {
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'bad.md') -Value $case.Link
        $failure = $null
        try { Assert-DocumentationLinks -Root $fixtureRoot -Files @('bad.md') }
        catch { $failure = $_.Exception.Message }
        if (-not $failure -or -not $failure.Contains($case.Reason) -or -not $failure.Contains('bad.md:1:')) {
            throw "Expected a located '$($case.Reason)' failure for $($case.Link); got: $failure"
        }
    }
    Write-Output 'Documentation link fixtures accept headings, explicit anchors, and literal examples; reject missing targets and anchors.'
} finally {
    $resolvedFixture = (Resolve-Path -LiteralPath $fixtureRoot).Path
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ($resolvedFixture -ne [IO.Path]::GetFullPath($fixtureRoot) -or -not $resolvedFixture.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove a documentation fixture outside its temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
