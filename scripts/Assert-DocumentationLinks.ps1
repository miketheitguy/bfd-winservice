#Requires -Version 7.0
Set-StrictMode -Version Latest

# Preserve line numbers while excluding examples and HTML comments from checks.
function Get-MarkdownBody([string]$Text) {
    $lines = $Text -split "`n"
    $fence = ''
    foreach ($line in $lines) {
        if ($fence) {
            if ($line -match ('^ {0,3}' + [regex]::Escape($fence[0]) + '{' + $fence.Length + ',}\s*$')) {
                $fence = ''
            }
            ''
        } elseif ($line -match '^ {0,3}(`{3,}|~{3,})') {
            $fence = $Matches[1]
            ''
        } else {
            $line
        }
    }
}

function Get-MarkdownAnchors([string]$Body) {
    $anchors = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $headings = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($heading in [regex]::Matches($Body, '(?m)^ {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*\r?$')) {
        $label = $heading.Groups[1].Value -replace '\[([^\]]+)\]\([^)]*\)', '$1'
        $label = [Net.WebUtility]::HtmlDecode(($label -replace '<[^>]*>', ''))
        $base = ($label.ToLowerInvariant() -replace '[^\p{L}\p{M}\p{N}\p{Pc}\- ]', '') -replace ' ', '-'
        $slug = $base
        $suffix = 0
        while (-not $headings.Add($slug)) {
            $suffix++
            $slug = "$base-$suffix"
        }
        [void]$anchors.Add($slug)
    }
    foreach ($tag in [regex]::Matches($Body, '(?i)<[^>]+\b(?:id|name)\s*=\s*["'']([^"'']+)["''][^>]*>')) {
        [void]$anchors.Add($tag.Groups[1].Value)
    }
    return ,$anchors
}

function Assert-DocumentationLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Files
    )
    $rootPath = [IO.Path]::GetFullPath($Root)
    $bodies = @{}
    $anchorCache = @{}
    $failures = [Collections.Generic.List[string]]::new()
    $linkCount = 0
    foreach ($file in $Files) {
        $source = [IO.Path]::GetFullPath((Join-Path $rootPath $file))
        $body = (Get-MarkdownBody ([IO.File]::ReadAllText($source))) -join "`n"
        $body = [regex]::Replace($body, '(?s)<!--.*?-->', { param($m) $m.Value -replace '[^\r\n]', ' ' })
        $bodies[$source] = $body
    }
    foreach ($file in $Files) {
        $source = [IO.Path]::GetFullPath((Join-Path $rootPath $file))
        # Inline code is literal text; code spans in headings remain available
        # in the cached body so their contents contribute to heading anchors.
        $body = [regex]::Replace($bodies[$source], '(`+)([^`]|(?!\1)`)*?\1', { param($m) $m.Value -replace '[^\r\n]', ' ' })
        # Check inline destinations and reference definitions. External URLs
        # and source-file fragments are outside this repository-local check.
        $pattern = '(?m)(?:!?\[[^\]]*\]\(\s*|^ {0,3}\[[^\]]+\]:\s*)(?:<(?<target>[^>]+)>|(?<target>[^\s)]+))'
        foreach ($link in [regex]::Matches($body, $pattern)) {
            $target = $link.Groups['target'].Value
            if ($target -match '^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)') { continue }
            $linkCount++
            $line = 1 + ([regex]::Matches($body.Substring(0, $link.Index), "`n")).Count
            $location = "${file}:${line}"
            $parts = $target -split '#', 2
            $relative = [Uri]::UnescapeDataString(($parts[0] -split '\?', 2)[0])
            $destination = if (-not $relative) {
                $source
            } elseif ($relative.StartsWith('/')) {
                [IO.Path]::GetFullPath((Join-Path $rootPath $relative.TrimStart('/')))
            } else {
                [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetDirectoryName($source)) $relative))
            }
            $withinRoot = [IO.Path]::GetRelativePath($rootPath, $destination)
            if ($withinRoot -eq '..' -or $withinRoot -match '^\.\.[/\\]' -or [IO.Path]::IsPathRooted($withinRoot)) {
                $failures.Add("${location}: link leaves repository: $target")
                continue
            }
            if (-not (Test-Path -LiteralPath $destination)) {
                $failures.Add("${location}: missing target: $target")
                continue
            }
            if ($parts.Count -lt 2 -or -not $parts[1] -or [IO.Path]::GetExtension($destination) -ne '.md') { continue }
            if (-not $anchorCache.ContainsKey($destination)) {
                if (-not $bodies.ContainsKey($destination)) {
                    $targetBody = (Get-MarkdownBody ([IO.File]::ReadAllText($destination))) -join "`n"
                    $bodies[$destination] = [regex]::Replace($targetBody, '(?s)<!--.*?-->', '')
                }
                $anchorCache[$destination] = Get-MarkdownAnchors $bodies[$destination]
            }
            $anchor = [Uri]::UnescapeDataString($parts[1])
            if (-not $anchorCache[$destination].Contains($anchor)) {
                $failures.Add("${location}: missing Markdown anchor: $target")
            }
        }
    }
    if ($failures.Count) { throw ($failures -join "`n") }
    Write-Output "Checked $linkCount local links in $($Files.Count) Markdown files."
}
