[CmdletBinding()]
param([string]$DrawioPath = 'C:\Program Files\draw.io\draw.io.exe')

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $DrawioPath -PathType Leaf)) {
    throw 'Set DrawioPath to the installed draw.io Desktop executable.'
}
$diagramPath = Join-Path $PSScriptRoot 'bfd-flower-power-lifecycle.drawio'
$renderArguments = @('--no-sandbox', '--disable-gpu', '--disable-update', '--theme', 'light')
# draw.io 32.4.1 exposes the routing algorithm through the custom-layout name.
& $DrawioPath @renderArguments --layout '[{"layout":"orthogonalEdge"}]' -x -f xml -o $diagramPath $diagramPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Connector routing failed.' }
& $DrawioPath @renderArguments -x -f png -e --scale 0.6 -b 24 -o "$diagramPath.png" $diagramPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'PNG export failed.' }
& $DrawioPath @renderArguments -x -f svg -e --embed-svg-fonts false -b 24 -o "$diagramPath.svg" $diagramPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SVG export failed.' }

# Embed the retro display face once; repeating font data per label inflates SVGs.
$displayFontPath = Join-Path $env:WINDIR 'Fonts\COOPBL.TTF'
if (Test-Path -LiteralPath $displayFontPath -PathType Leaf) {
    $fontData = [Convert]::ToBase64String([IO.File]::ReadAllBytes($displayFontPath))
    $svg = [IO.File]::ReadAllText("$diagramPath.svg")
    $fontStyle = '<defs><style type="text/css">@font-face{font-family:"Cooper Black";src:url("data:font/ttf;base64,' + $fontData + '") format("truetype");font-weight:400;font-style:normal;}</style></defs>'
    $svg = [regex]::Replace($svg, '(<svg\b[^>]*>)', ('$1' + $fontStyle), 1)
    [IO.File]::WriteAllText("$diagramPath.svg", $svg)
}
Write-Output 'Routed and rendered one connected diagram as editable draw.io, SVG, and PNG.'
