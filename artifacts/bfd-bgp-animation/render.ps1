$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$drawingAssembly = [System.Drawing.Bitmap].Assembly.Location
Add-Type -Path (Join-Path $PSScriptRoot 'render.cs') -ReferencedAssemblies $drawingAssembly, (Join-Path $PSHOME 'System.Private.Windows.Core.dll'), (Join-Path $PSHOME 'System.Private.Windows.GdiPlus.dll'), 'System.Xml.ReaderWriter', 'System.Xml.XmlDocument', 'System.Drawing.Primitives', 'System.Runtime.InteropServices', 'System.Console', 'System.Collections'
[BfdAnimation]::Render($PSScriptRoot)
python (Join-Path $PSScriptRoot 'make_animation.py')
