#Requires -Version 5.1
[CmdletBinding()]
param([string]$Path = (Join-Path (Split-Path $PSScriptRoot -Parent) 'installer\Package.wxs'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Assert-RestrictedAcl.ps1')
. (Join-Path $PSScriptRoot 'Assert-StatusComPermission.ps1')
$source = Get-Content -LiteralPath $Path -Raw
$xml = [xml]$source
$ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
$ns.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
$defines = @{}
foreach ($match in [regex]::Matches($source, '<\?define\s+(\w+)\s*=\s*"([^"]+)"\s*\?>')) {
    $defines[$match.Groups[1].Value] = $match.Groups[2].Value
}
function Resolve-WixDefine([string]$Value) {
    [regex]::Replace($Value, '\$\(var\.(\w+)\)', {
        param($Match)
        $defines[$Match.Groups[1].Value]
    })
}
$expected = @(Get-StatusComRegistryValues)
$actual = @($xml.SelectNodes('//w:RegistryValue[starts-with(@Id,"Status")]', $ns))
if ($actual.Count -ne $expected.Count) { throw 'Missing COM service registration values.' }
foreach ($entry in $expected) {
    $nodes = @($actual | Where-Object { $_.GetAttribute('Id') -ceq $entry.Id })
    if ($nodes.Count -ne 1) { throw "Missing COM registry value: $($entry.Id)" }
    $node = $nodes[0]
    $key = $node.ParentNode
    $component = $key.ParentNode
    if ($key.LocalName -ne 'RegistryKey' -or $key.GetAttribute('Root') -ne 'HKLM' -or
        $key.GetAttribute('Key') -cne $entry.Key -or $node.GetAttribute('Name') -cne $entry.Name -or
        $node.GetAttribute('Type') -cne $entry.Type -or
        $component.GetAttribute('Bitness') -ne 'always64') {
        throw "Incorrect COM registry type, path, root, or bitness: $($entry.Id)"
    }
    $value = Resolve-WixDefine $node.GetAttribute('Value')
    if ($entry.Type -eq 'binary') {
        Assert-StatusComPermission -Descriptor (ConvertFrom-StatusPermissionHex $value) -ObjectName $entry.Id -AccessMask ([int]$entry.Value)
    } elseif ($value -cne $entry.Value) { throw "Incorrect COM registry value: $($entry.Id)" }
}
$roots = @($xml.SelectNodes('//w:RegistryValue[starts-with(@Id,"Status")]/w:PermissionEx', $ns))
if ($roots.Count -ne 5) { throw 'Every COM registration root must have a protected ACL.' }
foreach ($permission in $roots) {
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new((Resolve-WixDefine $permission.GetAttribute('Sddl')))
    Assert-RestrictedAcl -Descriptor $descriptor -ObjectName $permission.GetAttribute('Id') -FullAccess 0xf003f -ReadAccess 0x20019 -InheritanceFlags 'ContainerInherit' -AdditionalAccess @{'S-1-5-19'=0x20019}
    if ($permission.ParentNode.GetAttribute('KeyPath') -ne 'yes') { throw 'COM registry security must have a repairable key path.' }
}
$service = $xml.SelectSingleNode('//w:ServiceInstall[@Name="BfdWinService"]', $ns)
if ($null -eq $service.SelectSingleNode('w:ServiceDependency[@Id="RpcSs"]', $ns)) { throw 'The COM service must depend directly on RpcSs.' }
foreach ($node in $xml.SelectNodes('//w:RegistryKey | //w:RegistryValue', $ns)) {
    if ($node.GetAttribute('Key') -match 'LocalServer32' -or
        $node.GetAttribute('Name') -in @('DllSurrogate','RemoteServerName')) {
        throw 'Status activation must remain in the installed service.'
    }
}
Write-Output 'Validated x64 COM service activation, identity mappings, local-only permissions, and protected registration ACLs.'
