#Requires -Version 5.1
[CmdletBinding()]
param([string]$Path)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $Path) { $Path = Join-Path (Split-Path $PSScriptRoot -Parent) 'installer\Package.wxs' }
. (Join-Path $PSScriptRoot 'Assert-InstallerHardening.ps1')
$source = [xml](Get-Content -LiteralPath $Path -Raw)
Assert-InstallerHardeningSource -Document $source
$mutations = @(
    @('ControlInbound','Action','block'),
    @('ControlInbound','Protocol','tcp'),
    @('ControlInbound','Outbound','yes'),
    @('ControlInbound','Enabled','no'),
    @('ControlInbound','Profile','domain'),
    @('ControlInbound','File','BrokerExe'),
    @('ControlInbound','Port','135'),
    @('ControlInbound','RemotePort','135'),
    @('ControlInbound','IgnoreFailure','yes'),
    @('ControlInbound','Scope','localSubnet'),
    @('ControlInbound','Port','3784'),
    @('SbfdRequestInbound','RemotePort','49152-65535'),
    @('SbfdRequestInbound','RemotePort','1-65535'),
    @('SbfdReplyOutbound','RemotePort','49152-65535'),
    @('SbfdReplyOutbound','RemotePort','1-65535'),
    @('ControlBfdService','Start','install'),
    @('ControlBgpBroker','Start','install'),
    @('CommitServicePolicy','Execute','deferred'),
    @('CommitServicePolicy','Impersonate','yes'),
    @('CommitServicePolicy','Return','ignore'),
    @('CommitServicePolicy','FileRef','ServiceExe'),
    @('CommitServicePolicy','ExeCommand','--configure-install'),
    @('PrepareServicePolicy','Execute','commit')
)
foreach ($mutation in $mutations) {
    $unsafe = $source.Clone()
    $node = $unsafe.SelectSingleNode('//*[@Id="' + $mutation[0] + '"]')
    $node.SetAttribute($mutation[1], $mutation[2])
    $rejected = $false
    try { Assert-InstallerHardeningSource -Document $unsafe } catch { $rejected = $true }
    if (-not $rejected) { throw "Unsafe installer hardening mutation was accepted: $($mutation -join ' ')" }
}
foreach ($id in @('ControlInbound','SbfdRequestInbound','CommitServicePolicy')) {
    $unsafe = $source.Clone()
    $node = $unsafe.SelectSingleNode('//*[@Id="' + $id + '"]')
    [void]$node.ParentNode.RemoveChild($node)
    $rejected = $false
    try { Assert-InstallerHardeningSource -Document $unsafe } catch { $rejected = $true }
    if (-not $rejected) { throw "Missing installer hardening setting was accepted: $id" }
}
# An extra firewall rule must not silently restore a status-host TCP policy.
$unsafe = $source.Clone()
$firewall = $unsafe.SelectSingleNode('//*[@Id="ControlInbound"]')
$extra = $firewall.Clone()
$extra.SetAttribute('Id', 'UnexpectedTcpRule')
$extra.SetAttribute('Protocol', 'tcp')
$extra.SetAttribute('Action', 'block')
[void]$firewall.ParentNode.AppendChild($extra)
$rejected = $false
try { Assert-InstallerHardeningSource -Document $unsafe } catch { $rejected = $true }
if (-not $rejected) { throw 'An additional TCP firewall rule was accepted.' }
# Status must not regain a COM activation endpoint or its RPC dependency.
$unsafe = $source.Clone()
$ns = [Xml.XmlNamespaceManager]::new($unsafe.NameTable)
$ns.AddNamespace('w','http://wixtoolset.org/schemas/v4/wxs')
$component = $unsafe.SelectSingleNode('//w:Component[@Id="ServiceComponent"]', $ns)
$key = $unsafe.CreateElement('RegistryKey', 'http://wixtoolset.org/schemas/v4/wxs')
$key.SetAttribute('Root', 'HKLM')
$key.SetAttribute('Key', 'SOFTWARE\Classes\CLSID\{E4A97D25-73E2-4E6C-9A35-281B6AE697C3}')
[void]$component.AppendChild($key)
$rejected = $false
try { Assert-InstallerHardeningSource -Document $unsafe } catch { $rejected = $true }
if (-not $rejected) { throw 'A COM status class registration was accepted.' }
foreach ($target in @(@('BfdWinService','RpcSs'), @('BfdWinService','BfdBgpBroker'), @('BfdBgpBroker','BfdWinService'))) {
    $unsafe = $source.Clone()
    $ns = [Xml.XmlNamespaceManager]::new($unsafe.NameTable)
    $ns.AddNamespace('w','http://wixtoolset.org/schemas/v4/wxs')
    $service = $unsafe.SelectSingleNode(('//w:ServiceInstall[@Name="' + $target[0] + '"]'), $ns)
    $dependency = $unsafe.CreateElement('ServiceDependency', 'http://wixtoolset.org/schemas/v4/wxs')
    $dependency.SetAttribute('Id', $target[1])
    [void]$service.AppendChild($dependency)
    $rejected = $false
    try { Assert-InstallerHardeningSource -Document $unsafe } catch { $rejected = $true }
    if (-not $rejected) { throw "An unexpected dependency was accepted: $($target -join ' -> ')" }
}
Write-Output 'Validated exactly five UDP allow rules, independent service startup, no COM status registration, commit-only service policy, and 31 unsafe source mutations.'
