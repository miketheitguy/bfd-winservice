#Requires -Version 5.1
# Source and MSI checks share the same independent firewall contract.
function Assert-BfdFirewallRules {
    param([Parameter(Mandatory)][object[]]$Rules)
    $expected = @{
        ControlInbound = @('3784,4784','49152-65535','1','17','1')
        SbfdRequestInbound = @('7784','1-7783,7785-65535','1','17','1')
        SbfdReplyInbound = @('49152-65535','7784','1','17','1')
        ProbeOutbound = @('49152-65535','3784,4784,7784','2','17','1')
        SbfdReplyOutbound = @('7784','1-7783,7785-65535','2','17','1')
    }
    if ($Rules.Count -ne $expected.Count) { throw 'Expected exactly five BFD UDP allow rules.' }
    foreach ($id in $expected.Keys) {
        $matches = @($Rules | Where-Object Id -CEQ $id)
        if ($matches.Count -ne 1) { throw "Missing or duplicate firewall rule: $id" }
        $rule = $matches[0]
        $values = $expected[$id]
        if ([string]$rule.LocalPort -cne $values[0] -or [string]$rule.RemotePort -cne $values[1] -or
            [string]$rule.Direction -cne $values[2] -or [string]$rule.Protocol -cne $values[3] -or
            [string]$rule.Action -cne $values[4] -or [string]$rule.Program -cne '[#ServiceExe]' -or
            [string]$rule.Profile -cne '2147483647' -or [string]$rule.Attributes -cne '0' -or
            [string]$rule.Enabled -cne '1') {
            throw "Unsafe firewall protocol, direction, scope, ports, profile, action, or enablement: $id"
        }
    }
}

function Assert-InstallerHardeningSource {
    param([Parameter(Mandatory)][xml]$Document)
    $ns = [Xml.XmlNamespaceManager]::new($Document.NameTable)
    $ns.AddNamespace('w','http://wixtoolset.org/schemas/v4/wxs')
    $ns.AddNamespace('f','http://wixtoolset.org/schemas/v4/wxs/firewall')
    $rows = @($Document.SelectNodes('//f:FirewallException', $ns) | ForEach-Object {
        $node = $_
        if ($node.GetAttribute('Scope') -cne 'any' -or $node.HasAttribute('Program') -or
            $node.SelectNodes('*').Count -ne 0) { throw 'Firewall rules must use a fixed installed program and all-address scope.' }
        [pscustomobject]@{
            Id=$node.GetAttribute('Id'); LocalPort=$node.GetAttribute('Port'); RemotePort=$node.GetAttribute('RemotePort')
            Direction=$(if ($node.GetAttribute('Outbound') -eq 'yes') {'2'} else {'1'})
            Protocol=$(switch ($node.GetAttribute('Protocol')) {'udp' {'17'} 'tcp' {'6'} default {'invalid'}})
            Action=$(switch ($node.GetAttribute('Action')) {'allow' {'1'} 'block' {'0'} default {'invalid'}})
            Program=('[#' + $node.GetAttribute('File') + ']')
            Profile=$(if ($node.GetAttribute('Profile') -ceq 'all') {'2147483647'} else {'invalid'})
            Attributes=$(if ($node.GetAttribute('IgnoreFailure') -ceq 'no') {'0'} else {'1'})
            Enabled=$(if ($node.GetAttribute('Enabled') -ceq 'yes') {'1'} else {'0'})
        }
    })
    Assert-BfdFirewallRules -Rules $rows
    # BFD hosts a private local RPC interface. Registering a COM class, ProgID, or
    # AppID would reintroduce an activation endpoint into the BFD process.
    $classes = @($Document.SelectNodes('//w:RegistryKey | //w:RegistryValue', $ns) | Where-Object {
        $_.GetAttribute('Key') -like 'SOFTWARE\Classes*' -or $_.GetAttribute('Name') -in @('AppID','AppIDFlags','LocalService','LaunchPermission','AccessPermission')
    })
    if ($classes.Count -ne 0) { throw 'The installer must not register COM classes, ProgIDs, or AppIDs.' }
    $service = $Document.SelectSingleNode('//w:ServiceInstall[@Name="BfdWinService"]', $ns)
    $dependencies = @($service.SelectNodes('w:ServiceDependency', $ns) | ForEach-Object { $_.GetAttribute('Id') })
    if ($dependencies.Count -ne 0) {
        throw 'BFD must start independently, with no SCM service dependencies.'
    }
    $broker = $Document.SelectSingleNode('//w:ServiceInstall[@Name="BfdBgpBroker"]', $ns)
    $brokerDependencies = @($broker.SelectNodes('w:ServiceDependency', $ns) | ForEach-Object { $_.GetAttribute('Id') })
    if ($brokerDependencies.Count -ne 1 -or $brokerDependencies[0] -cne 'RpcSs') {
        throw 'The broker must depend only on RpcSs for native MI, never on BFD.'
    }
    if ($Document.SelectNodes('//w:RequiredPrivilege | //w:RegistryValue[@Name="RequiredPrivileges"]', $ns).Count -ne 0) {
        throw 'SCM privilege policy must use the transactional native installer, not registry writes or MsiConfigureServices.'
    }
    $controls = @($Document.SelectNodes('//w:ServiceControl', $ns))
    if ($controls.Count -ne 2 -or @($controls | Where-Object {
        $_.HasAttribute('Start') -or $_.GetAttribute('Stop') -cne 'both' -or
        $_.GetAttribute('Remove') -cne 'uninstall' -or $_.GetAttribute('Wait') -cne 'yes'
    }).Count -ne 0) {
        throw 'MSI must stop both services and never start one before the commit-only privilege policy.'
    }
    $commit = @($Document.SelectNodes('//w:CustomAction[@Id="CommitServicePolicy"]', $ns))
    if ($Document.SelectNodes('//w:CustomAction[@Execute="commit"]', $ns).Count -ne 1 -or
        $commit.Count -ne 1 -or $commit[0].GetAttribute('Execute') -cne 'commit' -or
        $commit[0].GetAttribute('Impersonate') -cne 'no' -or $commit[0].GetAttribute('Return') -cne 'check' -or
        $commit[0].GetAttribute('FileRef') -cne 'BrokerExe' -or $commit[0].GetAttribute('ExeCommand') -cne '--commit-install') {
        throw 'Only the fixed-target elevated commit action may finalize BFD RequiredPrivileges.'
    }
}
