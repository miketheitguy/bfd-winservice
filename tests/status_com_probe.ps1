$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("00000001-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IBfdTestClassFactory {
    [PreserveSig] int CreateInstance(IntPtr outer, ref Guid iid, out IntPtr result);
    [PreserveSig] int LockServer(bool locked);
}
public static class BfdStatusProbe {
    public static object Create(string moniker) {
        var factory = (IBfdTestClassFactory) Marshal.BindToMoniker(moniker);
        var iid = new Guid("00020400-0000-0000-C000-000000000046");
        IntPtr result;
        Marshal.ThrowExceptionForHR(factory.CreateInstance(IntPtr.Zero, ref iid, out result));
        try { return Marshal.GetObjectForIUnknown(result); }
        finally { Marshal.Release(result); }
    }
}
'@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$authorized = $identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try {
    $endpoint = [BfdStatusProbe]::Create($env:BFD_TEST_STATUS_MONIKER)
    $snapshot = $endpoint.GetSnapshot()
    if (-not $authorized) { throw 'Non-administrator unexpectedly obtained a snapshot' }
    if ($snapshot.LocalAddress -ne '127.0.0.214') { throw 'LocalAddress mismatch' }
    if ($snapshot.LocalDiscriminator -ne 7) { throw 'LocalDiscriminator mismatch' }
    if ($snapshot.LocalDiscriminator -isnot [uint32]) { throw 'Discriminator must be UInt32' }
    if ($snapshot.PacketsReceivedAccepted -isnot [uint64]) { throw 'Counters must be UInt64' }
    if ($snapshot.Passive -isnot [bool]) { throw 'Passive must be Boolean' }
    if ($snapshot.StateSinceUtc -isnot [datetime]) { throw 'UTC timestamp must be DateTime' }
    if ($null -ne $snapshot.LastValidReceiveUtc) { throw 'Unobserved timestamp must be null' }
    $members = @($snapshot | Get-Member -MemberType Property | Select-Object -ExpandProperty Name)
    if ($members.Count -ne 55) { throw "Expected 55 snapshot properties, received $($members.Count): $($members -join ', ')" }
    foreach ($omitted in 'SnapshotAge', 'ReceiveAgeAtCapture', 'PublishInterval', 'BgpControlEnabled', 'CapturedAtUtc', 'SchemaVersion', 'ServiceStatus') {
        if ($members -contains $omitted) { throw "Unrequested property $omitted" }
    }
    try { $snapshot.LocalState = 'Up'; throw 'Read-only property accepted mutation' }
    catch { if ($_.Exception.Message -eq 'Read-only property accepted mutation') { throw } }
    $snapshot | Select-Object LocalAddress, PeerAddress, LocalState, LocalDiscriminator, PacketsReceivedAccepted, LastValidReceiveUtc | Format-List | Out-String | Write-Output
    Write-Output 'STATUS_COM_ALLOWED'
}
catch {
    $exception = $_.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    if ($authorized -or $exception.HResult -ne -2147024891) { throw }
    Write-Output 'STATUS_COM_DENIED: E_ACCESSDENIED'
}
