#Requires -Version 5.1
[CmdletBinding()]
param([string]$ExpectedLocalAddress, [string]$ExpectedPeerAddress)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ((Get-Service BfdWinService).Status -ne 'Running') {
    throw 'Start the configured BfdWinService before validating its status endpoint.'
}
$endpoint = $null
$snapshot = $null
$later = $null
try {
    $endpoint = New-Object -ComObject BfdWinService.Status.1
    $snapshot = $endpoint.GetSnapshot()
    if ($null -eq $snapshot) { throw 'The running BFD engine returned no snapshot.' }
    $properties = @($snapshot | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)
    foreach ($excluded in @('SnapshotAge','ReceiveAgeAtCapture','PublishInterval','BgpControlEnabled','CapturedAtUtc','SchemaVersion','ServiceStatus')) {
        if ($excluded -in $properties) { throw "Excluded property was exposed: $excluded" }
    }
    foreach ($property in @('LocalAddress','SessionType','TransportMode','LocalState','LocalDiagnostic','AuthenticationType')) {
        if ($snapshot.$property -isnot [string]) { throw "Expected a string property: $property" }
    }
    foreach ($property in @('Passive','PointToPoint','PeriodicTransmitEnabled')) {
        if ($snapshot.$property -isnot [bool]) { throw "Expected a Boolean property: $property" }
    }
    foreach ($property in @('PacketsReceivedAccepted','PacketsSentSuccessfully','PacketsRejected','AuthenticationFailures','MalformedPackets','ProtocolRejections','TransportValidationFailures','SocketErrors','DetectionTimeouts','UpTransitions','RepliesWithheld','ConfiguredMinTxIntervalMicroseconds','ConfiguredMinRxIntervalMicroseconds','StartupTxIntervalMicroseconds')) {
        if ($snapshot.$property -isnot [uint64]) { throw "Expected a UInt64 property: $property" }
    }
    foreach ($property in @('LocalSourcePort','ControlPort','LocalDiscriminator')) {
        if ($snapshot.$property -isnot [uint32]) { throw "Expected a UInt32 property: $property" }
    }
    if ($snapshot.StateSinceUtc -isnot [datetime]) { throw 'Expected StateSinceUtc to marshal to DateTime.' }
    if ($snapshot.LocalState -notin @('AdminDown','Down','Init','Up')) { throw 'Unexpected local BFD protocol state.' }
    if ($ExpectedLocalAddress -and $snapshot.LocalAddress -cne $ExpectedLocalAddress) { throw 'Unexpected local address.' }
    if ($ExpectedPeerAddress -and $snapshot.PeerAddress -cne $ExpectedPeerAddress) { throw 'Unexpected peer address.' }
    $state = $snapshot.LocalState
    $writeDenied = $false
    try { $snapshot.LocalState = $state } catch { $writeDenied = $true }
    if (-not $writeDenied) { throw 'The COM snapshot accepted a property write.' }
    $sent = $snapshot.PacketsSentSuccessfully
    Start-Sleep -Milliseconds 1200
    $later = $endpoint.GetSnapshot()
    if ($null -eq $later) { throw 'The engine exited during snapshot validation.' }
    if ($snapshot.LocalState -cne $state -or $snapshot.PacketsSentSuccessfully -ne $sent) {
        throw 'Retaining a snapshot did not preserve its immutable values.'
    }
    if ($later.PacketsSentSuccessfully -lt $sent) { throw 'Send counter decreased within one engine instance.' }
    $view = $snapshot | Select-Object LocalAddress, PeerAddress, LocalState, RemoteState,
        LastValidReceiveUtc, LastSuccessfulSendUtc, PacketsSentSuccessfully,
        PacketsReceivedAccepted, DetectionTimeMicroseconds
    if ($view.LocalAddress -cne $snapshot.LocalAddress -or $view.LocalState -cne $snapshot.LocalState) {
        throw 'PowerShell Select-Object did not preserve status properties.'
    }
    $view | Format-List | Out-String | Write-Output
    Write-Output 'Validated read-only COM Automation types, PowerShell output, and excluded fields.'
}
finally {
    if ($null -ne $later -and [Runtime.InteropServices.Marshal]::IsComObject($later)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($later)
    }
    if ($null -ne $snapshot -and [Runtime.InteropServices.Marshal]::IsComObject($snapshot)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($snapshot)
    }
    if ($null -ne $endpoint -and [Runtime.InteropServices.Marshal]::IsComObject($endpoint)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($endpoint)
    }
}
