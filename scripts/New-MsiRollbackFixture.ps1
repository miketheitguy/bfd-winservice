#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Destination
)

# Creates a test package only. It never installs, starts, or configures a service.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $Destination) { throw 'Rollback fixture destination already exists.' }
Copy-Item -LiteralPath (Resolve-Path -LiteralPath $Path).Path -Destination $Destination
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $null
try {
    $database = $installer.OpenDatabase((Resolve-Path -LiteralPath $Destination).Path, 1)
    $view = $database.OpenView('SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action` = ''ConfigureServicePolicy''')
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        try {
            $sequence = [int]$record.GetType().InvokeMember('IntegerData', [Reflection.BindingFlags]::GetProperty, $null, $record, @(1)) + 1
        }
        finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    }
    finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
    # The failure must be deferred. An immediate Type 19 error would fail script
    # generation before the queued account/SID changes actually execute.
    foreach ($sql in @(
        'INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES (''ForceRollbackTest'', 3090, ''BrokerExe'', ''--force-rollback-test'')',
        "INSERT INTO ``InstallExecuteSequence`` (``Action``, ``Condition``, ``Sequence``) VALUES ('ForceRollbackTest', '1', $sequence)"
    )) {
        $view = $database.OpenView($sql)
        try { [void]$view.Execute() }
        finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
    }
    [void]$database.Commit()
}
finally {
    if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
