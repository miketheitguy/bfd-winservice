#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\BfdWinService\Parameters'
$logDirectory = 'C:\ProgramData\BfdWinService'
$logFilePath = Join-Path $logDirectory 'trace.log'

New-Item -ItemType Directory -Path $logDirectory -Force
New-Item -Path $parameters -Force
New-ItemProperty -Path $parameters -Name LogFilePath `
    -PropertyType String -Value $logFilePath -Force
New-ItemProperty -Path $parameters -Name LogToFile `
    -PropertyType DWord -Value 0 -Force

Write-Output "LogFilePath (REG_SZ): $logFilePath"
Write-Output 'LogToFile (REG_DWORD): 0'
