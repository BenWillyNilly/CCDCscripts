$OutputFolder = "C:\ProgramData\Logs"

if (!(Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}

$TimeStamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$BackupFolder = "$OutputFolder\RegistryBackup-$TimeStamp"

New-Item -ItemType Directory -Path $BackupFolder | Out-Null

reg export HKLM "$BackupFolder\HKLM.reg" /y
reg export HKCU "$BackupFolder\HKCU.reg" /y
reg export HKCR "$BackupFolder\HKCR.reg" /y
reg export HKU "$BackupFolder\HKU.reg" /y

Write-Host "Registry backup saved to:"
Write-Host $BackupFolder