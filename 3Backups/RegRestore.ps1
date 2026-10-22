$BackupFolder = "C:\ProgramData\Logs\RegistryBackup-2026-09-27-21-55-39"

reg import "$BackupFolder\HKLM.reg"
reg import "$BackupFolder\HKCU.reg"
reg import "$BackupFolder\HKCR.reg"
reg import "$BackupFolder\HKU.reg"

Write-Host "Registry restore complete."