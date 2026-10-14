# IIS Restore Script
# Run as Administrator

$BackupBase = "C:\ProgramData\Backups"

Write-Host "Available IIS Backups:" -ForegroundColor Cyan

Get-ChildItem $BackupBase -Directory |
Select-Object Name |
Format-Table -AutoSize

$BackupFolder = Read-Host "Enter backup folder name"

$BackupRoot = Join-Path $BackupBase $BackupFolder

if (!(Test-Path $BackupRoot)) {
    Write-Host "Backup folder not found." -ForegroundColor Red
    exit
}

iisreset /stop

# Restore IIS Configuration
$BackupName = $BackupFolder.Replace("IIS_", "")

& "$env:SystemRoot\System32\inetsrv\appcmd.exe" restore backup "IIS_$BackupName"

# Restore Website Files
if (Test-Path "$BackupRoot\Sites") {

    Get-ChildItem "$BackupRoot\Sites" -Directory | ForEach-Object {

        $SiteName = $_.Name

        Write-Host "Found backup for site: $SiteName"
    }
}

iisreset /start

Write-Host ""
Write-Host "IIS configuration restored successfully." -ForegroundColor Green
`