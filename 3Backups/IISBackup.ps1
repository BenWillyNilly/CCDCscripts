# IIS Backup Script
# Run as Administrator

$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupRoot = "C:\ProgramData\Backups"

# Create root backup folder if missing
if (-not (Test-Path $BackupRoot)) {
    New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
    Write-Host "Created: $BackupRoot" -ForegroundColor Green
}

# Create timestamped backup folder
$BackupFolder = Join-Path $BackupRoot "IIS_$Date"

New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null

Write-Host "Backup Folder:" $BackupFolder -ForegroundColor Cyan

# Import IIS Module
Import-Module WebAdministration

# Backup IIS Config
Write-Host "Backing up IIS configuration..." -ForegroundColor Yellow

Copy-Item `
    "$env:windir\System32\inetsrv\config" `
    (Join-Path $BackupFolder "Config") `
    -Recurse `
    -Force

# Export Site List
Get-Website |
Select Name, ID, State, PhysicalPath |
Export-Csv `
    (Join-Path $BackupFolder "Sites.csv") `
    -NoTypeInformation

# Export App Pools
Get-ChildItem IIS:\AppPools |
Select Name, State |
Export-Csv `
    (Join-Path $BackupFolder "AppPools.csv") `
    -NoTypeInformation

# Backup Website Content
Write-Host "Backing up website files..." -ForegroundColor Yellow

$SitesFolder = Join-Path $BackupFolder "Sites"

New-Item -Path $SitesFolder -ItemType Directory -Force | Out-Null

foreach ($Site in Get-Website)
{
    $SiteName = $Site.Name -replace '[\\/:*?"<>|]', '_'

    $Path = $Site.PhysicalPath

    if ($Path -like "%SystemDrive%*") {
        $Path = $Path.Replace("%SystemDrive%", $env:SystemDrive)
    }

    if (Test-Path $Path)
    {
        $Destination = Join-Path $SitesFolder $SiteName

        Write-Host "Backing up: $SiteName"

        Copy-Item `
            -Path $Path `
            -Destination $Destination `
            -Recurse `
            -Force `
            -ErrorAction Continue
    }
    else
    {
        Write-Warning "Path not found: $Path"
    }
}

# Optional IIS Native Backup
Write-Host "Creating IIS native backup..." -ForegroundColor Yellow

$appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

if (Test-Path $appcmd)
{
    & $appcmd add backup "IIS_$Date"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " IIS Backup Completed"
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Backup Location:"
Write-Host $BackupFolder -ForegroundColor Cyan