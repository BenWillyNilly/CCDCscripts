# IIS Backup Script
# Run as Administrator

$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupBase = "C:\ProgramData\Backups"

# Create backup root if it doesn't exist
if (!(Test-Path $BackupBase)) {
    New-Item -Path $BackupBase -ItemType Directory -Force | Out-Null
    Write-Host "Created backup directory: $BackupBase"
}

$BackupRoot = Join-Path $BackupBase "IIS_$Date"

New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null

Write-Host "Creating IIS configuration backup..." -ForegroundColor Yellow

# Create IIS Configuration Backup
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup "IIS_$Date"

# Backup IIS Configuration Files
Write-Host "Backing up IIS configuration..." -ForegroundColor Yellow

Copy-Item `
    "$env:WinDir\System32\inetsrv\config" `
    "$BackupRoot\Config" `
    -Recurse `
    -Force

# Import IIS Module
Import-Module WebAdministration

# Backup All IIS Websites
Write-Host "Backing up website content..." -ForegroundColor Yellow

Get-Website | ForEach-Object {

    $SiteName = $_.Name -replace '[\\/:*?"<>|]', '_'
    $PhysicalPath = $_.PhysicalPath.Replace("%SystemDrive%", $env:SystemDrive)

    if (Test-Path $PhysicalPath) {

        $Destination = Join-Path $BackupRoot "Sites\$SiteName"

        Copy-Item `
            $PhysicalPath `
            $Destination `
            -Recurse `
            -Force `
            -ErrorAction Continue

        Write-Host "Backed up site: $SiteName"
    }
}

# Export Site Information
Get-Website |
Select-Object Name, State, PhysicalPath |
Export-Csv "$BackupRoot\Sites.csv" -NoTypeInformation

# Export App Pools
Get-ChildItem IIS:\AppPools |
Select-Object Name, State |
Export-Csv "$BackupRoot\AppPools.csv" -NoTypeInformation

Write-Host ""
Write-Host "Backup Complete" -ForegroundColor Green
Write-Host "Location: $BackupRoot" -ForegroundColor Green