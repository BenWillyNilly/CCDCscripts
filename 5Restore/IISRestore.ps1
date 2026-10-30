# IIS Restore Script
# Run as Administrator

Import-Module WebAdministration

$BackupBase = "C:\ProgramData\Backups"

Clear-Host

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Available IIS Backups"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

Get-ChildItem $BackupBase -Directory |
Sort-Object Name |
Select-Object Name |
Format-Table -AutoSize

Write-Host ""

$BackupFolder = Read-Host "Enter backup folder name"

$BackupRoot = Join-Path $BackupBase $BackupFolder

if (-not (Test-Path $BackupRoot))
{
    Write-Host ""
    Write-Host "Backup folder not found." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Stopping IIS..." -ForegroundColor Yellow

iisreset /stop

# =====================================================
# Restore Config Files
# =====================================================

if (Test-Path "$BackupRoot\Config")
{
    Write-Host ""
    Write-Host "Restoring IIS Configuration Files..." -ForegroundColor Yellow

    Copy-Item `
        "$BackupRoot\Config\*" `
        "$env:WinDir\System32\inetsrv\config" `
        -Recurse `
        -Force
}

# =====================================================
# Restore Native IIS Backup
# =====================================================

$BackupName = $BackupFolder.Replace("IIS_","")

$appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

if (Test-Path $appcmd)
{
    Write-Host ""
    Write-Host "Restoring IIS Native Backup..." -ForegroundColor Yellow

    & $appcmd restore backup "IIS_$BackupName"
}

# =====================================================
# Restore Website Files
# =====================================================

Write-Host ""
Write-Host "Restoring Website Content..." -ForegroundColor Yellow

if (Test-Path "$BackupRoot\Sites")
{
    foreach ($SiteBackup in Get-ChildItem "$BackupRoot\Sites" -Directory)
    {
        $SiteName = $SiteBackup.Name

        Write-Host ""
        Write-Host "Restoring Site: $SiteName" -ForegroundColor Cyan

        $Site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue

        if (-not $Site)
        {
            Write-Warning "Site not found in IIS. Skipping."
            continue
        }

        $PhysicalPath = $Site.PhysicalPath

        if ($PhysicalPath -like "%SystemDrive%*")
        {
            $PhysicalPath = $PhysicalPath.Replace(
                "%SystemDrive%",
                $env:SystemDrive
            )
        }

        Write-Host "Target Path: $PhysicalPath"

        # Create folder if missing
        if (-not (Test-Path $PhysicalPath))
        {
            New-Item `
                -Path $PhysicalPath `
                -ItemType Directory `
                -Force | Out-Null
        }

        # Remove everything currently in site
        Write-Host "Removing existing files..."

        Get-ChildItem `
            $PhysicalPath `
            -Force `
            -ErrorAction SilentlyContinue |
        Remove-Item `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue

        # Restore backup files
        Write-Host "Copying backup files..."

        Copy-Item `
            "$($SiteBackup.FullName)\*" `
            $PhysicalPath `
            -Recurse `
            -Force

        Write-Host "Restore complete." -ForegroundColor Green
    }
}

# =====================================================
# Start IIS
# =====================================================

Write-Host ""
Write-Host "Starting IIS..." -ForegroundColor Yellow

iisreset /start

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Restore Completed Successfully"
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Restored From:" -ForegroundColor Green
Write-Host $BackupRoot