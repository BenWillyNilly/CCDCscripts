#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Restores an IIS backup made by IISBackup.ps1 with exact NTFS permissions.

.DESCRIPTION
    * Stops IIS, restores config + every content root, then starts IIS (always,
      even if something fails midway).
    * Uses robocopy /MIR /COPYALL /B /SECFIX so files, ACLs, owners and
      timestamps match the backup exactly. /SECFIX matters: without it robocopy
      skips files whose data is unchanged and never repairs their permissions.
    * Re-applies each root folder's ACL and owner (robocopy does not reliably
      do this for the top-level folder).
    * Verifies every restored ACL against the backup and reports mismatches.
    * Extra files not in the backup are removed (mirror), same as the old
      "delete everything first" behaviour.

.PARAMETER BackupName
    Folder name under BackupBase (e.g. IIS_20261102_101500). Prompts if omitted.

.PARAMETER Force
    Skip the confirmation prompt.

.PARAMETER SkipVerify
    Skip the post-restore ACL comparison.
#>
[CmdletBinding()]
param(
    [string]$BackupBase = "C:\ProgramData\Backups",
    [string]$BackupName,
    [switch]$Force,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

# =====================================================
# Helpers
# =====================================================

function Invoke-RobocopyMirror {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile
    )

    $src = $Source.TrimEnd('\')
    $dst = $Destination.TrimEnd('\')

    $rcArgs = @(
        $src, $dst,
        '/MIR', '/COPYALL', '/B', '/DCOPY:DAT', '/SECFIX', '/TIMFIX', '/XJ',
        '/R:1', '/W:1', '/NP', '/NFL', '/NDL', "/LOG+:$LogFile"
    )

    & robocopy.exe @rcArgs | Out-Null
    $rc = $LASTEXITCODE

    if ($rc -ge 8) {
        Write-Warning "Robocopy reported failures (exit $rc) for $dst. See $LogFile"
        return $false
    }
    return $true
}

function Get-Sddl {
    param([string]$Path, [string]$Sections)
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($Sections)
}

function Set-RootAcl {
    param([string]$Path, [string]$AccessSddl, [string]$OwnerSid)

    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetSecurityDescriptorSddlForm($AccessSddl, 'Access')
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        Write-Warning "Could not set ACL on root '$Path': $($_.Exception.Message)"
    }

    if ($OwnerSid) {
        & icacls.exe $Path /setowner "*$OwnerSid" | Out-Null
    }
}

function Compare-TreeAcl {
    param([string]$Reference, [string]$Target)

    $Reference = $Reference.TrimEnd('\')
    $Target    = $Target.TrimEnd('\')
    $problems  = New-Object System.Collections.Generic.List[string]

    Get-ChildItem -LiteralPath $Reference -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $rel   = $_.FullName.Substring($Reference.Length)
        $other = $Target + $rel

        if (-not (Test-Path -LiteralPath $other)) {
            $problems.Add("MISSING   $rel")
            return
        }

        try {
            $a = Get-Sddl $_.FullName 'Owner,Access'
            $b = Get-Sddl $other      'Owner,Access'
            if ($a -ne $b) { $problems.Add("ACL DIFF  $rel") }
        }
        catch {
            $problems.Add("UNREADABLE $rel : $($_.Exception.Message)")
        }
    }

    return @($problems)
}

# =====================================================
# Pick a backup
# =====================================================

Import-Module WebAdministration

if (-not $BackupName) {
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
    $BackupName = Read-Host "Enter backup folder name"
}

$BackupRoot   = Join-Path $BackupBase $BackupName
$ManifestPath = Join-Path $BackupRoot "manifest.json"

if (-not (Test-Path $BackupRoot)) {
    Write-Host "Backup folder not found." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ManifestPath)) {
    Write-Host "No manifest.json in this backup." -ForegroundColor Red
    Write-Host "It was made with the old backup script, which did not preserve permissions." -ForegroundColor Red
    Write-Host "Create a new backup with the updated IISBackup.ps1 and restore from that." -ForegroundColor Red
    exit 1
}

$Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$LogFile  = Join-Path $BackupRoot ("Restore_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$Appcmd   = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

Write-Host ""
Write-Host "Backup:   $BackupName  (taken $($Manifest.Created) on $($Manifest.ComputerName))" -ForegroundColor Cyan
Write-Host "This will REPLACE the contents of:" -ForegroundColor Yellow
Write-Host "  $($Manifest.ConfigRoot.Source)"
foreach ($r in @($Manifest.ContentRoots)) { Write-Host "  $($r.Source)" }

if (-not $Force) {
    Write-Host ""
    $answer = Read-Host "Type YES to continue"
    if ($answer -ne 'YES') { Write-Host "Cancelled."; exit 0 }
}

$AllProblems = New-Object System.Collections.Generic.List[string]

# =====================================================
# Restore (IIS always restarted in finally)
# =====================================================

try {
    Write-Host ""
    Write-Host "Stopping IIS..." -ForegroundColor Yellow
    iisreset /stop

    # -------------------------------------------------
    # Config
    # -------------------------------------------------
    $ConfigBackup = Join-Path $BackupRoot "Config"
    $ConfigTarget = $Manifest.ConfigRoot.Source

    if (Test-Path $ConfigBackup) {
        Write-Host ""
        Write-Host "Restoring IIS configuration..." -ForegroundColor Yellow

        [void](Invoke-RobocopyMirror -Source $ConfigBackup -Destination $ConfigTarget -LogFile $LogFile)
        Set-RootAcl -Path $ConfigTarget `
                    -AccessSddl $Manifest.ConfigRoot.RootAccessSddl `
                    -OwnerSid   $Manifest.ConfigRoot.RootOwnerSid

        if (-not $SkipVerify) {
            foreach ($d in @(Compare-TreeAcl -Reference $ConfigBackup -Target $ConfigTarget)) {
                $AllProblems.Add("[Config] $d")
            }
        }
    }
    elseif (Test-Path $Appcmd) {
        # Fallback only: native backup lives in inetsrv\backup, not in this folder
        Write-Host ""
        Write-Host "No Config folder in backup - falling back to appcmd native restore..." -ForegroundColor Yellow
        & $Appcmd restore backup ($BackupName)
    }

    # -------------------------------------------------
    # Content roots
    # -------------------------------------------------
    foreach ($r in @($Manifest.ContentRoots)) {

        $Source = Join-Path $BackupRoot ("Content\" + $r.BackupSubfolder)
        $Target = $r.Source

        Write-Host ""
        Write-Host "Restoring: $Target" -ForegroundColor Cyan

        if (-not (Test-Path $Source)) {
            Write-Warning "Backup data missing: $Source. Skipping."
            continue
        }
        if ($Target -match '^[A-Za-z]:\\?$') {
            Write-Warning "Refusing to mirror onto a drive root: $Target"
            continue
        }

        if (-not (Test-Path -LiteralPath $Target)) {
            New-Item -Path $Target -ItemType Directory -Force | Out-Null
        }

        [void](Invoke-RobocopyMirror -Source $Source -Destination $Target -LogFile $LogFile)

        # Top-level folder ACL + owner (robocopy won't reliably set these)
        Set-RootAcl -Path $Target -AccessSddl $r.RootAccessSddl -OwnerSid $r.RootOwnerSid

        if (-not $SkipVerify) {
            $now = Get-Sddl $Target 'Access'
            if ($now -ne $r.RootAccessSddl) { $AllProblems.Add("[$Target] ROOT ACL DIFF") }

            foreach ($d in @(Compare-TreeAcl -Reference $Source -Target $Target)) {
                $AllProblems.Add("[$Target] $d")
            }
        }

        Write-Host "Restore complete." -ForegroundColor Green
    }
}
finally {
    Write-Host ""
    Write-Host "Starting IIS..." -ForegroundColor Yellow
    iisreset /start
}

# =====================================================
# Summary
# =====================================================

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Restore Finished"
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Restored From:" -ForegroundColor Green
Write-Host $BackupRoot
Write-Host "Log: $LogFile"

if ($SkipVerify) {
    Write-Host "ACL verification skipped." -ForegroundColor DarkYellow
}
elseif ($AllProblems.Count -eq 0) {
    Write-Host "ACL verification: every restored file and folder matches the backup." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "ACL verification found $($AllProblems.Count) problem(s):" -ForegroundColor Red
    $AllProblems | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $AllProblems | Set-Content (Join-Path $BackupRoot "RestoreAclProblems.txt")
    Write-Host "Full list: $(Join-Path $BackupRoot 'RestoreAclProblems.txt')" -ForegroundColor Red
    exit 1
}
