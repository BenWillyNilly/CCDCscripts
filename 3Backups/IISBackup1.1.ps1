#Requires -RunAsAdministrator
<#
.SYNOPSIS
    IIS backup that preserves NTFS permissions, owners, and timestamps.

.DESCRIPTION
    Backs up:
      * IIS configuration (inetsrv\config)
      * Every content root: site roots, application paths, virtual directories
        (found through appcmd, so nested apps/vdirs on other drives are included)
      * Any extra folders passed with -ExtraPath (log dirs, app data dirs, etc.)
      * A manifest.json describing sites, bindings, app pools, and root-folder ACLs
      * icacls ACL dumps (ACLs\*.acl) as an independent safety net
      * An appcmd native backup

    Files are copied with robocopy /COPYALL /B so ACLs, owner, and attributes are
    preserved exactly. Copy-Item does NOT do this: copied files simply inherit
    from the destination folder, which is how a .log file loses its write ACE.

    After copying, every ACL in the backup is compared to its source.

.PARAMETER BackupRoot
    Where timestamped backups are stored.

.PARAMETER ExtraPath
    Additional folders to include (e.g. C:\inetpub\logs, an app's data folder).

.PARAMETER SkipVerify
    Skip the ACL comparison pass (faster on very large sites).
#>
[CmdletBinding()]
param(
    [string]$BackupRoot = "C:\ProgramData\Backups",
    [string[]]$ExtraPath = @(),
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

# =====================================================
# Helpers
# =====================================================

function Invoke-Robocopy {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile
    )

    $src = $Source.TrimEnd('\')
    $dst = $Destination.TrimEnd('\')

    # /COPYALL = Data, Attributes, Timestamps, Security (ACL), Owner, aUditing
    # /B       = backup mode, bypasses ACLs that would deny us access
    # /SECFIX  = fix security even on files robocopy would otherwise skip
    # /XJ      = do not follow junctions (avoids loops)
    $rcArgs = @(
        $src, $dst,
        '/E', '/COPYALL', '/B', '/DCOPY:DAT', '/SECFIX', '/TIMFIX', '/XJ',
        '/R:1', '/W:1', '/NP', '/NFL', '/NDL', "/LOG+:$LogFile"
    )

    & robocopy.exe @rcArgs | Out-Null
    $rc = $LASTEXITCODE

    # Robocopy: 0-7 = success (bit flags), 8+ = at least one failure
    if ($rc -ge 8) {
        Write-Warning "Robocopy reported failures (exit $rc) for $src. See $LogFile"
        return $false
    }
    return $true
}

function Get-Sddl {
    param([string]$Path, [string]$Sections)
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($Sections)
}

# Compares owner + ACL of every item under Reference to the same relative item under Target.
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
# Setup
# =====================================================

Import-Module WebAdministration

$Date         = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupFolder = Join-Path $BackupRoot "IIS_$Date"
$LogFile      = Join-Path $BackupFolder "Backup.log"
$AclFolder    = Join-Path $BackupFolder "ACLs"
$Appcmd       = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
New-Item -Path $AclFolder    -ItemType Directory -Force | Out-Null

Write-Host "Backup Folder: $BackupFolder" -ForegroundColor Cyan

$AllProblems = New-Object System.Collections.Generic.List[string]

# =====================================================
# IIS Configuration
# =====================================================

Write-Host ""
Write-Host "Backing up IIS configuration..." -ForegroundColor Yellow

$ConfigSource = "$env:windir\System32\inetsrv\config"
$ConfigBackup = Join-Path $BackupFolder "Config"

New-Item -Path $ConfigBackup -ItemType Directory -Force | Out-Null
[void](Invoke-Robocopy -Source $ConfigSource -Destination $ConfigBackup -LogFile $LogFile)

$ConfigAcl  = Get-Acl -LiteralPath $ConfigSource
$ConfigRoot = [ordered]@{
    Source         = $ConfigSource
    RootAccessSddl = $ConfigAcl.GetSecurityDescriptorSddlForm('Access')
    RootOwnerSid   = $ConfigAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
}

if (-not $SkipVerify) {
    $diff = @(Compare-TreeAcl -Reference $ConfigSource -Target $ConfigBackup)
    foreach ($d in $diff) { $AllProblems.Add("[Config] $d") }
}

# =====================================================
# Sites / App Pools metadata
# =====================================================

Write-Host "Collecting site and app pool details..." -ForegroundColor Yellow

$SiteInfo = @(
    foreach ($s in Get-Website) {
        [ordered]@{
            Name         = $s.Name
            Id           = $s.Id
            State        = [string]$s.State
            PhysicalPath = $s.PhysicalPath
            AppPool      = $s.ApplicationPool
            Bindings     = @($s.Bindings.Collection | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" })
        }
    }
)

$PoolInfo = @(
    foreach ($p in Get-ChildItem IIS:\AppPools) {
        [ordered]@{
            Name         = $p.Name
            State        = [string]$p.State
            IdentityType = [string]$p.processModel.identityType
            UserName     = $p.processModel.userName
        }
    }
)

# Friendly CSVs (same as before)
Get-Website | Select-Object Name, ID, State, PhysicalPath |
    Export-Csv (Join-Path $BackupFolder "Sites.csv") -NoTypeInformation
Get-ChildItem IIS:\AppPools | Select-Object Name, State |
    Export-Csv (Join-Path $BackupFolder "AppPools.csv") -NoTypeInformation

# =====================================================
# Find every content root
# =====================================================

$Candidates = New-Object System.Collections.Generic.List[string]

foreach ($s in Get-Website) {
    $Candidates.Add($s.PhysicalPath)

    # All vdirs for the site, including those inside applications
    if (Test-Path $Appcmd) {
        $vdirs = & $Appcmd list vdir "/site.name:$($s.Name)" "/text:physicalPath"
        foreach ($v in $vdirs) { if ($v) { $Candidates.Add($v.Trim()) } }
    }
}

foreach ($e in $ExtraPath) { $Candidates.Add($e) }

$Expanded = $Candidates |
    ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') } |
    Where-Object { $_ } |
    Sort-Object -Unique

# Drop paths that live inside another root we already copy
$Roots = @()
foreach ($p in ($Expanded | Sort-Object Length)) {

    if ($p -match '^[A-Za-z]:$') {
        Write-Warning "Skipping drive root '$p' (too broad to back up safely)."
        continue
    }
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Warning "Path not found: $p"
        continue
    }

    $covered = $Roots | Where-Object { $p.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }
    if (-not $covered) { $Roots += $p }
}

# =====================================================
# Back up content roots
# =====================================================

Write-Host ""
Write-Host "Backing up website content (with permissions)..." -ForegroundColor Yellow

$ContentFolder = Join-Path $BackupFolder "Content"
New-Item -Path $ContentFolder -ItemType Directory -Force | Out-Null

$ContentRoots = @()
$i = 0

foreach ($p in $Roots) {
    $i++
    $leaf = (Split-Path $p -Leaf) -replace '[\\/:*?"<>|]', '_'
    $sub  = '{0:D2}_{1}' -f $i, $leaf
    $dest = Join-Path $ContentFolder $sub

    Write-Host "  [$i/$($Roots.Count)] $p"

    New-Item -Path $dest -ItemType Directory -Force | Out-Null
    [void](Invoke-Robocopy -Source $p -Destination $dest -LogFile $LogFile)

    # Safety-net ACL dump (restorable with: icacls <path> /restore <file>)
    & icacls.exe "$p\*" /save (Join-Path $AclFolder "$sub.acl") /t /c /q | Out-Null

    $acl = Get-Acl -LiteralPath $p
    $ContentRoots += [ordered]@{
        Source          = $p
        BackupSubfolder = $sub
        RootAccessSddl  = $acl.GetSecurityDescriptorSddlForm('Access')
        RootOwnerSid    = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    }

    if (-not $SkipVerify) {
        $diff = @(Compare-TreeAcl -Reference $p -Target $dest)
        foreach ($d in $diff) { $AllProblems.Add("[$sub] $d") }
    }
}

# =====================================================
# Manifest
# =====================================================

[ordered]@{
    Version      = 2
    Created      = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    ConfigRoot   = $ConfigRoot
    ContentRoots = $ContentRoots
    Sites        = $SiteInfo
    AppPools     = $PoolInfo
} | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $BackupFolder "manifest.json") -Encoding UTF8

# =====================================================
# IIS native backup
# =====================================================

if (Test-Path $Appcmd) {
    Write-Host ""
    Write-Host "Creating IIS native backup..." -ForegroundColor Yellow
    & $Appcmd add backup "IIS_$Date" | Out-Null
}

# =====================================================
# Summary
# =====================================================

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " IIS Backup Completed"
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Backup Location:"
Write-Host $BackupFolder -ForegroundColor Cyan

if ($SkipVerify) {
    Write-Host "ACL verification skipped." -ForegroundColor DarkYellow
}
elseif ($AllProblems.Count -eq 0) {
    Write-Host "ACL verification: all permissions in the backup match the source." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "ACL verification found $($AllProblems.Count) problem(s):" -ForegroundColor Red
    $AllProblems | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    if ($AllProblems.Count -gt 25) { Write-Host "  ... see $LogFile" -ForegroundColor Red }
    $AllProblems | Set-Content (Join-Path $BackupFolder "AclProblems.txt")
}
