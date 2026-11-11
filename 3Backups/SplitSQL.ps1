#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Interactive backup / restore for a local SQL Server (default instance)
  plus its related Windows config (firewall, SMB shares, SOP files).

.USAGE
  Interactive menu:      .\SqlBackupRestore.ps1
  Unattended backup:     .\SqlBackupRestore.ps1 -Action Backup     (for Task Scheduler)

  If scripts are blocked:
  powershell -ExecutionPolicy Bypass -File .\SqlBackupRestore.ps1

  Run it as an account that is a SQL Server sysadmin (Windows auth is used).
#>
[CmdletBinding()]
param(
    [ValidateSet('Backup', 'Restore')]
    [string]$Action
)

# ---------------------------- CONFIG (edit these) ----------------------------
$BackupRoot        = 'C:\Backups'                  # where backup sets are stored
$SopPath           = 'C:\SOPs'                     # folder holding the SOP files / SMB share
$SqlServer         = 'localhost'                   # default instance
$SqlServiceAccount = 'NT SERVICE\MSSQLSERVER'      # must be able to write to $BackupRoot
$KeepBackups       = 7                             # newest N backup sets are kept
$SystemDbs         = @('master', 'model', 'msdb', 'tempdb')   # backed up, never auto-restored
# -----------------------------------------------------------------------------

# Generates one CREATE LOGIN statement per SQL login (keeps password hash + SID)
$LoginQuery = @'
SELECT 'IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N''' + REPLACE(name, '''', '''''') + ''') CREATE LOGIN ' + QUOTENAME(name) + ' WITH PASSWORD = ' + CONVERT(varchar(max), password_hash, 1) + ' HASHED, SID = ' + CONVERT(varchar(max), sid, 1) + ', CHECK_POLICY = OFF;'
FROM sys.sql_logins
WHERE name NOT LIKE '##%' AND name <> 'sa';
'@

$script:LogFile = $null
$script:LastBackupOk = $false

# ------------------------------ find sqlcmd ----------------------------------
$SqlCmd = (Get-Command sqlcmd.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $SqlCmd) {
    $SqlCmd = Get-ChildItem 'C:\Program Files\Microsoft SQL Server' -Recurse -Filter sqlcmd.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $SqlCmd) {
    Write-Host 'sqlcmd.exe was not found. Install the SQL command line tools or SSMS, then try again.' -ForegroundColor Red
    exit 1
}

# ------------------------------- helpers -------------------------------------
function Write-Log {
    param([string]$Message, [string]$Color = 'Gray')
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line -ForegroundColor $Color
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line }
}

# Runs T-SQL through sqlcmd. Returns output lines; throws if SQL reports an error.
function Invoke-Sql {
    param([string]$Query)
    $tmp = Join-Path $env:TEMP ('sql_{0}.sql' -f [guid]::NewGuid())
    "SET NOCOUNT ON;`r`n$Query" | Set-Content -Path $tmp -Encoding Unicode
    try {
        $out  = & $SqlCmd -S $SqlServer -E -b -h -1 -y 0 -i $tmp 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) { throw (($out | Out-String).Trim()) }
    return @($out | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
}

# Creates the backup folder; the SQL service account needs write access to it.
function Initialize-BackupRoot {
    if (-not (Test-Path $BackupRoot)) {
        New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
        # Admins + SYSTEM + SQL service only (backups contain password hashes)
        icacls $BackupRoot /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' "${SqlServiceAccount}:(OI)(CI)M" | Out-Null
    }
    else {
        icacls $BackupRoot /grant "${SqlServiceAccount}:(OI)(CI)M" | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: could not set permissions for $SqlServiceAccount on $BackupRoot. Database backups may fail with 'access denied'." -ForegroundColor Yellow
    }
}

# --------------------------------- BACKUP ------------------------------------
function Start-Backup {
    param([string]$Label = '', [switch]$SkipPrune)

    Initialize-BackupRoot
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if ($Label) { $stamp = "${stamp}_$Label" }
    $dest = Join-Path $BackupRoot $stamp
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $script:LogFile = Join-Path $dest 'backup.log'
    $failures = @()

    Write-Log "Backup started -> $dest" Cyan

    # 1. Databases (all online databases except tempdb), each verified after backup
    $dbs = @()
    try {
        $dbs = Invoke-Sql "SELECT name FROM sys.databases WHERE name <> 'tempdb' AND state_desc = 'ONLINE' ORDER BY name;"
    }
    catch {
        Write-Log "Cannot list databases: $_" Red
        $failures += 'database list'
    }
    foreach ($db in $dbs) {
        $dbq  = $db.Replace(']', ']]')
        $file = (Join-Path $dest "$db.bak").Replace("'", "''")
        try {
            Invoke-Sql "BACKUP DATABASE [$dbq] TO DISK = N'$file' WITH INIT, CHECKSUM;" | Out-Null
            Invoke-Sql "RESTORE VERIFYONLY FROM DISK = N'$file' WITH CHECKSUM;" | Out-Null
            Write-Log "Database OK: $db" Green
        }
        catch {
            Write-Log "Database FAILED: $db - $_" Red
            $failures += $db
        }
    }

    # 2. SQL settings and logins
    try {
        Invoke-Sql "SELECT name + ' = ' + CAST(value_in_use AS varchar(20)) FROM sys.configurations ORDER BY name;" |
            Out-File -FilePath (Join-Path $dest 'sql-config.txt') -Encoding ASCII
        Invoke-Sql $LoginQuery |
            Out-File -FilePath (Join-Path $dest 'logins.sql') -Encoding ASCII
        Write-Log 'SQL settings and logins saved' Green
    }
    catch {
        Write-Log "SQL settings/logins FAILED: $_" Red
        $failures += 'sql settings'
    }

    # 3. SQL network config (reference copy) and original setup config
    try {
        $inst = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction Stop).MSSQLSERVER
        reg export "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\$inst\MSSQLServer\SuperSocketNetLib" (Join-Path $dest 'sql-network.reg') /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'reg export failed' }
        $ini = Get-ChildItem 'C:\Program Files\Microsoft SQL Server\150\Setup Bootstrap\Log' -Recurse -Filter ConfigurationFile.ini -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($ini) { Copy-Item $ini.FullName (Join-Path $dest 'ConfigurationFile.ini') }
        Write-Log 'SQL network/setup config saved' Green
    }
    catch {
        Write-Log "SQL network config skipped: $_" Yellow
    }

    # 4. Windows config: firewall, SMB shares, policy, users and groups
    try {
        netsh advfirewall export (Join-Path $dest 'firewall.wfw') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'firewall export failed' }
        reg export 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares' (Join-Path $dest 'smb-shares.reg') /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SMB share export failed' }
        Get-SmbShare | Select-Object Name, Path, Description |
            Export-Csv (Join-Path $dest 'smb-shares.csv') -NoTypeInformation
        secedit /export /cfg (Join-Path $dest 'secpol.inf') | Out-Null
        Get-LocalUser | Select-Object Name, Enabled, LastLogon |
            Export-Csv (Join-Path $dest 'local-users.csv') -NoTypeInformation
        foreach ($g in 'Administrators', 'Remote Desktop Users') {
            Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass |
                Export-Csv (Join-Path $dest ('group-{0}.csv' -f ($g -replace ' ', '-'))) -NoTypeInformation
        }
        Write-Log 'Windows config saved (firewall, SMB shares, policy, users/groups)' Green
    }
    catch {
        Write-Log "Windows config FAILED: $_" Red
        $failures += 'windows config'
    }

    # 5. SOP files and their permissions
    if (Test-Path $SopPath) {
        try {
            Copy-Item $SopPath (Join-Path $dest 'SOPs') -Recurse -Force
            icacls $SopPath /save (Join-Path $dest 'sop-acl.txt') /t /c | Out-Null
            Write-Log "SOP files saved from $SopPath" Green
        }
        catch {
            Write-Log "SOP backup FAILED: $_" Red
            $failures += 'SOPs'
        }
    }
    else {
        Write-Log "SOP path not found: $SopPath (edit `$SopPath at the top of the script)" Yellow
    }

    # Summary + retention (only prune when this backup was clean)
    if ($failures.Count -eq 0) {
        $script:LastBackupOk = $true
        Write-Log 'Backup completed with no errors.' Green
        if (-not $SkipPrune) {
            Get-ChildItem $BackupRoot -Directory | Sort-Object Name -Descending |
                Select-Object -Skip $KeepBackups | ForEach-Object {
                    Write-Log "Removing old backup set: $($_.Name)" DarkGray
                    Remove-Item $_.FullName -Recurse -Force
                }
        }
    }
    else {
        $script:LastBackupOk = $false
        Write-Log ('Backup finished WITH ERRORS: ' + ($failures -join ', ')) Red
        Write-Log 'Old backups were NOT pruned.' Yellow
    }
}

# --------------------------------- RESTORE -----------------------------------
function Restore-Databases {
    param([string]$Folder)

    $baks = @(Get-ChildItem $Folder -Filter *.bak -ErrorAction SilentlyContinue |
        Where-Object { $SystemDbs -notcontains $_.BaseName } | Sort-Object Name)
    if ($baks.Count -eq 0) {
        Write-Log 'No user database backups (.bak) found in this backup set.' Yellow
        return
    }

    Write-Host ''
    for ($i = 0; $i -lt $baks.Count; $i++) {
        Write-Host ('  [{0}] {1}  ({2:N1} MB)' -f ($i + 1), $baks[$i].BaseName, ($baks[$i].Length / 1MB))
    }
    Write-Host '  (System databases master/model/msdb are not restored by this script.)' -ForegroundColor DarkGray
    $pick = Read-Host 'Database number, A for all, or Enter to skip'

    if ($pick -match '^[aA]$') { $selected = $baks }
    elseif ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $baks.Count) { $selected = @($baks[[int]$pick - 1]) }
    else { Write-Log 'Database restore skipped.' Yellow; return }

    foreach ($b in $selected) {
        $db   = $b.BaseName
        $dbq  = $db.Replace(']', ']]')
        $dbl  = $db.Replace("'", "''")
        $file = $b.FullName.Replace("'", "''")
        $sql = @"
IF DB_ID(N'$dbl') IS NOT NULL ALTER DATABASE [$dbq] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
RESTORE DATABASE [$dbq] FROM DISK = N'$file' WITH REPLACE, RECOVERY, CHECKSUM;
ALTER DATABASE [$dbq] SET MULTI_USER;
"@
        try {
            Invoke-Sql $sql | Out-Null
            Write-Log "Database restored: $db" Green
        }
        catch {
            Write-Log "Database restore FAILED: $db - $_" Red
            try {
                Invoke-Sql "IF DB_ID(N'$dbl') IS NOT NULL AND DATABASEPROPERTYEX(N'$dbl', 'Status') = 'ONLINE' ALTER DATABASE [$dbq] SET MULTI_USER;" | Out-Null
            }
            catch { }
        }
    }
}

function Restore-Logins {
    param([string]$Folder)
    $file = Join-Path $Folder 'logins.sql'
    if (-not (Test-Path $file)) { Write-Log 'No logins.sql in this backup set.' Yellow; return }
    $sql = Get-Content $file -Raw
    if ([string]::IsNullOrWhiteSpace($sql)) { Write-Log 'logins.sql is empty (no SQL logins were saved).' Yellow; return }
    try {
        Invoke-Sql $sql | Out-Null
        Write-Log 'SQL logins restored (logins that already exist were left unchanged).' Green
    }
    catch {
        Write-Log "Login restore FAILED: $_" Red
    }
}

function Restore-Sops {
    param([string]$Folder)
    $src = Join-Path $Folder 'SOPs'
    if (-not (Test-Path $src)) { Write-Log 'No SOPs folder in this backup set.' Yellow; return }
    try {
        New-Item -ItemType Directory -Path $SopPath -Force | Out-Null
        Copy-Item (Join-Path $src '*') $SopPath -Recurse -Force
        $acl = Join-Path $Folder 'sop-acl.txt'
        if (Test-Path $acl) {
            # icacls /save stores paths relative to the parent folder, so restore against the parent
            icacls (Split-Path $SopPath -Parent) /restore $acl /c | Out-Null
        }
        Write-Log "SOP files restored to $SopPath" Green
    }
    catch {
        Write-Log "SOP restore FAILED: $_" Red
    }
}

function Restore-Firewall {
    param([string]$Folder)
    $file = Join-Path $Folder 'firewall.wfw'
    if (-not (Test-Path $file)) { Write-Log 'No firewall.wfw in this backup set.' Yellow; return }
    netsh advfirewall import $file | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Log 'Firewall rules restored (current rules were replaced).' Green }
    else { Write-Log 'Firewall import FAILED.' Red }
}

function Restore-SmbShares {
    param([string]$Folder)
    $file = Join-Path $Folder 'smb-shares.reg'
    if (-not (Test-Path $file)) { Write-Log 'No smb-shares.reg in this backup set.' Yellow; return }
    try {
        reg import $file | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'reg import failed' }
        $deps = @(Get-Service LanmanServer -DependentServices | Where-Object { $_.Status -eq 'Running' })
        Restart-Service LanmanServer -Force
        foreach ($d in $deps) { Start-Service $d.Name -ErrorAction SilentlyContinue }
        Write-Log 'SMB share definitions restored; Server service restarted.' Green
    }
    catch {
        Write-Log "SMB share restore FAILED: $_" Red
    }
}

function Start-Restore {
    $sets = @(Get-ChildItem $BackupRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if ($sets.Count -eq 0) {
        Write-Host "No backups found in $BackupRoot" -ForegroundColor Yellow
        return
    }

    Write-Host "`nAvailable backups (newest first):"
    for ($i = 0; $i -lt $sets.Count; $i++) {
        $n = @(Get-ChildItem $sets[$i].FullName -Filter *.bak -ErrorAction SilentlyContinue).Count
        Write-Host ('  [{0}] {1}   ({2} database file(s))' -f ($i + 1), $sets[$i].Name, $n)
    }
    $pick = Read-Host 'Backup number (Enter to cancel)'
    if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $sets.Count) {
        Write-Host 'Cancelled.'
        return
    }
    $chosen = $sets[[int]$pick - 1]
    $folder = $chosen.FullName

    Write-Host "`nWhat do you want to restore from $($chosen.Name)?"
    Write-Host '  [1] Databases'
    Write-Host '  [2] SQL logins'
    Write-Host '  [3] SOP files and permissions'
    Write-Host '  [4] Firewall rules'
    Write-Host '  [5] SMB share definitions'
    Write-Host '  [6] Everything above'
    $what = Read-Host 'Choice (Enter to cancel)'
    if ($what -notin '1', '2', '3', '4', '5', '6') { Write-Host 'Cancelled.'; return }

    $warnings = @{
        '1' = 'Selected databases will be OVERWRITTEN and all users disconnected.'
        '2' = 'Missing SQL logins will be re-created. Existing logins are not changed.'
        '3' = 'SOP files will be copied back over the current ones and permissions reset.'
        '4' = 'ALL current Windows Firewall rules will be REPLACED by the saved ones.'
        '5' = 'SMB share definitions will be replaced and the Server service restarted (brief SMB outage).'
        '6' = 'Databases, firewall rules, SOP files, logins and shares will be overwritten.'
    }
    Write-Host "`nWARNING: $($warnings[$what])" -ForegroundColor Yellow
    if ((Read-Host 'Type YES to continue') -ne 'YES') { Write-Host 'Cancelled.'; return }

    $safety = Read-Host 'Take a safety backup of the CURRENT state first? (Y/n)'
    if ($safety -notmatch '^[nN]') {
        Start-Backup -Label 'pre-restore' -SkipPrune
        if (-not $script:LastBackupOk) {
            $go = Read-Host 'The safety backup had errors. Continue anyway? (y/N)'
            if ($go -notmatch '^[yY]') { Write-Host 'Cancelled.'; return }
        }
    }

    $script:LogFile = Join-Path $BackupRoot 'restore.log'
    Write-Log "Restore started from $($chosen.Name)" Cyan

    if ($what -in '1', '6') { Restore-Databases -Folder $folder }
    if ($what -in '2', '6') { Restore-Logins -Folder $folder }
    if ($what -in '3', '6') { Restore-Sops -Folder $folder }
    if ($what -in '4', '6') { Restore-Firewall -Folder $folder }
    if ($what -in '5', '6') { Restore-SmbShares -Folder $folder }

    Write-Log 'Restore finished. Re-test SMB, RDP and the SQL login from another machine.' Cyan
}

# ---------------------------------- MAIN -------------------------------------
try {
    Invoke-Sql 'SELECT @@VERSION;' | Out-Null
}
catch {
    Write-Host "Warning: cannot connect to SQL Server at '$SqlServer' with Windows authentication." -ForegroundColor Yellow
    Write-Host "         Database steps will fail until this is fixed. Details: $_" -ForegroundColor Yellow
}

if ($Action -eq 'Backup') {
    Start-Backup
    if ($script:LastBackupOk) { exit 0 } else { exit 1 }
}
if ($Action -eq 'Restore') {
    Start-Restore
    exit 0
}

while ($true) {
    Write-Host ''
    Write-Host '=====================================' -ForegroundColor Cyan
    Write-Host '   SQL Server Backup / Restore'         -ForegroundColor Cyan
    Write-Host '=====================================' -ForegroundColor Cyan
    Write-Host "   Backups: $BackupRoot"                -ForegroundColor DarkGray
    Write-Host '  [1] Backup now'
    Write-Host '  [2] Restore from a backup'
    Write-Host '  [3] Quit'
    $choice = Read-Host 'Choose 1, 2 or 3'
    switch ($choice) {
        '1' { Start-Backup }
        '2' { Start-Restore }
        '3' { exit 0 }
        default { Write-Host 'Please enter 1, 2 or 3.' -ForegroundColor Yellow }
    }
}
