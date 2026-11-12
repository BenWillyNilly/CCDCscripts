#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Defensive tripwire for your OWN machine. Watches for whoami.exe being run
  (Security event 4688), logs who/what ran it, and can kill the shell that ran it.

.USAGE
  .\WhoamiTripwire.ps1 -Install                      alert-only (safe default)
  .\WhoamiTripwire.ps1 -Install -Kill                kill non-interactive shells (reverse shells, WinRM, xp_cmdshell...)
  .\WhoamiTripwire.ps1 -Install -Kill -BlockIP       ...and firewall-block the remote IPs they were using
  .\WhoamiTripwire.ps1 -Install -Kill -IncludeInteractive
        also acts in RDP/console sessions. WARNING: this also hits YOU if you run whoami there.
  .\WhoamiTripwire.ps1 -Uninstall                    remove task, remove TW-Block firewall rules
  .\WhoamiTripwire.ps1 -Run [-Kill ...]              run in this console (good for testing, Ctrl+C to stop)

  Check your event rules before using -Kill / -BlockIP, and fill in $NeverBlock first.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Run,
    [switch]$Kill,
    [switch]$BlockIP,
    [switch]$IncludeInteractive
)

# ---------------------------- CONFIG (edit these) ----------------------------
$Watched    = @('whoami.exe')            # add more if you like, e.g. 'net.exe','nltest.exe','systeminfo.exe'
$Dir        = 'C:\ProgramData\SvcHealth' # script copy + log live here (admins/SYSTEM only)
$TaskName   = 'WindowsHealthMonitor'     # keep it boring
$NeverBlock = @('127.0.0.1', '::1')      # ADD: your team IPs, scoring engine, VyOS gateway, DNS servers
# Processes the script will never kill, and will stop climbing the process tree at:
$Protected  = @('explorer.exe', 'services.exe', 'svchost.exe', 'wininit.exe', 'winlogon.exe',
                'lsass.exe', 'csrss.exe', 'smss.exe', 'System', 'sqlservr.exe', 'w3wp.exe',
                'WmiPrvSE.exe', 'dwm.exe', 'sihost.exe', 'taskhostw.exe')
# -----------------------------------------------------------------------------

$LogFile   = Join-Path $Dir 'events.log'
$Installed = Join-Path $Dir 'monitor.ps1'

function Initialize-Dir {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        icacls $Dir /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    }
}

function Write-Log {
    param([string]$Msg)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Msg
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

# Process chain starting at a PID and walking up through its parents
function Get-Chain {
    param([int]$StartPid)
    $chain = @()
    $cur = $StartPid
    for ($i = 0; $i -lt 10 -and $cur -gt 4; $i++) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $cur" -ErrorAction SilentlyContinue
        if (-not $p) { break }
        $chain += $p
        $cur = [int]$p.ParentProcessId
    }
    return $chain
}

# Remote IPs of established TCP connections owned by the given PIDs
function Get-Peers {
    param([int[]]$Pids)
    $found = @()
    foreach ($id in $Pids) {
        $conns = Get-NetTCPConnection -OwningProcess $id -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            $ip = [string]$c.RemoteAddress
            if ($ip -match '^(127\.|::1$|0\.0\.0\.0|::$)') { continue }
            $found += $ip
        }
    }
    return @($found | Select-Object -Unique)
}

function Invoke-Response {
    param($d)

    $creatorPid = [Convert]::ToInt32($d['ProcessId'], 16)
    $user  = '{0}\{1}' -f $d['SubjectDomainName'], $d['SubjectUserName']
    $chain = @(Get-Chain $creatorPid)
    if ($chain.Count -eq 0) {
        Write-Log "TRIGGER user=$user cmd=[$($d['CommandLine'])] - parent PID $creatorPid already exited"
        return
    }

    $sessionId = [int]$chain[0].SessionId
    $desc = ($chain | ForEach-Object { '{0}({1})' -f $_.Name, $_.ProcessId }) -join ' <- '
    Write-Log "TRIGGER user=$user session=$sessionId cmd=[$($d['CommandLine'])] chain: $desc"

    $peersAll = @(Get-Peers -Pids @($chain | ForEach-Object { [int]$_.ProcessId }))
    if ($peersAll.Count -gt 0) { Write-Log ('Network peers in chain: ' + ($peersAll -join ', ')) }

    # Work out what is safe to kill: climb from the creator until a protected process
    $toKill = @()
    foreach ($p in $chain) {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.ParentProcessId)" -ErrorAction SilentlyContinue
        $stop = ($Protected -contains $p.Name) -or ($p.ProcessId -eq $PID) -or ($parent -and $parent.Name -ieq 'services.exe')
        if ($stop) { break }
        $toKill += $p
    }
    if ($toKill.Count -eq 0) {
        Write-Log 'Nothing killable in chain (parent is protected). Alert only.'
        return
    }

    $names = ($toKill | ForEach-Object { '{0}({1})' -f $_.Name, $_.ProcessId }) -join ', '
    if (-not $Kill) {
        Write-Log "ALERT ONLY (-Kill not set). Would kill: $names"
        return
    }
    if ($sessionId -ne 0 -and -not $IncludeInteractive) {
        Write-Log "Interactive session $sessionId - alert only (-IncludeInteractive not set). Would kill: $names"
        return
    }

    # Block remote peers of the processes we are about to kill
    if ($BlockIP) {
        $peers = @(Get-Peers -Pids @($toKill | ForEach-Object { [int]$_.ProcessId }))
        foreach ($ip in $peers) {
            if ($NeverBlock -contains $ip) { Write-Log "Not blocking $ip (in NeverBlock)"; continue }
            New-NetFirewallRule -DisplayName "TW-Block-$ip" -Direction Outbound -RemoteAddress $ip -Action Block -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "TW-Block-$ip" -Direction Inbound  -RemoteAddress $ip -Action Block -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Blocked $ip in the firewall"
        }
    }

    # Kill outermost first so nothing respawns the inner shell
    for ($i = $toKill.Count - 1; $i -ge 0; $i--) {
        $t = $toKill[$i]
        Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Log "KILLED $($t.Name) (PID $($t.ProcessId))"
    }
}

# --------------------------------- INSTALL -----------------------------------
if ($Install) {
    Initialize-Dir
    Copy-Item $PSCommandPath $Installed -Force

    # Make Windows log process creation, with command lines
    auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    wevtutil sl Security /ms:268435456   # 256 MB so 4688 events do not roll over quickly

    $extra = @()
    if ($Kill)               { $extra += '-Kill' }
    if ($BlockIP)            { $extra += '-BlockIP' }
    if ($IncludeInteractive) { $extra += '-IncludeInteractive' }
    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Installed`" -Run " + ($extra -join ' ')

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "Installed. Task '$TaskName' is running as SYSTEM. Log: $LogFile" -ForegroundColor Green
    Write-Host ('Mode: ' + $(if ($Kill) { 'KILL' } else { 'ALERT ONLY' }) + $(if ($BlockIP) { ' + BLOCK IP' } else { '' }) + $(if ($IncludeInteractive) { ' + INTERACTIVE' } else { '' }))
    auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"
    exit 0
}

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName 'TW-Block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host 'Task and TW-Block firewall rules removed. Logs and audit settings were left in place.' -ForegroundColor Green
    exit 0
}

if (-not $Run) {
    Get-Help $PSCommandPath | Out-String | Write-Host
    exit 0
}

# ---------------------------------- RUN LOOP ---------------------------------
Initialize-Dir
$mode = if ($Kill) { 'KILL' } else { 'ALERT ONLY' }
if ($BlockIP)            { $mode += ' + BLOCK IP' }
if ($IncludeInteractive) { $mode += ' + INTERACTIVE' }
Write-Log "Tripwire started. Mode: $mode. Watching: $($Watched -join ', ')"

$first = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
$last  = if ($first) { [long]$first.RecordId } else { [long]0 }

while ($true) {
    $xpath  = "*[System[(EventID=4688) and (EventRecordID > $last)]]"
    $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue | Sort-Object RecordId)
    foreach ($e in $events) {
        $last = [long]$e.RecordId
        try {
            $xml = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
            $exe = [IO.Path]::GetFileName($d['NewProcessName'])
            if ($Watched -contains $exe) { Invoke-Response $d }
        }
        catch {
            Write-Log "Error handling event $($e.RecordId): $_"
        }
    }
    Start-Sleep -Milliseconds 500
}
