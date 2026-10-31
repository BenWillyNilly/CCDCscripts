#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Shows who is connected to this server from any remote service, and who has
    connected in the past.

.DESCRIPTION
    Default (live monitor): refreshes every few seconds, shows current remote
    sessions/connections, raises alerts when something NEW connects or ends,
    and appends everything to a log file.
        [H] history report   [R] refresh now   [Q] quit

    -Once        Print one report (current + history), save it, and exit.
    -Background  No screen output or keys. Logs only. For a startup scheduled task.

    Covers: RDP, SSH, WinRM / PowerShell remoting, WinRS, PsExec, SMB, WMI/RPC,
    Telnet, VNC, FTP, remote-access tools (AnyDesk, TeamViewer...) and shells
    with outbound network connections (reverse shells).
#>
param(
    [switch]$Once,
    [switch]$Background,
    [ValidateRange(2, 300)][int]$Interval = 5,
    [int]$HistoryDays = 7,
    [string]$LogFile = 'C:\RemoteConnections.log'
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Alerts     = New-Object System.Collections.ArrayList
$script:LastRecord = [int64]0

# Local ports that mean "someone is connecting in to a remote service"
$ServicePorts = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 135 = 'RPC/WMI/DCOM'; 139 = 'NetBIOS'
    445 = 'SMB'; 3389 = 'RDP'; 5900 = 'VNC'; 5901 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM-HTTPS'
}
$rdpPort = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').PortNumber
if ($rdpPort) { $ServicePorts[[int]$rdpPort] = 'RDP' }

$RemoteToolRegex = 'anydesk|teamviewer|vnc|screenconnect|rustdesk|ngrok|chisel|plink|meterpreter|logmein|splashtop|supremo'
$ShellRegex      = '^(cmd|powershell|pwsh|nc|nc64|ncat|netcat|socat|wscript|cscript|mshta|bash)$'

# ------------------------------------------------------------------ helpers
function Get-Width {
    $w = $Host.UI.RawUI.WindowSize.Width
    if (-not $w -or $w -lt 80) { $w = 120 }
    $w
}
function Write-Header($t) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $t" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Write-Sub($t) { Write-Host ""; Write-Host "--- $t" -ForegroundColor Yellow }
function Write-None    { Write-Host "  (nothing found)" -ForegroundColor DarkGray }

function Show-Table {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin   { $items = @() }
    process { $items += $InputObject }
    end {
        if ($items.Count -eq 0) { Write-None; return }
        $items | Format-Table -AutoSize -Wrap | Out-String -Width (Get-Width) | Write-Host
    }
}
function Write-Log($kind, $text) {
    $line = "{0} {1,-8} {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $kind, $text
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch {}
}
function Add-Alert($kind, $text) {
    [void]$script:Alerts.Insert(0, [pscustomobject]@{ Time = (Get-Date -Format 'HH:mm:ss'); Kind = $kind; Text = $text })
    while ($script:Alerts.Count -gt 20) { $script:Alerts.RemoveAt(20) }
    Write-Log $kind $text
    if ($kind -in 'NEW', 'LOGON' -and -not $Background) { try { [Console]::Beep(1000, 150) } catch {} }
}

# ----------------------------------------------------------- current state
function Get-Snapshot {
    $items = New-Object System.Collections.ArrayList
    function Add-Item($cat, $who, $svc, $detail, $key, $level = 'alert') {
        [void]$items.Add([pscustomobject]@{
            Category = $cat; Who = $who; Service = $svc; Detail = $detail; Key = $key; Level = $level })
    }

    # Logged-on sessions (console, RDP, disconnected RDP)
    $q = @(quser 2>$null) | Select-Object -Skip 1
    foreach ($line in $q) {
        if ($line -match '^\s*>?\s*(?<user>\S+)\s+(?:(?<sess>[^\s\d]\S*)\s+)?(?<id>\d+)\s+(?<state>\S+)\s+(?<idle>\S+)\s+(?<logon>.+?)\s*$') {
            $sess = $Matches.sess
            $type = if     ($sess -match '^rdp')     { 'RDP' }
                    elseif ($sess -match '^console') { 'Console' }
                    elseif (-not $sess)              { 'Disconnected' }
                    else                             { $sess }
            $level = if ($type -eq 'Console') { 'info' } else { 'alert' }
            Add-Item 'Session' $Matches.user $type ("session {0}, {1}, idle {2}, since {3}" -f $Matches.id, $Matches.state, $Matches.idle, $Matches.logon) "SESSION|$($Matches.user)|$($Matches.id)" $level
        }
    }

    # Processes that only exist while a remote session is open
    $names = @{
        'wsmprovhost.exe' = 'WinRM/PS remoting'; 'sshd.exe' = 'SSH'; 'sshd-session.exe' = 'SSH'
        'psexesvc.exe' = 'PsExec'; 'winrshost.exe' = 'WinRS'; 'rdpclip.exe' = 'RDP session'
    }
    foreach ($p in (Get-CimInstance Win32_Process | Where-Object { $names.ContainsKey($_.Name.ToLower()) })) {
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
        $owner = if ($o.User) { "$($o.Domain)\$($o.User)" } else { '?' }
        if ($owner -eq 'NT AUTHORITY\SYSTEM' -and $p.Name -match '^sshd') { continue }   # listener, not a session
        Add-Item 'Process' $owner $names[$p.Name.ToLower()] ("{0} PID {1}, started {2}" -f $p.Name, $p.ProcessId, $p.CreationDate) "PROC|$($p.Name)|$($p.ProcessId)"
    }

    # SMB sessions
    foreach ($s in (Get-SmbSession)) {
        Add-Item 'SMB' $s.ClientUserName 'SMB' ("from {0}, {1} open file(s), connected {2}s" -f $s.ClientComputerName, $s.NumOpens, $s.SecondsExists) "SMB|$($s.ClientUserName)|$($s.ClientComputerName)"
    }

    # TCP connections: inbound to remote services, remote tools, shells with network
    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.Name }
    $conns = @(Get-NetTCPConnection -State Established)

    $inbound = foreach ($c in $conns) {
        $svc = $ServicePorts[[int]$c.LocalPort]
        if ($svc) { [pscustomobject]@{ Svc = $svc; Remote = $c.RemoteAddress; Port = $c.LocalPort; Proc = $procs[[int]$c.OwningProcess] } }
    }
    foreach ($g in ($inbound | Group-Object Svc, Remote)) {
        $f = $g.Group[0]
        $loop = if ($f.Remote -match '^(127\.|::1$)') { ' (loopback - possible tunnel)' } else { '' }
        Add-Item 'Inbound' $f.Remote $f.Svc ("{0} connection(s) to port {1}, process {2}{3}" -f $g.Count, $f.Port, $f.Proc, $loop) "IN|$($f.Svc)|$($f.Remote)"
    }

    foreach ($c in $conns) {
        if ($c.RemoteAddress -match '^(127\.|::1$|::$|0\.0\.0\.0)') { continue }
        $pn = [string]$procs[[int]$c.OwningProcess]
        if ($pn -match $RemoteToolRegex) {
            Add-Item 'Tool' "$($c.RemoteAddress):$($c.RemotePort)" 'Remote tool' "$pn (PID $($c.OwningProcess))" "TOOL|$pn|$($c.RemoteAddress):$($c.RemotePort)"
        }
        elseif ($pn -match $ShellRegex) {
            Add-Item 'Tool' "$($c.RemoteAddress):$($c.RemotePort)" 'Shell + network' "$pn (PID $($c.OwningProcess)) possible reverse shell" "SHELL|$pn|$($c.RemoteAddress):$($c.RemotePort)"
        }
    }
    $items
}

function Show-Snapshot($snap) {
    $cats = [ordered]@{
        Session = 'Logged-on sessions (console / RDP / disconnected)'
        Inbound = 'Inbound connections to remote services'
        Process = 'Active remote-service processes (the account running them is the connected user)'
        SMB     = 'SMB sessions'
        Tool    = 'Remote-access tools and shells with outbound connections'
    }
    foreach ($c in $cats.Keys) {
        Write-Sub $cats[$c]
        $rows = @($snap | Where-Object Category -eq $c)
        if ($rows.Count -eq 0) { Write-None; continue }
        foreach ($r in $rows) {
            if ($r.Level -eq 'info') { $mark = '[*]'; $col = 'Green' } else { $mark = '[!]'; $col = 'Red' }
            Write-Host ("  {0} {1,-26} {2,-16} {3}" -f $mark, $r.Who, $r.Service, $r.Detail) -ForegroundColor $col
        }
    }
}

# ------------------------------------------------------------------ history
function Get-LogonEvents([int]$Seconds, [int]$Max = 5000) {
    $ms = [int64]$Seconds * 1000
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and " +
          "*[EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='8' or Data[@Name='LogonType']='10']]"
    $typeName = @{ 3 = 'Network'; 8 = 'NetworkCleartext'; 10 = 'RDP' }
    Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents $Max | ForEach-Object {
        $user = [string]$_.Properties[5].Value
        if ($user -like '*$') { return }                       # skip machine accounts
        $src = [string]$_.Properties[18].Value
        if (-not $src -or $src -eq '-') { $src = '(local)' }
        [pscustomobject]@{
            RecordId    = $_.RecordId
            Time        = $_.TimeCreated
            User        = "$($_.Properties[6].Value)\$user"
            Type        = [int]$_.Properties[8].Value
            TypeName    = $typeName[[int]$_.Properties[8].Value]
            Auth        = $_.Properties[10].Value
            Workstation = $_.Properties[11].Value
            Source      = $src
        }
    }
}

function Show-History {
    $since = (Get-Date).AddDays(-$HistoryDays)
    Write-Header "CONNECTION HISTORY (last $HistoryDays days, since $($since.ToString('yyyy-MM-dd HH:mm')))"

    Write-Sub "Remote logons seen in the Security log (grouped; machine accounts hidden)"
    $ev = @(Get-LogonEvents -Seconds ($HistoryDays * 86400))
    $ev | Group-Object User, TypeName, Source, Workstation | ForEach-Object {
        $g = $_.Group | Sort-Object Time
        [pscustomobject]@{
            User = $g[0].User; Type = $g[0].TypeName; Source = $g[0].Source
            Workstation = $g[0].Workstation; Count = $_.Count; First = $g[0].Time; Last = $g[-1].Time
        }
    } | Sort-Object Last -Descending | Select-Object -First 60 | Show-Table
    Write-Host "  If empty, logon auditing may be off. Check: auditpol /get /category:Logon/Logoff" -ForegroundColor DarkGray

    Write-Sub "RDP session activity (logon / logoff / disconnect / reconnect)"
    $map = @{ 21 = 'Logon'; 23 = 'Logoff'; 24 = 'Disconnected'; 25 = 'Reconnected' }
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        Id = 21, 23, 24, 25; StartTime = $since } -MaxEvents 500 | ForEach-Object {
            $d = ([xml]$_.ToXml()).Event.UserData.EventXML
            [pscustomobject]@{ Time = $_.TimeCreated; Event = $map[[int]$_.Id]; User = $d.User; Source = $d.Address; Session = $d.SessionID }
        } | Select-Object -First 60 | Show-Table

    Write-Sub "RDP authentication succeeded (before the session starts)"
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        Id = 1149; StartTime = $since } -MaxEvents 500 | ForEach-Object {
            $d = ([xml]$_.ToXml()).Event.UserData.EventXML
            [pscustomobject]@{ Time = $_.TimeCreated; User = "$($d.Param2)\$($d.Param1)"; Source = $d.Param3 }
        } | Select-Object -First 40 | Show-Table

    Write-Sub "SSH logins accepted (OpenSSH log)"
    Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = $since } -MaxEvents 3000 |
        ForEach-Object {
            if ($_.Message -match 'Accepted (\S+) for (\S+) from (\S+) port') {
                [pscustomobject]@{ Time = $_.TimeCreated; User = $Matches[2]; Method = $Matches[1]; Source = $Matches[3] }
            }
        } | Select-Object -First 40 | Show-Table

    Write-Sub "WinRM / PowerShell remoting authentications"
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WinRM/Operational'; Id = 169; StartTime = $since } -MaxEvents 500 |
        ForEach-Object {
            if ($_.Message -match 'User (.+?) authenticated successfully using (\S+)') {
                [pscustomobject]@{ Time = $_.TimeCreated; User = $Matches[1]; Auth = $Matches[2] }
            }
        } | Select-Object -First 40 | Show-Table

    Write-Sub "Failed remote logons, last 24 hours (top sources)"
    $xp = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]] and " +
          "*[EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]"
    Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 5000 | ForEach-Object {
        [pscustomobject]@{ Time = $_.TimeCreated; User = [string]$_.Properties[5].Value; Source = [string]$_.Properties[19].Value }
    } | Group-Object Source, User | ForEach-Object {
        $g = $_.Group | Sort-Object Time
        [pscustomobject]@{ Source = $g[0].Source; User = $g[0].User; Failures = $_.Count; Last = $g[-1].Time }
    } | Sort-Object Failures -Descending | Select-Object -First 20 | Show-Table
}

# -------------------------------------------------------------------- modes
function Invoke-Once {
    Clear-Host
    $file = "C:\RemoteReport_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $out = & {
        Write-Header "CURRENT REMOTE CONNECTIONS   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Show-Snapshot (Get-Snapshot)
        Show-History
    } *>&1 | Out-String -Stream
    $out | Set-Content -Path $file
    $out | Out-Host -Paging
    Write-Host ""
    Write-Host "Report saved to $file" -ForegroundColor Green
}

function Wait-Key([int]$Seconds) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        try {
            if ([Console]::KeyAvailable) { return [Console]::ReadKey($true).Key.ToString() }
        } catch { Start-Sleep -Seconds $Seconds; return $null }
        Start-Sleep -Milliseconds 200
    }
    return $null
}

function Draw-Screen($snap) {
    Clear-Host
    Write-Host ("REMOTE CONNECTION MONITOR   {0}   refresh {1}s   log: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Interval, $LogFile) -ForegroundColor Cyan
    Write-Host "[H] history   [R] refresh now   [Q] quit" -ForegroundColor Cyan
    Show-Snapshot $snap
    Write-Sub "Alerts since the monitor started (newest first)"
    if ($script:Alerts.Count -eq 0) { Write-None }
    foreach ($a in $script:Alerts) {
        $col = switch ($a.Kind) { 'NEW' { 'Red' } 'LOGON' { 'Magenta' } default { 'DarkGray' } }
        Write-Host ("  {0} {1,-6} {2}" -f $a.Time, $a.Kind, $a.Text) -ForegroundColor $col
    }
}

function Start-Monitor {
    Write-Log 'START' "Monitor started (interval ${Interval}s, background=$Background)"
    $script:LastRecord = [int64](Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 1).RecordId
    $prev = $null

    while ($true) {
        $snap = @(Get-Snapshot)
        $cur = @{}
        foreach ($i in $snap) { $cur[$i.Key] = $i }

        if ($null -eq $prev) {
            foreach ($i in $snap) { Write-Log 'PRESENT' ("{0} {1} {2}" -f $i.Service, $i.Who, $i.Detail) }
        } else {
            foreach ($k in $cur.Keys)  { if (-not $prev.ContainsKey($k)) { Add-Alert 'NEW'   ("{0} {1} {2}" -f $cur[$k].Service, $cur[$k].Who, $cur[$k].Detail) } }
            foreach ($k in $prev.Keys) { if (-not $cur.ContainsKey($k))   { Add-Alert 'ENDED' ("{0} {1} {2}" -f $prev[$k].Service, $prev[$k].Who, $prev[$k].Detail) } }
        }
        $prev = $cur

        # New remote logon events since the last pass
        $window = [Math]::Max(60, $Interval * 3)
        $new = @(Get-LogonEvents -Seconds $window | Where-Object { $_.RecordId -gt $script:LastRecord } | Sort-Object RecordId)
        foreach ($e in $new) {
            Add-Alert 'LOGON' ("{0} logon {1} from {2} ({3}, {4})" -f $e.TypeName, $e.User, $e.Source, $e.Workstation, $e.Auth)
            if ($e.RecordId -gt $script:LastRecord) { $script:LastRecord = $e.RecordId }
        }

        if ($Background) { Start-Sleep -Seconds $Interval; continue }

        Draw-Screen $snap
        switch (Wait-Key $Interval) {
            'Q' { Clear-Host; Write-Host "Monitor stopped. Log: $LogFile"; Write-Log 'STOP' 'Monitor stopped'; return }
            'H' {
                Clear-Host
                & { Show-History } *>&1 | Out-String -Stream | Out-Host -Paging
                Read-Host "`nPress Enter to return to the monitor" | Out-Null
            }
        }
    }
}

# --------------------------------------------------------------------- main
if ($Once) { Invoke-Once } else { Start-Monitor }
