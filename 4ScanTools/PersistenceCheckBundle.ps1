#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Menu-driven persistence hunter for Windows Server 2022 Core.

.DESCRIPTION
    Pick a number to run one category of checks, A to run everything and save
    a report, P to toggle paging, or Q to quit. Lines starting with [!] are
    things worth a closer look. Read-only: this script changes nothing.
#>

$ErrorActionPreference = 'SilentlyContinue'
$script:Paging = $true      # page long output one screen at a time
$RecentDays    = 7          # "recently modified" window for file checks

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
function Write-Sub($t)  { Write-Host ""; Write-Host "--- $t" -ForegroundColor Yellow }
function Write-None     { Write-Host "  (nothing found)" -ForegroundColor DarkGray }
function Write-Flag($t) { Write-Host "  [!] $t" -ForegroundColor Red }

function Show-Table {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin   { $items = @() }
    process { $items += $InputObject }
    end {
        if ($items.Count -eq 0) { Write-None; return }
        $items | Format-Table -AutoSize -Wrap | Out-String -Width (Get-Width) | Write-Host
    }
}
function Show-List {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin   { $items = @() }
    process { $items += $InputObject }
    end {
        if ($items.Count -eq 0) { Write-None; return }
        $items | Format-List | Out-String -Width (Get-Width) | Write-Host
    }
}
function Show-RegValues($path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $props = (Get-ItemProperty -LiteralPath $path).PSObject.Properties |
             Where-Object { $_.Name -notmatch '^PS' }
    Write-Host "[$path]" -ForegroundColor White
    if (-not $props) { Write-Host "  (empty)" -ForegroundColor DarkGray; return }
    foreach ($p in $props) { Write-Host ("  {0} = {1}" -f $p.Name, ($p.Value -join ' ')) }
}
function Get-EvData($e, $name) {
    $x = [xml]$e.ToXml()
    ($x.Event.EventData.Data | Where-Object Name -eq $name).'#text'
}

# ------------------------------------------------------------------- checks
function Check-Registry {
    Write-Header "1. REGISTRY AUTORUNS"

    Write-Sub "Run / RunOnce keys (HKLM and every loaded user hive)"
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($h in (Get-ChildItem Registry::HKEY_USERS)) {
        if ($h.PSChildName -match '^S-1-5-21-[\d-]+$') {
            $paths += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            $paths += "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
    }
    foreach ($p in $paths) { Show-RegValues $p }
    Write-Host "  Note: users who are not logged in have unloaded hives that are not shown." -ForegroundColor DarkGray

    Write-Sub "Winlogon (Core normally uses a cmd.exe shell; Userinit should be the default)"
    $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Write-Host "  Shell    = $($wl.Shell)"
    Write-Host "  Userinit = $($wl.Userinit)"
    if ($wl.Userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') { Write-Flag "Userinit is not the default value" }
    if ($wl.Shell -notmatch '(?i)^(explorer\.exe|cmd\.exe)') { Write-Flag "Shell is not explorer.exe or cmd.exe" }

    Write-Sub "Image File Execution Options (Debugger hijacks)"
    $found = $false
    foreach ($k in (Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        $d = (Get-ItemProperty $k.PSPath).Debugger
        if ($d) { Write-Flag "$($k.PSChildName) -> $d"; $found = $true }
    }
    foreach ($k in (Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit')) {
        $m = (Get-ItemProperty $k.PSPath).MonitorProcess
        if ($m) { Write-Flag "SilentProcessExit $($k.PSChildName) -> $m"; $found = $true }
    }
    if (-not $found) { Write-None }

    Write-Sub "AppInit_DLLs"
    foreach ($p in 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
                   'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = Get-ItemProperty $p
        Write-Host "  [$p] AppInit_DLLs='$($v.AppInit_DLLs)' LoadAppInit_DLLs=$($v.LoadAppInit_DLLs)"
        if ($v.AppInit_DLLs) { Write-Flag "AppInit_DLLs is set" }
    }

    Write-Sub "Session Manager BootExecute (default: autocheck autochk *)"
    $be = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager').BootExecute
    Write-Host "  BootExecute = $($be -join ' | ')"
    if (($be -join ' ') -notmatch '^autocheck autochk \*$') { Write-Flag "BootExecute is not the default" }

    Write-Sub "LSA packages (defaults: msv1_0 / scecli; anything else deserves a look)"
    $lsa = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa'
    foreach ($n in 'Authentication Packages', 'Security Packages', 'Notification Packages') {
        Write-Host ("  {0} = {1}" -f $n, ($lsa.$n -join ', '))
    }
}

function Check-Tasks {
    Write-Header "2. SCHEDULED TASKS"
    $tasks = Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object {
        [pscustomobject]@{
            Name  = $_.TaskName
            Path  = $_.TaskPath
            State = $_.State
            Run   = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join '; ')
        }
    }

    Write-Sub "Non-Microsoft tasks (outside \Microsoft\Windows\)"
    $tasks | Where-Object { $_.Path -notlike '\Microsoft\Windows\*' } | Show-Table

    Write-Sub "Microsoft-path tasks that launch script hosts or user/temp locations"
    $tasks | Where-Object {
        $_.Path -like '\Microsoft\Windows\*' -and
        $_.Run -match 'powershell|cmd\.exe|wscript|cscript|mshta|\\Users\\|\\Temp\\|ProgramData'
    } | Show-Table

    Write-Host ""
    Write-Host "Total enabled tasks: $($tasks.Count)   (task files: C:\Windows\System32\Tasks)"
}

function Check-Services {
    Write-Header "3. SERVICES"
    $svc = Get-CimInstance Win32_Service

    Write-Sub "Services running from outside System32 / Program Files"
    $svc | Where-Object {
        $_.PathName -and $_.PathName -notmatch 'system32|syswow64|Program Files|\\servicing\\|WinSxS|Windows Defender|Microsoft\.NET'
    } | Select-Object Name, State, StartMode, StartName, PathName | Show-Table

    Write-Sub "Unquoted service paths containing spaces"
    $svc | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^"' -and (($_.PathName -split '(?i)\.exe')[0] -match ' ')
    } | Select-Object Name, StartName, PathName | Show-Table

    Write-Sub "Services running as an unusual account"
    $svc | Where-Object {
        $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService|System)|NT SERVICE\\.*|Window Manager\\.*|Font Driver Host\\.*)$'
    } | Select-Object Name, State, StartName, PathName | Show-Table

    Write-Sub "Most recent service installs (System log, event 7045)"
    Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = 7045} -MaxEvents 15 | ForEach-Object {
        [pscustomobject]@{
            Time    = $_.TimeCreated
            Service = $_.Properties[0].Value
            Path    = $_.Properties[1].Value
            Account = $_.Properties[4].Value
        }
    } | Show-Table
}

function Check-Startup {
    Write-Header "4. STARTUP FOLDERS"
    $dirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')
    foreach ($u in (Get-ChildItem C:\Users -Directory -Force)) {
        $dirs += Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($d in $dirs) {
        Write-Sub $d
        if (-not (Test-Path $d)) { Write-Host "  (folder does not exist)" -ForegroundColor DarkGray; continue }
        Get-ChildItem $d -Force | Where-Object Name -ne 'desktop.ini' |
            Select-Object Name, Length, LastWriteTime | Show-Table
    }
}

function Check-WMI {
    Write-Header "5. WMI EVENT SUBSCRIPTIONS"
    Write-Host "  Only 'SCM Event Log Filter' / 'SCM Event Log Consumer' are normal here." -ForegroundColor DarkGray

    Write-Sub "Event filters"
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
        Select-Object Name, Query | Show-List

    Write-Sub "Event consumers"
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
        Select-Object Name,
            @{n = 'Type'; e = { $_.CimClass.CimClassName }},
            CommandLineTemplate, ExecutablePath, ScriptingEngine, ScriptFileName, ScriptText | Show-List

    Write-Sub "Filter-to-consumer bindings"
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
        Select-Object @{n = 'Filter'; e = { $_.Filter.Name }}, @{n = 'Consumer'; e = { $_.Consumer.Name }} | Show-List
}

function Check-Accounts {
    Write-Header "6. ACCOUNTS, GROUPS AND SSH KEYS"

    Write-Sub "Local users"
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires | Show-Table

    Write-Sub "Guest account"
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }
    if ($guest.Enabled) { Write-Flag "Guest account is ENABLED" } else { Write-Host "  Guest is disabled." }

    Write-Sub "Account names ending in `$ (hidden-style accounts)"
    Get-LocalUser | Where-Object Name -like '*$' | Select-Object Name, Enabled | Show-Table

    Write-Sub "Enabled accounts whose password never expires"
    Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordExpires } | Select-Object Name, PasswordLastSet | Show-Table

    $groups = [ordered]@{
        'S-1-5-32-544' = 'Administrators'
        'S-1-5-32-555' = 'Remote Desktop Users'
        'S-1-5-32-580' = 'Remote Management Users'
        'S-1-5-32-551' = 'Backup Operators'
    }
    foreach ($sid in $groups.Keys) {
        $g = Get-LocalGroup -SID $sid
        Write-Sub "Members of $($g.Name)"
        Get-LocalGroupMember -Group $g.Name | Select-Object Name, ObjectClass, PrincipalSource | Show-Table
    }

    Write-Sub "SSH authorized_keys files"
    $ssh = @()
    if (Test-Path 'C:\ProgramData\ssh\administrators_authorized_keys') {
        $ssh += Get-Item 'C:\ProgramData\ssh\administrators_authorized_keys' -Force
    }
    $ssh += Get-ChildItem 'C:\Users\*\.ssh' -Force -File
    if ($ssh.Count -gt 0) { Write-Flag "SSH key files exist" }
    $ssh | Select-Object FullName, Length, LastWriteTime | Show-Table
}

function Check-Network {
    Write-Header "7. LISTENERS, CONNECTIONS AND REMOTE ACCESS"
    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.Name }

    Write-Sub "Listening TCP ports"
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Process'; e = { $procs[[int]$_.OwningProcess] }} | Show-Table

    Write-Sub "Listening UDP ports"
    Get-NetUDPEndpoint | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{n = 'Process'; e = { $procs[[int]$_.OwningProcess] }} | Show-Table

    Write-Sub "Established connections"
    Get-NetTCPConnection -State Established | Sort-Object RemoteAddress |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{n = 'Process'; e = { $procs[[int]$_.OwningProcess] }} | Show-Table

    Write-Sub "Remote access services"
    Get-Service sshd, WinRM, TermService, RemoteRegistry, TlntSvr, SNMP | Select-Object Name, Status, StartType | Show-Table

    Write-Sub "Processes that look like remote access / tunneling tools"
    Get-Process | Where-Object {
        $_.Name -match '^(nc|nc64|ncat|netcat|plink|psexesvc|chisel|ngrok|socat)$|anydesk|teamviewer|vnc|screenconnect|rustdesk|meterpreter'
    } | Select-Object Id, Name, Path | Show-Table
}

function Check-Binaries {
    Write-Header "8. BINARY AND DLL HIJACKS"

    Write-Sub "Accessibility binaries (Sticky Keys etc. replaced with cmd/powershell?)"
    $sys     = "$env:SystemRoot\System32"
    $cmdHash = (Get-FileHash "$sys\cmd.exe").Hash
    $psHash  = (Get-FileHash "$sys\WindowsPowerShell\v1.0\powershell.exe").Hash
    foreach ($n in 'sethc', 'utilman', 'osk', 'narrator', 'magnify', 'displayswitch', 'atbroker') {
        $f = "$sys\$n.exe"
        if (-not (Test-Path $f)) { Write-Host ("  {0,-16} not present" -f "$n.exe") -ForegroundColor DarkGray; continue }
        $sig  = (Get-AuthenticodeSignature $f).Status
        $hash = (Get-FileHash $f).Hash
        if ($hash -eq $cmdHash -or $hash -eq $psHash -or $sig -ne 'Valid') {
            Write-Flag ("{0,-16} signature={1}  (replaced or unsigned)" -f "$n.exe", $sig)
        } else {
            Write-Host ("  {0,-16} signature={1}" -f "$n.exe", $sig)
        }
    }

    Write-Sub "Newest files in System32 (last $RecentDays days, unsigned/invalid listed first)"
    Write-Host "  Checking signatures, this can take a moment..." -ForegroundColor DarkGray
    $cut = (Get-Date).AddDays(-$RecentDays)
    Get-ChildItem $sys -File -Force |
        Where-Object { $_.Extension -match '^\.(exe|dll|sys|bat|cmd|ps1|vbs|js)$' -and $_.LastWriteTime -gt $cut } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 60 |
        ForEach-Object {
            [pscustomobject]@{
                Name      = $_.Name
                Modified  = $_.LastWriteTime
                Signature = (Get-AuthenticodeSignature $_.FullName).Status
            }
        } | Sort-Object @{e = { $_.Signature -eq 'Valid' }}, @{e = 'Modified'; Descending = $true} |
        Select-Object -First 40 | Show-Table
    Write-Host "  Tip: on a freshly patched VM many files are recent. Change `$RecentDays at the top of the script." -ForegroundColor DarkGray

    Write-Sub "PowerShell profiles (run every time PowerShell starts)"
    $profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost)
    $profiles += @(Get-ChildItem 'C:\Users\*\Documents\WindowsPowerShell\*.ps1' -Force | ForEach-Object FullName)
    $any = $false
    foreach ($p in $profiles) {
        if ($p -and (Test-Path $p)) {
            $any = $true
            Write-Flag "$p exists. First lines:"
            Get-Content $p | Select-Object -First 15 | ForEach-Object { Write-Host "      $_" }
        }
    }
    if (-not $any) { Write-None }
}

function Check-Other {
    Write-Header "9. OTHER PERSISTENCE SPOTS"

    Write-Sub "Drivers loaded from outside system32\drivers"
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -and $_.PathName -notmatch 'system32\\drivers' } |
        Select-Object Name, State, StartMode, PathName | Show-Table

    Write-Sub "Netsh helper DLLs"
    Show-RegValues 'HKLM:\Software\Microsoft\NetSh'

    Write-Sub "Time providers (expect w32time.dll / vmictimeprovider.dll)"
    foreach ($k in (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\W32Time\TimeProviders')) {
        Write-Host ("  {0} -> {1}" -f $k.PSChildName, (Get-ItemProperty $k.PSPath).DllName)
    }

    Write-Sub "Print monitors"
    foreach ($k in (Get-ChildItem 'HKLM:\System\CurrentControlSet\Control\Print\Monitors')) {
        Write-Host ("  {0} -> {1}" -f $k.PSChildName, (Get-ItemProperty $k.PSPath).Driver)
    }

    Write-Sub "Group Policy startup/logon scripts"
    foreach ($d in "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts", "$env:SystemRoot\System32\GroupPolicy\User\Scripts") {
        Write-Host "  $d" -ForegroundColor White
        if (Test-Path $d) {
            Get-ChildItem $d -Recurse -Force -File | Select-Object FullName, LastWriteTime | Show-Table
        } else {
            Write-Host "    (does not exist)" -ForegroundColor DarkGray
        }
    }

    Write-Sub "Windows Defender exclusions (attackers add these)"
    $mp = Get-MpPreference
    if ($mp) {
        Write-Host "  ExclusionPath      = $($mp.ExclusionPath -join ', ')"
        Write-Host "  ExclusionProcess   = $($mp.ExclusionProcess -join ', ')"
        Write-Host "  ExclusionExtension = $($mp.ExclusionExtension -join ', ')"
        if ($mp.ExclusionPath -or $mp.ExclusionProcess -or $mp.ExclusionExtension) { Write-Flag "Exclusions are configured" }
        if ($mp.DisableRealtimeMonitoring) { Write-Flag "Real-time monitoring is DISABLED" }
    } else {
        Write-Host "  Defender cmdlets not available." -ForegroundColor DarkGray
    }

    Write-Sub "Executables/scripts in Temp, Public, ProgramData and user AppData (first 100)"
    Write-Host "  Scanning, this can take a moment..." -ForegroundColor DarkGray
    $roots = @('C:\Windows\Temp', 'C:\Users\Public', 'C:\ProgramData')
    foreach ($u in (Get-ChildItem C:\Users -Directory -Force)) { $roots += Join-Path $u.FullName 'AppData' }
    $roots | ForEach-Object {
        Get-ChildItem $_ -Recurse -Force -File -Include *.exe, *.dll, *.ps1, *.bat, *.cmd, *.vbs, *.js, *.hta
    } | Where-Object { $_.FullName -notmatch 'Windows Defender|\\Microsoft\\Windows\\Start Menu|\\Packages\\' } |
        Select-Object -First 100 FullName, Length, LastWriteTime | Show-Table
}

function Check-Logs {
    Write-Header "10. EVENT LOGS"

    Write-Sub "Account, group, task and service changes (Security log, newest 40)"
    $desc = @{
        4720 = 'User created'; 4722 = 'User enabled'; 4724 = 'Password reset'; 4726 = 'User deleted'
        4732 = 'Added to local group'; 4738 = 'User changed'; 4698 = 'Task created'; 4697 = 'Service installed'
    }
    Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4720, 4722, 4724, 4726, 4732, 4738, 4698, 4697} -MaxEvents 40 |
        ForEach-Object {
            $detail = switch ($_.Id) {
                4732 { Get-EvData $_ 'MemberSid' }
                4698 { Get-EvData $_ 'TaskName' }
                4697 { Get-EvData $_ 'ServiceName' }
                default { '' }
            }
            [pscustomobject]@{
                Time   = $_.TimeCreated
                Event  = $desc[[int]$_.Id]
                By     = Get-EvData $_ 'SubjectUserName'
                Target = Get-EvData $_ 'TargetUserName'
                Detail = $detail
            }
        } | Show-Table
    Write-Host "  If this is empty, auditing may be off. Check: auditpol /get /category:*" -ForegroundColor DarkGray

    Write-Sub "Recent RDP logons (4624, logon type 10)"
    Get-WinEvent -LogName Security -MaxEvents 20 `
        -FilterXPath "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]" |
        ForEach-Object {
            [pscustomobject]@{
                Time     = $_.TimeCreated
                User     = $_.Properties[5].Value
                Domain   = $_.Properties[6].Value
                SourceIP = $_.Properties[18].Value
            }
        } | Show-Table

    Write-Sub "Failed logons in the last 24 hours (4625)"
    $failed = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-24)}).Count
    Write-Host "  $failed failed logon events"
    if ($failed -gt 20) { Write-Flag "High number of failed logons (possible brute force)" }
}

# --------------------------------------------------------------------- menu
$checks = [ordered]@{
    '1'  = @('Registry autoruns (Run keys, Winlogon, IFEO, AppInit, LSA)',      'Check-Registry')
    '2'  = @('Scheduled tasks',                                                  'Check-Tasks')
    '3'  = @('Services (odd paths, unquoted paths, new installs)',                'Check-Services')
    '4'  = @('Startup folders',                                                  'Check-Startup')
    '5'  = @('WMI event subscriptions',                                          'Check-WMI')
    '6'  = @('Accounts, groups and SSH keys',                                    'Check-Accounts')
    '7'  = @('Listeners, connections and remote access tools',                   'Check-Network')
    '8'  = @('Binary hijacks (accessibility, System32, PS profiles)',            'Check-Binaries')
    '9'  = @('Other spots (drivers, netsh, GPO scripts, Defender, temp dirs)',   'Check-Other')
    '10' = @('Event logs (account/task/service changes, RDP logons)',            'Check-Logs')
}

function Invoke-Check($fn) {
    Clear-Host
    if ($script:Paging) { & $fn *>&1 | Out-String -Stream | Out-Host -Paging }
    else                { & $fn }
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

function Run-All {
    Clear-Host
    Write-Host "Running all checks, please wait..." -ForegroundColor Cyan
    $file = "C:\PersistenceReport_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $text = & { foreach ($k in $checks.Keys) { & $checks[$k][1] } } *>&1 | Out-String -Stream
    $text | Set-Content -Path $file
    Clear-Host
    if ($script:Paging) { $text | Out-Host -Paging } else { $text | ForEach-Object { Write-Host $_ } }
    Write-Host ""
    Write-Host "Report saved to $file  (view later with: notepad $file)" -ForegroundColor Green
    Read-Host "`nPress Enter to return to the menu" | Out-Null
}

do {
    Clear-Host
    Write-Host "==================== PERSISTENCE CHECKER ====================" -ForegroundColor Cyan
    Write-Host ""
    foreach ($k in $checks.Keys) { Write-Host ("  {0,2}) {1}" -f $k, $checks[$k][0]) }
    Write-Host ""
    Write-Host "   A) Run ALL checks and save a report"
    Write-Host ("   P) Toggle paging (currently {0})" -f $(if ($script:Paging) { 'ON' } else { 'OFF' }))
    Write-Host "   Q) Quit"
    Write-Host ""
    $choice = (Read-Host "Select an option").Trim().ToUpper()

    if     ($checks.Contains($choice)) { Invoke-Check $checks[$choice][1] }
    elseif ($choice -eq 'A')           { Run-All }
    elseif ($choice -eq 'P')           { $script:Paging = -not $script:Paging }
} while ($choice -ne 'Q')

Write-Host "Bye."
