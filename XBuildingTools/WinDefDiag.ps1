#Requires -RunAsAdministrator
<#
.SYNOPSIS
  READ-ONLY diagnostic collector. It changes nothing on the system; it only reads state
  and writes report files to C:\DefDiag\<stage>_<time>\ (plus a .zip of them).

.USAGE
  Run it three times, once per stage, in an elevated PowerShell:

    .\DefenderDiag.ps1 -Stage 1-Before            -ToolFolder "C:\path\to\restore\tool"
    (run the restore tool)
    .\DefenderDiag.ps1 -Stage 2-AfterRestoreTool  -ToolFolder "C:\path\to\restore\tool"
    (run DISM)
    .\DefenderDiag.ps1 -Stage 3-AfterDism         -ToolFolder "C:\path\to\restore\tool"

  If scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\DefenderDiag.ps1 -Stage 1-Before

  It can take a few minutes (the package and app queries are slow). Then upload the
  diag-*.txt files from the output folder (or the .zip).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('1-Before', '2-AfterRestoreTool', '3-AfterDism', 'Other')]
    [string]$Stage,

    [string]$ToolFolder = ''
)

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Out   = "C:\DefDiag\${Stage}_$stamp"
New-Item -ItemType Directory -Path $Out -Force | Out-Null

function Add-Section {
    param([string]$File, [string]$Title, [scriptblock]$Code)
    $path = Join-Path $Out $File
    Add-Content -Path $path -Value ("`r`n===== {0} =====" -f $Title) -Encoding UTF8
    try {
        $text = & $Code 2>&1 | Out-String -Width 250
        if ([string]::IsNullOrWhiteSpace($text)) { $text = '(no output)' }
        Add-Content -Path $path -Value $text.TrimEnd() -Encoding UTF8
    }
    catch {
        Add-Content -Path $path -Value "ERROR: $_" -Encoding UTF8
    }
    Write-Host "  done: $Title"
}

function Get-RegVal {
    param([string]$Path, [string]$Name)
    $p = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($null -eq $p) { return '<key missing>' }
    $v = $p.$Name
    if ($null -eq $v) { return '<value not set>' }
    return $v
}

function Export-Reg {
    param([string]$Key, [int]$MaxLines = 400)
    $tmp = Join-Path $env:TEMP ('r_' + [guid]::NewGuid().ToString() + '.reg')
    reg export $Key $tmp /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $tmp)) {
        $lines = @(Get-Content $tmp)
        "### $Key ($($lines.Count) lines)"
        $lines | Select-Object -First $MaxLines
        if ($lines.Count -gt $MaxLines) { '... truncated ...' }
    }
    else {
        "### $Key : <missing>"
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

Write-Host "Collecting to $Out (read-only; this can take a few minutes)..." -ForegroundColor Cyan
$main = 'diag-main.txt'
$reg  = 'diag-registry.txt'
$logs = 'diag-logs.txt'
$bk   = 'diag-backup-search.txt'

# ------------------------------- MAIN REPORT ---------------------------------
Add-Section $main 'Header' {
    "Stage       : $Stage"
    "Collected   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Computer    : $env:COMPUTERNAME"
    $os = Get-CimInstance Win32_OperatingSystem
    "OS          : $($os.Caption) build $($os.BuildNumber) ($($os.Version))"
    "Last boot   : $($os.LastBootUpTime)"
    "Internet 443 (windowsupdate.microsoft.com): " + (Test-NetConnection windowsupdate.microsoft.com -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
}

Add-Section $main 'Windows features' {
    Get-WindowsFeature Windows-Defender* | Format-Table Name, InstallState -AutoSize | Out-String
}

Add-Section $main 'Services' {
    Get-Service WinDefend, WdNisSvc, Sense, SecurityHealthService, wscsvc, SgrmBroker, MpsSvc, BFE -ErrorAction SilentlyContinue |
        Format-Table Name, Status, StartType -AutoSize | Out-String
}

Add-Section $main 'Service / driver registry (Start: 0=boot 1=system 2=auto 3=manual 4=disabled)' {
    foreach ($n in 'WinDefend', 'WdNisSvc', 'WdFilter', 'WdBoot', 'WdNisDrv', 'Sense', 'SecurityHealthService', 'wscsvc', 'SgrmBroker', 'Sgrm', 'MpsSvc', 'BFE') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
        if (Test-Path $k) {
            $p = Get-ItemProperty $k
            '{0,-22} Start={1}  ImagePath={2}' -f $n, $p.Start, $p.ImagePath
        }
        else {
            '{0,-22} <key missing>' -f $n
        }
    }
}

Add-Section $main 'Key paths and files exist?' {
    foreach ($p in @(
            'C:\Program Files\Windows Defender',
            'C:\ProgramData\Microsoft\Windows Defender',
            'C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy',
            'C:\Windows\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\AppXManifest.xml',
            'C:\Windows\System32\drivers\WdFilter.sys',
            'C:\Windows\System32\drivers\WdBoot.sys',
            'C:\Windows\System32\drivers\WdNisDrv.sys',
            'C:\Windows\System32\SecurityHealthService.exe',
            'C:\Windows\System32\SecurityHealthSystray.exe',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
            'Registry::HKEY_CLASSES_ROOT\windowsdefender')) {
        '{0} : {1}' -f $p, (Test-Path -LiteralPath $p)
    }
}

Add-Section $main 'Folder: C:\Program Files\Windows Defender' {
    Get-ChildItem 'C:\Program Files\Windows Defender' -Force -ErrorAction SilentlyContinue |
        Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
}

Add-Section $main 'Folder: C:\ProgramData\Microsoft\Windows Defender (+ Platform versions)' {
    Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender' -Force -ErrorAction SilentlyContinue |
        Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
    'Platform versions:'
    Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform' -Force -ErrorAction SilentlyContinue |
        Select-Object Name, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
}

Add-Section $main 'Windows Security app (AppX)' {
    'Installed packages:'
    Get-AppxPackage -AllUsers -Name '*SecHealth*' | Format-List Name, Version, Status, InstallLocation | Out-String
    'Provisioned packages:'
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -match 'SecHealth' | Format-List DisplayName, Version | Out-String
}

Add-Section $main 'Keys that block re-registering the Security app' {
    $st = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    'Deprovisioned entries matching SecHealth:'
    Get-ChildItem "$st\Deprovisioned" -ErrorAction SilentlyContinue | Where-Object Name -match 'SecHealth' | Select-Object -ExpandProperty Name
    'EndOfLife entries matching SecHealth:'
    Get-ChildItem "$st\EndOfLife" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -match 'SecHealth' | Select-Object -ExpandProperty Name
}

Add-Section $main 'Defender status (Get-MpComputerStatus)' {
    Get-MpComputerStatus | Format-List AMServiceEnabled, AMRunningMode, AntivirusEnabled, AntispywareEnabled,
        RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled,
        NISEnabled, IsTamperProtected, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion,
        AntivirusSignatureAge, QuickScanAge, FullScanAge | Out-String
}

Add-Section $main 'Defender preferences (disable flags and exclusions)' {
    Get-MpPreference | Format-List Disable*, Exclusion*, MAPSReporting, SubmitSamplesConsent, PUAProtection, CloudBlockLevel | Out-String
}

Add-Section $main 'Detected threats' {
    Get-MpThreat | Format-List ThreatID, ThreatName, IsActive | Out-String
}

Add-Section $main 'Defender scheduled tasks' {
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\*' -ErrorAction SilentlyContinue |
        Format-Table TaskName, State -AutoSize | Out-String
}

Add-Section $main 'Security settings (UAC, mitigations, SmartScreen, tamper protection)' {
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $mm  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    "EnableLUA                  = $(Get-RegVal $sys 'EnableLUA')"
    "ConsentPromptBehaviorAdmin = $(Get-RegVal $sys 'ConsentPromptBehaviorAdmin')"
    "FeatureSettingsOverride    = $(Get-RegVal $mm 'FeatureSettingsOverride')"
    "FeatureSettingsOverrideMask= $(Get-RegVal $mm 'FeatureSettingsOverrideMask')"
    "SmartScreenEnabled         = $(Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')"
    "EnableSmartScreen (policy) = $(Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')"
    "TamperProtection           = $(Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' 'TamperProtection')"
    ''
    'bcdedit {current}:'
    bcdedit /enum '{current}'
}

Add-Section $main 'Security Center products (root/SecurityCenter2; may not exist on Server)' {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Format-List displayName, productState
}

Add-Section $main 'Component store (WinSxS) Defender / SecHealth folders' {
    $d = @(Get-ChildItem 'C:\Windows\WinSxS' -Directory -Force -ErrorAction SilentlyContinue | Where-Object Name -match 'defender|sechealth')
    "Matching folders in WinSxS: $($d.Count)"
    $d | Select-Object -First 40 -ExpandProperty Name
}

Add-Section $main 'Servicing packages (Defender / SecHealth)' {
    Get-WindowsPackage -Online | Where-Object PackageName -match 'Defender|SecHealth' |
        Format-Table PackageName, PackageState -AutoSize | Out-String -Width 250
}

# ------------------------------ REGISTRY DUMP --------------------------------
Write-Host '  exporting registry keys...'
$keys = @(
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center',
    'HKLM\SOFTWARE\Microsoft\Windows Defender',
    'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center',
    'HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
    'HKLM\SOFTWARE\Policies\Microsoft\Windows\Servicing',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend',
    'HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc',
    'HKLM\SYSTEM\CurrentControlSet\Services\WdFilter',
    'HKLM\SYSTEM\CurrentControlSet\Services\WdBoot',
    'HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv',
    'HKLM\SYSTEM\CurrentControlSet\Services\wscsvc',
    'HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService',
    'HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker',
    'HKLM\SYSTEM\CurrentControlSet\Services\Sgrm',
    'HKCR\windowsdefender'
)
foreach ($k in $keys) {
    Add-Section $reg $k { Export-Reg -Key $k }
}

# ---------------------------------- LOGS -------------------------------------
Add-Section $logs 'Defender operational log (last 60 events)' {
    Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 60 -ErrorAction SilentlyContinue |
        ForEach-Object { '{0:yyyy-MM-dd HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, (($_.Message -split "`n")[0]).Trim() }
}

Add-Section $logs 'System log: Defender/Security service events (last 2 days)' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Defender|WinDefend|WdNis|WdFilter|Security Center|SecurityHealth|Sgrm' } |
        Select-Object -First 60 |
        ForEach-Object { '{0:yyyy-MM-dd HH:mm:ss} id={1} {2}' -f $_.TimeCreated, $_.Id, (($_.Message -split "`n")[0]).Trim() }
}

Add-Section $logs 'dism.log (last 120 lines)' {
    Get-Content 'C:\Windows\Logs\DISM\dism.log' -Tail 120 -ErrorAction SilentlyContinue
}

Add-Section $logs 'CBS.log (last 120 lines)' {
    Get-Content 'C:\Windows\Logs\CBS\CBS.log' -Tail 120 -ErrorAction SilentlyContinue
}

# ------------------------------ BACKUP SEARCH --------------------------------
Add-Section $bk 'Top-level folders on C:' {
    Get-ChildItem C:\ -Force -ErrorAction SilentlyContinue |
        Select-Object Mode, Name, CreationTime, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
}

Add-Section $bk 'Copies of Defender binaries outside the normal locations' {
    $roots = @('C:\ProgramData', 'C:\Windows\Temp', 'C:\Users', 'C:\Windows.old', 'C:\Recovery', $env:TEMP)
    Get-ChildItem -Path $roots -Recurse -Force -Include MsMpEng.exe, MpSvc.dll, MpClient.dll, MpCmdRun.exe, SecurityHealthService.exe, WdFilter.sys -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\Microsoft\\Windows Defender\\(Platform|Definition Updates)\\' } |
        Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
}

Add-Section $bk "Files/folders named like 'defender' or 'restore' (outside Defender's own folders, first 150)" {
    Get-ChildItem -Path 'C:\ProgramData', 'C:\Users', 'C:\Windows\Temp' -Recurse -Force -Include *defender*, *restore* -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\Microsoft\\Windows Defender' -and $_.FullName -notmatch '\\Microsoft\\Windows Defender Advanced' } |
        Select-Object -First 150 FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 250
}

if ($ToolFolder -and (Test-Path $ToolFolder)) {
    Add-Section $bk "Restore tool folder: $ToolFolder (first 500 entries)" {
        Get-ChildItem $ToolFolder -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 500 FullName, Length, LastWriteTime |
            Format-Table -AutoSize | Out-String -Width 250
    }
}
else {
    Add-Section $bk 'Restore tool folder' { 'No -ToolFolder given, or the path does not exist.' }
}

# ---------------------------------- ZIP --------------------------------------
$zip = "$Out.zip"
try {
    Compress-Archive -Path (Join-Path $Out '*') -DestinationPath $zip -Force
}
catch {
    Write-Host "Could not create zip: $_" -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Finished. Upload these files:' -ForegroundColor Green
Get-ChildItem $Out -Filter 'diag-*.txt' | ForEach-Object { Write-Host "  $($_.FullName)" }
if (Test-Path $zip) { Write-Host "Zip of everything: $zip" }
