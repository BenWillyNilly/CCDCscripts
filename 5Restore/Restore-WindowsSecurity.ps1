<#
.SYNOPSIS
    Re-enables Windows Security (Defender, Firewall, SmartScreen, UAC) and
    Windows Update settings that were disabled by "Defender remover" or
    "update blocker" style tools.

.DESCRIPTION
    Works through every common place those tools make changes:
      * Services and kernel drivers (start types + start them)
      * Policy and non-policy registry keys (machine and every loaded user hive)
      * Image File Execution Options "Debugger" blocks
      * Security Health tray startup entry
      * Scheduled tasks for Defender / Windows Update
      * Defender preferences (Set-MpPreference)
      * Firewall profiles
      * hosts-file blocks of Microsoft update/security domains
      * (optional) Local Group Policy reset, component repair, update cache reset

    Every registry key is exported to a .reg backup before it is changed, and
    the hosts file and policy files are copied before modification. Backups and
    a log are written to %ProgramData%\SecurityRestore-<timestamp>.

.PARAMETER ResetLocalGroupPolicy
    Deletes the LOCAL Group Policy Registry.pol files (backed up first) so
    that policy settings pushed by tools like LGPO / gpedit cannot re-apply.
    This removes ALL local policy settings, including any legitimate ones.

.PARAMETER RepairComponents
    Runs DISM /RestoreHealth + SFC and re-registers the Windows Security app.
    Use this if Defender files were actually deleted. Requires internet.

.PARAMETER ResetUpdateComponents
    Renames SoftwareDistribution and catroot2 so Windows Update rebuilds them.

.PARAMETER UpdateSignatures
    Downloads the latest Defender signatures when finished.

.EXAMPLE
    .\Restore-WindowsSecurity.ps1

.EXAMPLE
    .\Restore-WindowsSecurity.ps1 -ResetLocalGroupPolicy -RepairComponents -UpdateSignatures

.NOTES
    Run from an elevated PowerShell session. Reboot afterwards.
    Tamper Protection cannot be turned on by script - see the end of the output.
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$ResetLocalGroupPolicy,
    [switch]$RepairComponents,
    [switch]$ResetUpdateComponents,
    [switch]$UpdateSignatures
)

$ErrorActionPreference = 'Continue'
$stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupDir = Join-Path $env:ProgramData "SecurityRestore-$stamp"
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Start-Transcript -Path (Join-Path $BackupDir 'log.txt') | Out-Null

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
$script:BackedUp = @{}

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Skip($m) { Write-Host "  [--] $m" -ForegroundColor DarkGray }
function Write-Bad($m)  { Write-Host "  [!!] $m" -ForegroundColor Yellow }

function Backup-RegKey {
    param([string]$PsPath)
    $reg = ($PsPath -replace '^Registry::', '') -replace ':', ''
    if ($script:BackedUp.ContainsKey($reg)) { return }
    $file = Join-Path $BackupDir (($reg -replace '[\\/:*?"<>|]', '_') + '.reg')
    & reg.exe export $reg $file /y *> $null
    $script:BackedUp[$reg] = $true
}

function Remove-RegTree {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Backup-RegKey $Path
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Ok "Removed key: $Path"
    } catch { Write-Bad "Could not remove $Path : $($_.Exception.Message)" }
}

function Remove-RegValues {
    param([string]$Path, [string[]]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $key = Get-Item -LiteralPath $Path
    foreach ($n in $Name) {
        if ($null -ne $key.GetValue($n, $null)) {
            try {
                Backup-RegKey $Path
                Remove-ItemProperty -LiteralPath $Path -Name $n -Force -ErrorAction Stop
                Write-Ok "Removed value: $Path\$n"
            } catch { Write-Bad "Could not remove $Path\$n : $($_.Exception.Message)" }
        }
    }
}

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    try {
        if (Test-Path -LiteralPath $Path) { Backup-RegKey $Path }
        else { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        Write-Ok "Set $Path\$Name = $Value"
    } catch { Write-Bad "Could not set $Path\$Name : $($_.Exception.Message)" }
}

function Set-StartType {
    param([string]$Name, [int]$Start, [bool]$Delayed = $false)
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $key)) { Write-Skip "$Name not present on this system"; return }
    try {
        Backup-RegKey $key
        Set-ItemProperty -LiteralPath $key -Name Start -Value $Start -Type DWord -ErrorAction Stop
        if ($Delayed) { Set-ItemProperty -LiteralPath $key -Name DelayedAutostart -Value 1 -Type DWord -ErrorAction Stop }
        else          { Remove-ItemProperty -LiteralPath $key -Name DelayedAutostart -ErrorAction SilentlyContinue }
        Write-Ok "$Name start type restored (Start=$Start$(if($Delayed){', delayed'}))"
    } catch {
        # Protected service: fall back to the Service Control Manager
        $mode = switch ($Start) { 0 { 'boot' } 2 { if ($Delayed) { 'delayed-auto' } else { 'auto' } } 3 { 'demand' } default { 'demand' } }
        & sc.exe config $Name start= $mode *> $null
        if ($LASTEXITCODE -eq 0) { Write-Ok "$Name start type restored via sc.exe ($mode)" }
        else { Write-Bad "$Name is protected - could not change start type. Try running as SYSTEM or from Safe Mode." }
    }
}

# Loaded per-user registry hives (HKCU of every logged-on / loaded profile)
$UserHives = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
    ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" }

# ----------------------------------------------------------------------------
# 0. What is actually installed?
# ----------------------------------------------------------------------------
Write-Step 'Checking Defender files'
$mpEng = @("$env:ProgramFiles\Windows Defender\MsMpEng.exe") +
         @(Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" -Recurse -Filter MsMpEng.exe -ErrorAction SilentlyContinue | ForEach-Object FullName)
$defenderFilesPresent = [bool]($mpEng | Where-Object { Test-Path $_ })
if ($defenderFilesPresent) { Write-Ok 'Defender engine files found' }
else { Write-Bad 'MsMpEng.exe not found - the remover deleted Defender files. Re-run with -RepairComponents (and see notes at the end).' }

# ----------------------------------------------------------------------------
# 1. Local Group Policy (optional)
# ----------------------------------------------------------------------------
if ($ResetLocalGroupPolicy) {
    Write-Step 'Resetting LOCAL Group Policy'
    foreach ($f in "$env:windir\System32\GroupPolicy\Machine\Registry.pol", "$env:windir\System32\GroupPolicy\User\Registry.pol") {
        if (Test-Path $f) {
            $dest = Join-Path $BackupDir ((Split-Path $f -Parent | Split-Path -Leaf) + '_Registry.pol')
            Copy-Item $f $dest -Force
            Remove-Item $f -Force
            Write-Ok "Removed $f (backup: $dest)"
        } else { Write-Skip "No $f" }
    }
}

# ----------------------------------------------------------------------------
# 2. Registry: Defender / Security Center / SmartScreen / UAC / Windows Update
# ----------------------------------------------------------------------------
Write-Step 'Cleaning Defender and Security Center policies'
$policyTrees = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Defender Antivirus',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center',
    'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
)
$policyTrees | ForEach-Object { Remove-RegTree $_ }

Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows Defender' @('DisableAntiSpyware', 'DisableAntiVirus')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' @(
    'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection',
    'DisableScanOnRealtimeEnable', 'DisableIOAVProtection', 'DisableScriptScanning')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet' @('DisableBlockAtFirstSeen')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' @('DisableNotifications', 'DisableEnhancedNotifications')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Systray' @('HideSystray')

Write-Step 'Restoring SmartScreen'
Remove-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' @('EnableSmartScreen', 'ShellSmartScreenLevel')
Remove-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' @('SmartScreenEnabled', 'SmartScreenPuaEnabled', 'PreventSmartScreenPromptOverride', 'PreventSmartScreenPromptOverrideForFiles')
Remove-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' @('EnabledV9', 'PreventOverride', 'PreventOverrideAppRepUnknown')
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Warn' 'String'

Write-Step 'Restoring UAC'
$uac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-RegValue $uac 'EnableLUA' 1
Set-RegValue $uac 'ConsentPromptBehaviorAdmin' 5
Set-RegValue $uac 'PromptOnSecureDesktop' 1

Write-Step 'Cleaning Windows Update policies and pauses'
Remove-RegTree 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
Remove-RegTree 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired_Blocked'
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' @('AUOptions')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' @(
    'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
    'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime',
    'PauseUpdatesExpiryTime', 'PauseUpdatesStartTime')
Remove-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' @('AutoDownload')
Remove-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' @('DontOfferThroughWUAU')
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' @('NoWindowsUpdate')

Write-Step 'Cleaning per-user settings (all loaded user hives)'
foreach ($h in $UserHives) {
    Remove-RegTree   "$h\SOFTWARE\Policies\Microsoft\Windows Defender"
    Remove-RegTree   "$h\SOFTWARE\Policies\Microsoft\Windows Defender Security Center"
    Remove-RegTree   "$h\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Remove-RegValues "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" @('NoWindowsUpdate')
    Remove-RegValues "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" @('PreventOverride')
    Set-RegValue     "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' 1
}

# ----------------------------------------------------------------------------
# 3. Image File Execution Options "Debugger" blocks
# ----------------------------------------------------------------------------
Write-Step 'Removing IFEO blocks on security executables'
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$ifeoNames = 'MsMpEng.exe', 'MpCmdRun.exe', 'MpDefenderCoreService.exe', 'NisSrv.exe', 'MsSense.exe',
             'SecurityHealthService.exe', 'SecurityHealthSystray.exe', 'SecurityHealthHost.exe',
             'smartscreen.exe', 'wuauclt.exe', 'usoclient.exe', 'UsoSvc.exe', 'MoUsoCoreWorker.exe',
             'WaaSMedicAgent.exe', 'sihclient.exe', 'TiWorker.exe', 'TrustedInstaller.exe'
foreach ($exe in $ifeoNames) {
    Remove-RegValues (Join-Path $ifeoRoot $exe) @('Debugger', 'GlobalFlag')
}

# ----------------------------------------------------------------------------
# 4. Security Health tray startup entry
# ----------------------------------------------------------------------------
Write-Step 'Restoring Windows Security tray icon startup'
Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth' '%windir%\system32\SecurityHealthSystray.exe' 'ExpandString'
Remove-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' @('SecurityHealth')

# ----------------------------------------------------------------------------
# 5. Services and drivers
# ----------------------------------------------------------------------------
Write-Step 'Restoring service and driver start types'
# Start: 0=boot, 2=automatic, 3=manual, 4=disabled
$serviceDefaults = @(
    @{ Name = 'WinDefend';            Start = 2; Delayed = $false },
    @{ Name = 'WdNisSvc';             Start = 3; Delayed = $false },
    @{ Name = 'Sense';                Start = 3; Delayed = $false },
    @{ Name = 'SecurityHealthService';Start = 3; Delayed = $false },
    @{ Name = 'webthreatdefsvc';      Start = 3; Delayed = $false },
    @{ Name = 'wscsvc';               Start = 2; Delayed = $true  },
    @{ Name = 'BFE';                  Start = 2; Delayed = $false },
    @{ Name = 'mpssvc';               Start = 2; Delayed = $false },
    @{ Name = 'CryptSvc';             Start = 2; Delayed = $false },
    @{ Name = 'wuauserv';             Start = 3; Delayed = $false },
    @{ Name = 'UsoSvc';               Start = 2; Delayed = $true  },
    @{ Name = 'WaaSMedicSvc';         Start = 3; Delayed = $false },
    @{ Name = 'BITS';                 Start = 3; Delayed = $false },
    @{ Name = 'DoSvc';                Start = 2; Delayed = $true  },
    @{ Name = 'TrustedInstaller';     Start = 3; Delayed = $false },
    @{ Name = 'WdFilter';             Start = 0; Delayed = $false },   # driver
    @{ Name = 'WdBoot';               Start = 0; Delayed = $false },   # driver
    @{ Name = 'WdNisDrv';             Start = 3; Delayed = $false }    # driver
)
foreach ($s in $serviceDefaults) { Set-StartType -Name $s.Name -Start $s.Start -Delayed $s.Delayed }

# ----------------------------------------------------------------------------
# 6. Scheduled tasks
# ----------------------------------------------------------------------------
Write-Step 'Re-enabling Defender / Windows Update scheduled tasks'
$taskFolders = '\Microsoft\Windows\Windows Defender\', '\Microsoft\Windows\WindowsUpdate\',
               '\Microsoft\Windows\UpdateOrchestrator\', '\Microsoft\Windows\WaaSMedic\'
foreach ($tf in $taskFolders) {
    $tasks = Get-ScheduledTask -TaskPath $tf -ErrorAction SilentlyContinue
    if (-not $tasks) { Write-Skip "No tasks in $tf"; continue }
    foreach ($t in ($tasks | Where-Object { $_.State -eq 'Disabled' })) {
        try {
            Enable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null
            Write-Ok "Enabled task: $($t.TaskPath)$($t.TaskName)"
        } catch { Write-Bad "Could not enable $($t.TaskPath)$($t.TaskName): $($_.Exception.Message)" }
    }
}

# ----------------------------------------------------------------------------
# 7. hosts file blocks
# ----------------------------------------------------------------------------
Write-Step 'Checking hosts file for blocked Microsoft security/update domains'
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$pattern   = 'windowsupdate\.|update\.microsoft\.|delivery\.mp\.microsoft\.|wdcp(alt)?\.microsoft\.|definitionupdates\.microsoft\.|smartscreen|download\.microsoft\.com|ctldl\.'
if (Test-Path $hostsPath) {
    $lines   = Get-Content $hostsPath
    $changed = 0
    $newText = foreach ($l in $lines) {
        if ($l -notmatch '^\s*#' -and $l -match $pattern) { $changed++; "# [disabled by restore script] $l" } else { $l }
    }
    if ($changed -gt 0) {
        Copy-Item $hostsPath (Join-Path $BackupDir 'hosts.bak') -Force
        Set-Content -Path $hostsPath -Value $newText -Encoding ASCII
        Write-Ok "Commented out $changed blocking line(s) in hosts"
    } else { Write-Skip 'No blocking entries in hosts' }
}

# ----------------------------------------------------------------------------
# 8. Optional repairs
# ----------------------------------------------------------------------------
if ($ResetUpdateComponents) {
    Write-Step 'Resetting Windows Update components'
    $svcs = 'wuauserv', 'cryptsvc', 'bits', 'msiserver'
    foreach ($s in $svcs) { Stop-Service $s -Force -ErrorAction SilentlyContinue }
    foreach ($p in "$env:windir\SoftwareDistribution", "$env:windir\System32\catroot2") {
        if (Test-Path $p) {
            try { Rename-Item $p "$(Split-Path $p -Leaf).bak.$stamp" -ErrorAction Stop; Write-Ok "Renamed $p" }
            catch { Write-Bad "Could not rename $p : $($_.Exception.Message)" }
        }
    }
    foreach ($s in $svcs) { Start-Service $s -ErrorAction SilentlyContinue }
}

if ($RepairComponents) {
    Write-Step 'Repairing Windows components (this can take a while)'
    & DISM.exe /Online /Cleanup-Image /RestoreHealth
    & sfc.exe /scannow
    Get-AppxPackage -AllUsers Microsoft.SecHealthUI -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = Join-Path $_.InstallLocation 'AppXManifest.xml'
        if (Test-Path $manifest) {
            try { Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop; Write-Ok 'Re-registered Windows Security app' }
            catch { Write-Bad "Could not re-register Windows Security app: $($_.Exception.Message)" }
        }
    }
}

# ----------------------------------------------------------------------------
# 9. Start services
# ----------------------------------------------------------------------------
Write-Step 'Starting services'
foreach ($n in 'BFE', 'mpssvc', 'CryptSvc', 'wscsvc', 'WinDefend', 'WdNisSvc', 'SecurityHealthService', 'UsoSvc', 'wuauserv', 'BITS') {
    if (Get-Service -Name $n -ErrorAction SilentlyContinue) {
        try { Start-Service -Name $n -ErrorAction Stop; Write-Ok "Started $n" }
        catch { Write-Bad "$n did not start (a reboot is usually required): $($_.Exception.Message)" }
    }
}

# ----------------------------------------------------------------------------
# 10. Defender preferences and firewall
# ----------------------------------------------------------------------------
Write-Step 'Re-enabling Defender protections'
$wd = Get-Service WinDefend -ErrorAction SilentlyContinue
if ((Get-Command Set-MpPreference -ErrorAction SilentlyContinue) -and $wd -and $wd.Status -eq 'Running') {
    $prefs = [ordered]@{
        DisableRealtimeMonitoring          = $false
        DisableBehaviorMonitoring          = $false
        DisableBlockAtFirstSeen            = $false
        DisableIOAVProtection              = $false
        DisableScriptScanning              = $false
        DisableArchiveScanning             = $false
        DisableIntrusionPreventionSystem   = $false
        MAPSReporting                      = 'Advanced'
        SubmitSamplesConsent               = 'SendSafeSamples'
        PUAProtection                      = 'Enabled'
    }
    foreach ($k in $prefs.Keys) {
        try { Set-MpPreference @{ $k = $prefs[$k] } -ErrorAction Stop; Write-Ok "$k = $($prefs[$k])" }
        catch { Write-Bad "$k : $($_.Exception.Message)" }
    }

    $mp = Get-MpPreference
    if ($mp.ExclusionPath -or $mp.ExclusionExtension -or $mp.ExclusionProcess) {
        Write-Host "`n  Existing Defender EXCLUSIONS (review - the remover may have added these):" -ForegroundColor Yellow
        $mp.ExclusionPath      | ForEach-Object { Write-Host "    path:      $_" }
        $mp.ExclusionExtension | ForEach-Object { Write-Host "    extension: $_" }
        $mp.ExclusionProcess   | ForEach-Object { Write-Host "    process:   $_" }
    }

    if ($UpdateSignatures) {
        try { Update-MpSignature -ErrorAction Stop; Write-Ok 'Signatures updated' }
        catch { Write-Bad "Signature update failed: $($_.Exception.Message)" }
    }
} else {
    Write-Bad 'Defender service is not running yet - reboot, then re-run this script to apply Defender preferences.'
}

Write-Step 'Re-enabling Windows Firewall'
try {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
    Write-Ok 'Firewall enabled on Domain, Private and Public profiles'
} catch { Write-Bad "Firewall: $($_.Exception.Message)" }

$blockRules = Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'update|defender|windows security|smartscreen' }
if ($blockRules) {
    Write-Host "`n  Firewall BLOCK rules that look related to updates/security (review):" -ForegroundColor Yellow
    $blockRules | ForEach-Object { Write-Host "    $($_.DisplayName)  [$($_.Direction)]" }
}

# ----------------------------------------------------------------------------
# 11. Refresh policy and report
# ----------------------------------------------------------------------------
Write-Step 'Refreshing Group Policy'
& gpupdate.exe /force *> $null
Write-Ok 'gpupdate complete'

Write-Step 'Final status'
Get-Service -Name WinDefend, WdNisSvc, Sense, SecurityHealthService, wscsvc, mpssvc, BFE, wuauserv, UsoSvc, WaaSMedicSvc, BITS -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-Table -AutoSize

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    try {
        Get-MpComputerStatus -ErrorAction Stop |
            Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                          IoavProtectionEnabled, NISEnabled, IsTamperProtected, AntivirusSignatureLastUpdated |
            Format-List
    } catch { Write-Bad 'Defender status not available yet (reboot required).' }
}
Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled | Format-Table -AutoSize

Write-Host "`nManual steps still needed:" -ForegroundColor Cyan
Write-Host "  1. REBOOT now (drivers WdFilter/WdBoot and UAC only take effect after restart)."
Write-Host "  2. Turn Tamper Protection ON: Windows Security > Virus & threat protection > Manage settings."
Write-Host "     (It cannot be enabled from a script by design.)"
Write-Host "  3. Optional: Windows Security > Device security > Core isolation > Memory integrity = On."
if (-not $defenderFilesPresent) {
    Write-Host "  4. Defender files were missing: run with -RepairComponents. If MsMpEng.exe is still missing,"
    Write-Host "     do an in-place repair install (run setup.exe from a Windows ISO and choose 'Keep files and apps')."
}
Write-Host "`nBackups and log: $BackupDir" -ForegroundColor Cyan
Stop-Transcript | Out-Null
