#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reverts a "Defender Remover"-style script on Windows Server 2022 (also works on Win 10/11 with notes).

.NOTES
    - Run in an elevated PowerShell. Reboot when finished (twice if prompted).
    - Take a checkpoint/snapshot first if this is a VM.
    - Registry backups are saved to C:\DefenderRestore_Backup.
    - If the machine was attacked (rather than you running a remover yourself),
      treat it as compromised: rotate credentials, check for persistence,
      and consider rebuilding from known-good media.
#>

$ErrorActionPreference = 'Continue'
$backup = 'C:\DefenderRestore_Backup'
New-Item -ItemType Directory -Path $backup -Force | Out-Null
Start-Transcript -Path "$backup\restore-log.txt" -Append | Out-Null

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }

function Remove-RegKey($path) {
    if (Test-Path $path) {
        $name = ($path -replace '[:\\ ]', '_')
        reg export ($path -replace '^HKLM:', 'HKLM') "$backup\$name.reg" /y 2>$null | Out-Null
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed key: $path"
    }
}
function Remove-RegValue($path, $names) {
    foreach ($n in $names) {
        if ((Test-Path $path) -and ($null -ne (Get-ItemProperty $path -Name $n -ErrorAction SilentlyContinue).$n)) {
            Remove-ItemProperty -Path $path -Name $n -Force -ErrorAction SilentlyContinue
            Write-Host "Removed value: $path\$n"
        }
    }
}
function Set-RegDword($path, $name, $value) {
    if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWord -Force | Out-Null
    Write-Host "Set $path\$name = $value"
}

# ---------------------------------------------------------------------------
Step '1. Remove Defender / SmartScreen / Security Center policies'
# ---------------------------------------------------------------------------
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\MRT'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartScreen'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
Remove-RegKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppHost'

Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' @('EnableSmartScreen','ShellSmartScreenLevel')
Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows Defender' @('DisableAntiSpyware','DisableAntiVirus','PUAProtection')
Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' @('SettingsPageVisibility')
Remove-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' @('SettingsPageVisibility')
Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' @('SmartScreenEnabled')
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -Value 'Warn' -ErrorAction SilentlyContinue

# Per-user SmartScreen / Edge
Remove-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' @('EnableWebContentEvaluation','PreventOverride')

# Re-add the tray icon
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityHealth' `
    -Value '%windir%\system32\SecurityHealthSystray.exe' -PropertyType ExpandString -Force | Out-Null

# ---------------------------------------------------------------------------
Step '2. Restore UAC / File Virtualization (LUA)'
# ---------------------------------------------------------------------------
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-RegDword $sys 'EnableLUA' 1
Set-RegDword $sys 'EnableVirtualization' 1
Set-RegDword $sys 'ConsentPromptBehaviorAdmin' 5   # default: prompt for consent for non-Windows binaries
Set-RegDword $sys 'ConsentPromptBehaviorUser' 3
Set-RegDword $sys 'PromptOnSecureDesktop' 1
Set-RegDword $sys 'EnableInstallerDetection' 1
Remove-RegValue $sys @('FilterAdministratorToken')

# ---------------------------------------------------------------------------
Step '3. Restore hypervisor launch (VBS / HVCI support)'
# ---------------------------------------------------------------------------
bcdedit /set hypervisorlaunchtype auto | Out-Null
Write-Host 'hypervisorlaunchtype = auto'

# ---------------------------------------------------------------------------
Step '4. Revert system mitigations (Spectre/Meltdown, kernel/service mitigations, Exploit Guard)'
# ---------------------------------------------------------------------------
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' @('FeatureSettingsOverride','FeatureSettingsOverrideMask')
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' @('MitigationOptions','MitigationAuditOptions')
Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' @('MitigationOptions','MitigationAuditOptions')
Remove-RegKey   'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard'
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' @('EnableVirtualizationBasedSecurity','RequirePlatformSecurityFeatures')
Remove-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' @('Enabled')

# Per-process mitigation overrides under IFEO (only removes MitigationOptions values; other IFEO settings untouched)
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-RegValue $_.PSPath @('MitigationOptions','MitigationAuditOptions') }

# Confirm what the system now reports
try { Get-ProcessMitigation -System | Out-Host } catch {}

# ---------------------------------------------------------------------------
Step '5. Restore service start types'
# ---------------------------------------------------------------------------
# Defaults for Server 2022. 0=Boot 2=Automatic 3=Manual 4=Disabled
$services = [ordered]@{
    'WdFilter'              = 0
    'WdBoot'                = 0
    'WinDefend'             = 2
    'WdNisSvc'              = 3
    'WdNisDrv'              = 3
    'Sense'                 = 3
    'wscsvc'                = 2
    'SecurityHealthService' = 3
    'SgrmBroker'            = 2
    'Sgrm'                  = 0
    'webthreatdefsvc'       = 3
}
foreach ($s in $services.GetEnumerator()) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Key)"
    if (Test-Path $key) {
        Set-ItemProperty $key -Name Start -Value $s.Value -Force
        if ($s.Key -in 'wscsvc','SgrmBroker') { Set-ItemProperty $key -Name DelayedAutostart -Value 1 -Force -ErrorAction SilentlyContinue }
        Write-Host "Service $($s.Key) -> Start=$($s.Value)"
    } else {
        Write-Warning "Service key missing: $($s.Key)  (will be restored by feature reinstall / DISM below)"
    }
}

# ---------------------------------------------------------------------------
Step '6. Re-register Defender shell context-menu handlers (Scan with Defender)'
# ---------------------------------------------------------------------------
$clsid = '{09A47860-11B0-4DA5-AFA5-26D86198A780}'
foreach ($p in 'Registry::HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\EPP',
               'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\EPP',
               'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\EPP') {
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name '(default)' -Value $clsid
}
Write-Host 'Context menu handlers restored (takes effect after Explorer restart).'

# ---------------------------------------------------------------------------
Step '7. Re-enable Defender scheduled tasks'
# ---------------------------------------------------------------------------
Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -ErrorAction SilentlyContinue |
    ForEach-Object { Enable-ScheduledTask -InputObject $_ | Out-Null; Write-Host "Enabled task: $($_.TaskName)" }
Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'SmartScreenSpecific' -ErrorAction SilentlyContinue |
    ForEach-Object { Enable-ScheduledTask -InputObject $_ | Out-Null }

# ---------------------------------------------------------------------------
Step '8. Repair / reinstall missing components (restores deleted files, drivers, services)'
# ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$isServer = $os.ProductType -ne 1

if ($isServer) {
    $feat = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
    if ($feat -and $feat.Installed) {
        Write-Host 'Defender feature shows as installed; files may still be missing. Running DISM/SFC repair...'
    } else {
        Write-Host 'Installing Windows-Defender feature...'
        Install-WindowsFeature -Name Windows-Defender -IncludeManagementTools | Out-Host
    }
    # GUI feature (Windows Security app) is optional on Server
    Install-WindowsFeature -Name Windows-Defender-GUI -ErrorAction SilentlyContinue | Out-Host
} else {
    Get-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-Default-Definitions' -ErrorAction SilentlyContinue |
        Where-Object State -ne 'Enabled' |
        ForEach-Object { Enable-WindowsOptionalFeature -Online -FeatureName $_.FeatureName -NoRestart }
    # Windows Security UWP app (client SKUs only)
    Get-AppxPackage -AllUsers -Name 'Microsoft.SecHealthUI' | ForEach-Object {
        Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
    }
    Get-AppxPackage -AllUsers -Name 'Microsoft.SecHealthUI' | Out-Host
}

Write-Host "`nRunning DISM RestoreHealth (needs Windows Update or a source - this can take a while)..."
DISM /Online /Cleanup-Image /RestoreHealth
Write-Host "`nRunning SFC..."
sfc /scannow

# ---------------------------------------------------------------------------
Step '9. Start services and reset Defender preferences'
# ---------------------------------------------------------------------------
foreach ($svc in 'wscsvc','SgrmBroker','WinDefend','WdNisSvc','SecurityHealthService','Sense') {
    $o = Get-Service $svc -ErrorAction SilentlyContinue
    if ($o -and $o.Status -ne 'Running' -and $o.StartType -ne 'Disabled') {
        Start-Service $svc -ErrorAction SilentlyContinue
    }
}

try {
    Set-MpPreference -DisableRealtimeMonitoring $false `
                     -DisableBehaviorMonitoring $false `
                     -DisableBlockAtFirstSeen $false `
                     -DisableIOAVProtection $false `
                     -DisableScriptScanning $false `
                     -DisableArchiveScanning $false `
                     -DisableIntrusionPreventionSystem $false `
                     -MAPSReporting Advanced `
                     -SubmitSamplesConsent SendSafeSamples `
                     -PUAProtection Enabled `
                     -CloudBlockLevel High -ErrorAction Stop
    Update-MpSignature -ErrorAction SilentlyContinue
    Write-Host 'Defender preferences restored; signature update requested.'
} catch {
    Write-Warning "Defender not responding yet ($($_.Exception.Message)). Reboot and re-run this script."
}

# ---------------------------------------------------------------------------
Step 'Status'
# ---------------------------------------------------------------------------
Get-Service WinDefend,WdNisSvc,wscsvc,SgrmBroker,SecurityHealthService,Sense -ErrorAction SilentlyContinue |
    Format-Table Name,Status,StartType -AutoSize
try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List } catch {}

Write-Host "`nDone. REBOOT NOW. After reboot, run again if anything above shows as missing." -ForegroundColor Green
Stop-Transcript | Out-Null