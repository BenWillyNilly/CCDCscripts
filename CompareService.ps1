# =================================================================
# Find Running Services Not In Approved Baseline
# =================================================================

# Baseline services
$BaselineServices = @(
'AppHostSvc',
'AppXSvc',
'BFE',
'BrokerInfrastructure',
'camsvc',
'cbdhsvc',
'CDPSvc',
'ClipSVC',
'CoreMessagingRegistrar',
'CryptSvc',
'DcomLaunch',
'Dhcp',
'DiagTrack',
'DispBrokerDesktopSvc',
'Dnscache',
'DoSvc',
'DPS',
'edgeupdate',
'EventLog',
'EventSystem',
'FontCache',
'gpsvc',
'IKEEXT',
'iphlpsvc',
'KeyIso',
'LanmanServer',
'LanmanWorkstation',
'lmhosts',
'LSM',
'MDCoreSvc',
'MSDTC',
'mpssvc',
'NcbService',
'netprofm',
'NetSetupSvc',
'NlaSvc',
'nsi',
'PcaSvc',
'PlugPlay',
'Power',
'ProfSvc',
'RasMan',
'RemoteRegistry',
'RpcEptMapper',
'RpcSs',
'SamSs',
'Schedule',
'SENS',
'ShellHWDetection',
'Spooler',
'SstpSvc',
'StateRepository',
'StorSvc',
'SysMain',
'SystemEventsBroker',
'TabletInputService',
'Themes',
'TimeBrokerSvc',
'TokenBroker',
'TrustedInstaller',
'TrkWks',
'UALSVC',
'UserManager',
'UsoSvc',
'VBoxService',
'W32Time',
'W3SVC',
'WAS',
'Wcmsvc',
'WdNisSvc',
'WinDefend',
'WinHttpAutoProxySvc',
'Winmgmt',
'WinRM',
'wlidsvc',
'WLMS',
'WPDBusEnum',
'WpnService',
'wuauserv',
'Appinfo',
'NgcCtnrSvc',
'NgcSvc',
'SecurityHealthService',
'VaultSvc',
'WbioSrvc'
)

# Service name patterns that have random suffixes
$WildcardServices = @(
'CDPUserSvc_*',
'WpnUserService_*',
'cbdhsvc_*'
)


# Service name patterns that have random suffixes
$WildcardServices = @(
'CDPUserSvc_*',
'WpnUserService_*'
)

# Get all running services
$RunningServices = Get-Service | Where-Object {
    $_.Status -eq 'Running'
}

# Find services that are not in the baseline
$ExtraServices = foreach ($Service in $RunningServices) {

    $Allowed = $false

    # Exact match
    if ($Service.Name -in $BaselineServices) {
        $Allowed = $true
    }

    # Wildcard match
    foreach ($Pattern in $WildcardServices) {
        if ($Service.Name -like $Pattern) {
            $Allowed = $true
            break
        }
    }

    if (-not $Allowed) {
        [PSCustomObject]@{
            ServiceName = $Service.Name
            DisplayName = $Service.DisplayName
        }
    }
}

Write-Host ""
Write-Host "=== EXTRA RUNNING SERVICES ===" -ForegroundColor Yellow
Write-Host ""

if ($ExtraServices) {
    $ExtraServices |
        Sort-Object ServiceName |
        Format-Table -AutoSize
}
else {
    Write-Host "No extra running services found." -ForegroundColor Green
}
pause