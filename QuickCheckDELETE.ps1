# Persistence Check Script
# Run PowerShell as Administrator

Write-Host "=== Windows Persistence Audit ===" -ForegroundColor Cyan

# Common Run Keys
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

Write-Host "`n[+] Registry Run Keys" -ForegroundColor Yellow
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n$key"
        Get-ItemProperty $key |
        Select-Object * |
        Format-List
    }
}

# Startup Folder Items
Write-Host "`n[+] Startup Folders" -ForegroundColor Yellow

$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem $folder -Force |
        Select-Object Name, FullName, CreationTime
    }
}

# Scheduled Tasks
Write-Host "`n[+] Scheduled Tasks" -ForegroundColor Yellow

Get-ScheduledTask |
Where-Object {
    $_.State -ne "Disabled"
} |
Select-Object TaskName, TaskPath |
Sort-Object TaskName

# Services with Non-Microsoft Paths
Write-Host "`n[+] Auto-Start Services" -ForegroundColor Yellow

Get-CimInstance Win32_Service |
Where-Object { $_.StartMode -eq "Auto" } |
Select-Object Name, State, StartMode, PathName

# WMI Event Subscriptions
Write-Host "`n[+] WMI Persistence Checks" -ForegroundColor Yellow

Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue

# Recent Local Users
Write-Host "`n[+] Local User Accounts" -ForegroundColor Yellow

Get-LocalUser |
Select-Object Name, Enabled, LastLogon

# Network Connections
Write-Host "`n[+] Active Network Connections" -ForegroundColor Yellow

Get-NetTCPConnection |
Where-Object { $_.State -eq "Established" } |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort

Write-Host "`n=== Audit Complete ===" -ForegroundColor Green

pause