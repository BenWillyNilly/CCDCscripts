Clear-Host

$Log = "$env:USERPROFILE\Desktop\SystemAudit.log"

$Pass = 0
$Fail = 0
$Warn = 0

# =========================================
# SYSTEM INFORMATION
# =========================================

$OS = Get-CimInstance Win32_OperatingSystem

$Build = (Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " SYSTEM INFORMATION" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

Write-Host "OS Name    : $($OS.Caption)"
Write-Host "Version    : $($OS.Version)"
Write-Host "Build      : $Build"
Write-Host "Computer   : $env:COMPUTERNAME"

Write-Host ""

Write-Host "FIREWALL PROFILES"
Write-Host "-----------------------------------------"

try
{
    $Profiles = Get-NetFirewallProfile

    foreach ($Profile in $Profiles)
    {
        if ($Profile.Enabled)
        {
            Write-Host "[ PASS ] $($Profile.Name) Firewall Enabled" -ForegroundColor Green
        }
        else
        {
            Write-Host "[ FAIL ] $($Profile.Name) Firewall Disabled" -ForegroundColor Red
        }
    }
}
catch
{
    Write-Host "[ FAIL ] Unable to query firewall state" -ForegroundColor Red
}

Write-Host ""

function Write-Result {
    param(
        [string]$Status,
        [string]$Name
    )

    switch ($Status)
    {
        "PASS" {
            Write-Host "[ PASS ] $Name" -ForegroundColor Green
            $script:Pass++
        }

        "FAIL" {
            Write-Host "[ FAIL ] $Name" -ForegroundColor Red
            $script:Fail++
        }

        "WARN" {
            Write-Host "[ WARN ] $Name" -ForegroundColor Yellow
            $script:Warn++
        }
    }

    Add-Content $Log "[$Status] $Name"
}

function Test-Program {
    param(
        [string]$Name,
        [string]$Path,
        [switch]$Optional
    )

    if (Test-Path $Path)
    {
        Write-Result PASS $Name
    }
    else
    {
        if ($Optional)
        {
            Write-Result WARN "$Name Missing"
        }
        else
        {
            Write-Result FAIL "$Name Missing"
        }
    }
}

function Test-ServiceStatus {
    param(
        [string]$Name
    )

    $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (!$Svc)
    {
        Write-Result FAIL "$Name Service Missing"
        return
    }

    if ($Svc.Status -eq 'Running')
    {
        Write-Result PASS "$Name Running"
    }
    else
    {
        Write-Result FAIL "$Name Stopped"
    }
}

"" | Out-File $Log

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " WINDOWS SYSTEM AUDIT" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "TOOLS"
Write-Host "-----------------------------------------"

Test-Program "DISM" "$env:windir\System32\dism.exe"
Test-Program "SFC" "$env:windir\System32\sfc.exe"
Test-Program "PowerShell" "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
Test-Program "CMD" "$env:windir\System32\cmd.exe"
Test-Program "REG" "$env:windir\System32\reg.exe"
Test-Program "SC" "$env:windir\System32\sc.exe"
Test-Program "NETSH" "$env:windir\System32\netsh.exe"
Test-Program "TASKLIST" "$env:windir\System32\tasklist.exe"
Test-Program "TASKKILL" "$env:windir\System32\taskkill.exe"
Test-Program "WHOAMI" "$env:windir\System32\whoami.exe"
Test-Program "PING" "$env:windir\System32\ping.exe"
Test-Program "IPCONFIG" "$env:windir\System32\ipconfig.exe"

# Optional on modern Windows
Test-Program "WMIC" "$env:windir\System32\wbem\wmic.exe" -Optional

Write-Host ""
Write-Host "SERVICES"
Write-Host "-----------------------------------------"

Test-ServiceStatus "RpcSs"
Test-ServiceStatus "EventLog"
Test-ServiceStatus "BITS"
Test-ServiceStatus "CryptSvc"
Test-ServiceStatus "Winmgmt"
Test-ServiceStatus "Schedule"

# Security Services
Test-ServiceStatus "WinDefend"
Test-ServiceStatus "SecurityHealthService"
Test-ServiceStatus "wscsvc"

Write-Host ""
Write-Host "SUMMARY"
Write-Host "-----------------------------------------"

Write-Host "PASS : $Pass" -ForegroundColor Green
Write-Host "FAIL : $Fail" -ForegroundColor Red
Write-Host "WARN : $Warn" -ForegroundColor Yellow

Write-Host ""
Write-Host "Log File:"
Write-Host $Log -ForegroundColor Cyan

Write-Host ""
Read-Host "Press Enter to Exit"