# Requires Administrator

# ==============================
# Configuration
# ==============================

$AuditFolder = "C:\PortAudit"
$AuditLog = "$AuditFolder\PortAudit.log"

# Create audit folder/file if needed
if (!(Test-Path $AuditFolder)) {
    New-Item -Path $AuditFolder -ItemType Directory -Force | Out-Null
}

if (!(Test-Path $AuditLog)) {
    New-Item -Path $AuditLog -ItemType File -Force | Out-Null
}

# Ports that should stay open on a basic IIS server
$DesiredPorts = @(
    '80',
    '443'
)

# ==============================
# Logging Function
# ==============================

function Write-AuditLog {
    param(
        [string]$Action,
        [string]$Port
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Add-Content -Path $AuditLog -Value "$Timestamp | $Action | Port $Port"
}

# ==============================
# Display Ports
# ==============================

function Show-Ports {

    Clear-Host

    Write-Host "==== ACTIVE LISTENING PORTS ====" -ForegroundColor Cyan

    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "==== INBOUND FIREWALL RULES ====" -ForegroundColor Green

    $Results = Get-NetFirewallRule -Enabled True -Direction Inbound |
        ForEach-Object {

            $Rule = $_

            Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue |
            Select-Object @{
                Name = "Status"
                Expression = {
                    if ($_.LocalPort -in $DesiredPorts) {
                        "[KEEP]"
                    }
                    else {
                        "[REMOVE]"
                    }
                }
            }, @{
                Name = "RuleName"
                Expression = {
                    $Rule.DisplayName
                }
            }, Protocol, LocalPort
        } |
        Where-Object { $_.LocalPort -ne "Any" }

    $Results |
        Sort-Object `
            @{Expression = { if ($_.Status -eq "[KEEP]") { 0 } else { 1 } }},
            LocalPort |
        Format-Table -Wrap -AutoSize

    Write-Host ""
    Write-Host "Audit Log: $AuditLog" -ForegroundColor DarkGray
}

# ==============================
# Open Port
# ==============================

function Open-Port {
    param(
        [int]$Port
    )

    $RuleName = "Competition Open Port $Port"

    if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {

        New-NetFirewallRule `
            -DisplayName $RuleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $Port `
            -Action Allow | Out-Null

        Write-AuditLog -Action "OPENED" -Port $Port

        Write-Host ""
        Write-Host "Port $Port opened." -ForegroundColor Green
    }
    else {

        Enable-NetFirewallRule -DisplayName $RuleName

        Write-AuditLog -Action "OPENED" -Port $Port

        Write-Host ""
        Write-Host "Port $Port enabled." -ForegroundColor Green
    }
}

# ==============================
# Close Port
# ==============================

function Close-Port {
    param(
        [int]$Port
    )

    $RuleName = "Competition Open Port $Port"

    if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {

        Disable-NetFirewallRule -DisplayName $RuleName

        Write-AuditLog -Action "CLOSED" -Port $Port

        Write-Host ""
        Write-Host "Port $Port closed." -ForegroundColor Yellow
        return
    }

    $Rules = Get-NetFirewallRule -Enabled True -Direction Inbound |
        ForEach-Object {

            $Rule = $_

            Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LocalPort -eq "$Port"
                } |
                ForEach-Object {
                    $Rule
                }
        }

    if ($Rules) {

        $Rules | Disable-NetFirewallRule

        Write-AuditLog -Action "CLOSED" -Port $Port

        Write-Host ""
        Write-Host "Disabled firewall rules associated with port $Port." -ForegroundColor Yellow
    }
    else {

        Write-Host ""
        Write-Host "No firewall rule found for port $Port." -ForegroundColor Red
    }
}

# ==============================
# Main Menu
# ==============================

do {

    Show-Ports

    Write-Host ""
    Write-Host "Commands" -ForegroundColor Cyan
    Write-Host "--------"
    Write-Host "open <port>"
    Write-Host "close <port>"
    Write-Host "refresh"
    Write-Host "exit"
    Write-Host ""

    $Command = Read-Host "Enter command"

    switch -Regex ($Command) {

        '^open\s+(\d+)$' {

            Open-Port -Port ([int]$Matches[1])
        }

        '^close\s+(\d+)$' {

            Close-Port -Port ([int]$Matches[1])
        }

        '^refresh$' {

        }

        '^exit$' {

            break
        }

        default {

            Write-Host ""
            Write-Host "Invalid command." -ForegroundColor Red
        }
    }

    Start-Sleep -Seconds 1

} while ($true)