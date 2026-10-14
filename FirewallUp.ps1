# Run as Administrator

Write-Host "=== Enable Windows Firewall ===" -ForegroundColor Cyan

# Enable Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

Write-Host "`nFirewall has been enabled for all profiles." -ForegroundColor Green

# Display status
Write-Host "`nCurrent Firewall Status:" -ForegroundColor Yellow

Get-NetFirewallProfile |
Select-Object Name, Enabled |
Format-Table -AutoSize

Pause