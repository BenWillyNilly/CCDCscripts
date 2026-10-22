$PIDToKill = Read-Host "Enter PID"

Get-Process -Id $PIDToKill

$confirm = Read-Host "Stop this process? (Y/N)"

if ($confirm -eq "Y")
{
Stop-Process -Id $PIDToKill -Force
Write-Host "Process terminated." -ForegroundColor Green
}