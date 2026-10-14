# Run as Administrator

Write-Host "=== Local User Management ===" -ForegroundColor Cyan

# Get local users
$users = Get-LocalUser | Sort-Object Name

# Display users
$users | Format-Table Name, Enabled, LastLogon -AutoSize

Write-Host ""

$userToDisable = Read-Host "Enter the username to disable (or press Enter to quit)"

if ([string\]::IsNullOrWhiteSpace($userToDisable)) {
    Write-Host "No user selected. Exiting."
    exit
}

# Verify user exists
$user = Get-LocalUser -Name $userToDisable -ErrorAction SilentlyContinue

if (-not $user) {
    Write-Host "User '$userToDisable' not found." -ForegroundColor Red
    exit
}

$confirm = Read-Host "Are you sure you want to disable '$userToDisable'? (Y/N)"

if ($confirm -match '^[Yy]$') {
    try {
        Disable-LocalUser -Name $userToDisable
        Write-Host "User '$userToDisable' has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to disable user: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
}