# Run as Administrator

Write-Host "=== Local User Management ===" -ForegroundColor Cyan

# Get local users
$users = Get-LocalUser | Sort-Object Name

# Display users
$users | Format-Table Name, Enabled, LastLogon -AutoSize

Write-Host ""
$userToDelete = Read-Host "Enter the username to delete (or press Enter to quit)"

if ([string\]::IsNullOrWhiteSpace($userToDelete)) {
    Write-Host "No user selected. Exiting."
    exit
}

# Verify user exists
$user = Get-LocalUser -Name $userToDelete -ErrorAction SilentlyContinue

if (-not $user) {
    Write-Host "User '$userToDelete' not found." -ForegroundColor Red
    exit
}

$confirm = Read-Host "Are you sure you want to delete '$userToDelete'? (Y/N)"

if ($confirm -match '^[Yy]$') {
    try {
        Remove-LocalUser -Name $userToDelete
        Write-Host "User '$userToDelete' has been deleted." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to delete user: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host "Deletion cancelled." -ForegroundColor Yellow
}