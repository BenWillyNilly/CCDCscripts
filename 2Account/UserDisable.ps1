# Run as Administrator

do
{
    Clear-Host

    Write-Host "=== Local User Management ===" -ForegroundColor Cyan
    Write-Host ""

    # Get local users
    $users = Get-LocalUser | Sort-Object Name

    # Display users
    $users | Format-Table Name, Enabled, LastLogon -AutoSize

    Write-Host ""

    $userToDisable = Read-Host "Enter username to disable (Q to quit)"

    if ($userToDisable -match '^[Qq]$')
    {
        break
    }

    if ([string]::IsNullOrWhiteSpace($userToDisable))
    {
        Write-Host ""
        Write-Host "No username entered." -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        continue
    }

    # Verify user exists
    $user = Get-LocalUser -Name $userToDisable -ErrorAction SilentlyContinue

    if (-not $user)
    {
        Write-Host ""
        Write-Host "User '$userToDisable' not found." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        continue
    }

    # Check if already disabled
    if (-not $user.Enabled)
    {
        Write-Host ""
        Write-Host "[INFO] User '$userToDisable' is already disabled." -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        continue
    }

    Write-Host ""
    $confirm = Read-Host "Are you sure you want to disable '$userToDisable'? (Y/N)"

    if ($confirm -match '^[Yy]$')
    {
        try
        {
            Disable-LocalUser -Name $userToDisable

            Write-Host ""
            Write-Host "[PASS] User '$userToDisable' has been disabled." -ForegroundColor Green
        }
        catch
        {
            Write-Host ""
            Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else
    {
        Write-Host ""
        Write-Host "Operation cancelled." -ForegroundColor Yellow
    }

    Write-Host ""
    Read-Host "Press Enter to continue"

}
while ($true)

Write-Host ""
Write-Host "Exiting Local User Management..." -ForegroundColor Cyan