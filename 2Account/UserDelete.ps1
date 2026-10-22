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
    $userToDelete = Read-Host "Enter username to delete (Q to quit)"

    if ($userToDelete -match '^[Qq]$')
    {
        break
    }

    if ([string]::IsNullOrWhiteSpace($userToDelete))
    {
        Write-Host ""
        Write-Host "No username entered." -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        continue
    }

    # Verify user exists
    $user = Get-LocalUser -Name $userToDelete -ErrorAction SilentlyContinue

    if (-not $user)
    {
        Write-Host ""
        Write-Host "User '$userToDelete' not found." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        continue
    }

    Write-Host ""
    $confirm = Read-Host "Are you sure you want to delete '$userToDelete'? (Y/N)"

    if ($confirm -match '^[Yy]$')
    {
        try
        {
            Remove-LocalUser -Name $userToDelete

            Write-Host ""
            Write-Host "[PASS] User '$userToDelete' has been deleted." -ForegroundColor Green
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
        Write-Host "Deletion cancelled." -ForegroundColor Yellow
    }

    Write-Host ""
    Read-Host "Press Enter to continue"

}
while ($true)

Write-Host ""
Write-Host "Exiting Local User Management..." -ForegroundColor Cyan