# Event Viewer Security Investigation Tool

Clear-Host

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Event Viewer Investigation Tool"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Search Recommended Security Event IDs"
Write-Host "2. Search Newly Installed Services Only"
Write-Host ""

$choice = Read-Host "Select an option (1 or 2)"

$days = Read-Host "Search how many days back? (Example: 30)"

try {
    $StartDate = (Get-Date).AddDays(-[int]$days)
}
catch {
    Write-Host "Invalid number entered." -ForegroundColor Red
    exit
}

switch ($choice) {

    "1" {

        $SuspiciousEventIDs = @(
            7045, # Service Installed
            4697, # Service Installed
            4698, # Scheduled Task Created
            4702, # Scheduled Task Modified
            4720, # User Created
            4726, # User Deleted
            4732, # User Added to Group
            4733, # User Removed from Group
            4672, # Special Admin Privileges
            1102  # Audit Log Cleared
        )

        Write-Host ""
        Write-Host "Searching..." -ForegroundColor Yellow

       Get-WinEvent -FilterHashtable @{
       LogName = @("System","Security")
       StartTime = $StartDate
       } -ErrorAction SilentlyContinue |
        Where-Object {
            $SuspiciousEventIDs -contains $_.Id
        } |
        Select-Object TimeCreated,
                      Id,
                      ProviderName,
                      LevelDisplayName,
                      Message |
        Out-GridView -Title "Recommended Security Events"

    }

    "2" {

        Write-Host ""
        Write-Host "Searching for installed services..." -ForegroundColor Yellow

        Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $StartDate
        } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated,
                      Id,
                      ProviderName,
                      Message |
        Out-GridView -Title "New Services Installed"

    }

    Default {
        Write-Host "Invalid selection." -ForegroundColor Red
    }
}