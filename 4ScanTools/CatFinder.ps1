Clear-Host

$Keywords = @(
    "ncat",
    "mimikatz"
)

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Security Tool Hunt"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# ========================================================
# RUNNING PROCESSES
# ========================================================

Write-Host "[1/5] Checking Running Processes..." -ForegroundColor Yellow

$Found = $false

Get-Process -ErrorAction SilentlyContinue |
ForEach-Object {

    foreach ($Keyword in $Keywords)
    {
        if ($_.ProcessName -match $Keyword)
        {
            Write-Host "FOUND PROCESS: $($_.ProcessName) PID: $($_.Id)" -ForegroundColor Red
            $Found = $true
        }
    }
}

if (-not $Found)
{
    Write-Host "No matching processes found." -ForegroundColor Green
}

Write-Host ""

# ========================================================
# SERVICES
# ========================================================

Write-Host "[2/5] Checking Services..." -ForegroundColor Yellow

$Found = $false

Get-CimInstance Win32_Service |
ForEach-Object {

    foreach ($Keyword in $Keywords)
    {
        if ($_.Name -match $Keyword -or
            $_.DisplayName -match $Keyword -or
            $_.PathName -match $Keyword)
        {
            Write-Host "FOUND SERVICE: $($_.Name)" -ForegroundColor Red
            Write-Host "Path: $($_.PathName)"
            Write-Host ""

            $Found = $true
        }
    }
}

if (-not $Found)
{
    Write-Host "No matching services found." -ForegroundColor Green
}

Write-Host ""

# ========================================================
# STARTUP PERSISTENCE
# ========================================================

Write-Host "[3/5] Checking Startup Persistence..." -ForegroundColor Yellow

$Found = $false

Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
ForEach-Object {

    foreach ($Keyword in $Keywords)
    {
        if ($_.Command -match $Keyword)
        {
            Write-Host "FOUND STARTUP ITEM:" -ForegroundColor Red
            Write-Host $_.Command
            Write-Host ""

            $Found = $true
        }
    }
}

if (-not $Found)
{
    Write-Host "No matching startup entries found." -ForegroundColor Green
}

Write-Host ""

# ========================================================
# SCHEDULED TASKS
# ========================================================

Write-Host "[4/5] Checking Scheduled Tasks..." -ForegroundColor Yellow

$Found = $false

Get-ScheduledTask -ErrorAction SilentlyContinue |
ForEach-Object {

    $Task = $_

    foreach ($Keyword in $Keywords)
    {
        if ($Task.TaskName -match $Keyword)
        {
            Write-Host "FOUND TASK: $($Task.TaskName)" -ForegroundColor Red
            $Found = $true
        }
    }
}

if (-not $Found)
{
    Write-Host "No matching scheduled tasks found." -ForegroundColor Green
}

Write-Host ""

# ========================================================
# FILE SYSTEM SEARCH
# ========================================================

Write-Host "[5/5] Checking Common Locations..." -ForegroundColor Yellow

$Locations = @(
    "C:\ProgramData",
    "C:\Users",
    "C:\Temp",
    "C:\Windows\Temp"
)

$Found = $false

foreach ($Location in $Locations)
{
    if (Test-Path $Location)
    {
        Get-ChildItem $Location `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue |
        ForEach-Object {

            foreach ($Keyword in $Keywords)
            {
                if ($_.Name -match $Keyword)
                {
                    Write-Host "FOUND FILE: $($_.FullName)" -ForegroundColor Red
                    $Found = $true
                }
            }
        }
    }
}

if (-not $Found)
{
    Write-Host "No matching files found." -ForegroundColor Green
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Scan Complete"
Write-Host "=========================================" -ForegroundColor Cyan