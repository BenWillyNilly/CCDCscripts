# Run as Administrator

Clear-Host

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Windows Recovery Restore Tool"
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[1] Restore From Local ZIP"
Write-Host "[2] Restore From GitHub"
Write-Host "[Q] Quit"
Write-Host ""

$Choice = Read-Host "Select Option"

if ($Choice -match '^[Qq]$')
{
    return
}

# --------------------------------------------------
# Detect Build
# --------------------------------------------------

$Build = (
    Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
).CurrentBuild

Write-Host ""
Write-Host "[ PASS ] Build Detected: $Build" -ForegroundColor Green

# --------------------------------------------------
# Locations
# --------------------------------------------------

$ExtractDir = "$env:TEMP\WindowsRecovery"

if(Test-Path $ExtractDir)
{
    Remove-Item $ExtractDir -Recurse -Force
}

New-Item `
    -ItemType Directory `
    -Path $ExtractDir `
    -Force | Out-Null

# --------------------------------------------------
# LOCAL MODE
# --------------------------------------------------

if($Choice -eq "1")
{
    $ZipPath = Read-Host "Enter ZIP File Path"

    if(!(Test-Path $ZipPath))
    {
        Write-Host ""
        Write-Host "[ FAIL ] ZIP File Not Found" -ForegroundColor Red
        return
    }
}

# --------------------------------------------------
# GITHUB MODE
# --------------------------------------------------

if($Choice -eq "2")
{
    $RepoRoot = Read-Host "GitHub Raw URL"

    $ZipPath = "$env:TEMP\$Build.zip"

    $DownloadURL = "$RepoRoot/${Build}_core.zip"

    Write-Host ""
    Write-Host "[ INFO ] Downloading Package..."

    try
    {
        Invoke-WebRequest `
            -Uri $DownloadURL `
            -OutFile $ZipPath `
            -UseBasicParsing

        Write-Host "[ PASS ] Download Complete" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[ ERROR ] Download Failed" -ForegroundColor Red
        return
    }
}

# --------------------------------------------------
# Extract Package
# --------------------------------------------------

Write-Host ""
Write-Host "[ INFO ] Extracting Package..."

try
{
    Expand-Archive `
        -Path $ZipPath `
        -DestinationPath $ExtractDir `
        -Force

    Write-Host "[ PASS ] Extraction Complete" -ForegroundColor Green
}
catch
{
    Write-Host "[ ERROR ] Extraction Failed" -ForegroundColor Red
    return
}

# --------------------------------------------------
# Files To Restore
# --------------------------------------------------

$RestoreFiles = @(
    "dism.exe",
    "sfc.exe",
    "powershell.exe",
    "cmd.exe",
    "reg.exe",
    "sc.exe",
    "netsh.exe",
    "tasklist.exe",
    "taskkill.exe"
)

Write-Host ""
Write-Host "========================================="
Write-Host " Restoring Files"
Write-Host "========================================="
Write-Host ""

foreach($File in $RestoreFiles)
{
    $Source = Get-ChildItem `
        $ExtractDir `
        -Recurse `
        -Filter $File `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if(!$Source)
    {
        Write-Host "[ SKIP ] $File Not In Package" -ForegroundColor Yellow
        continue
    }

    $Destination = Join-Path `
        "$env:SystemRoot\System32" `
        $File

    try
    {
        Copy-Item `
            $Source.FullName `
            $Destination `
            -Force

        Write-Host "[ FIXED ] $File" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[ ERROR ] $File" -ForegroundColor Red
    }
}

# --------------------------------------------------
# DISM Folder
# --------------------------------------------------

$DismFolder = Join-Path $ExtractDir "Dism"

if(Test-Path $DismFolder)
{
    try
    {
        Copy-Item `
            $DismFolder `
            "$env:SystemRoot\System32\Dism" `
            -Recurse `
            -Force

        Write-Host "[ FIXED ] DISM Folder" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[ ERROR ] DISM Folder" -ForegroundColor Red
    }
}
else
{
    Write-Host "[ SKIP ] DISM Folder Missing From Package" -ForegroundColor Yellow
}

# --------------------------------------------------
# Validation
# --------------------------------------------------

Write-Host ""
Write-Host "========================================="
Write-Host " Validation"
Write-Host "========================================="

try
{
    & "$env:SystemRoot\System32\dism.exe" /? > $null

    Write-Host "[ PASS ] DISM Launch Test" -ForegroundColor Green
}
catch
{
    Write-Host "[ FAIL ] DISM Launch Test" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter To Return"