<#
.SYNOPSIS
    Downloads the latest OpenSSL installer for Windows (download only, no install).

.PARAMETER Edition
    Light = essentials (default), Dev = full with headers/libs, LTS = long-term-support Light build.

.PARAMETER OutDir
    Where to save the installer. Defaults to your Downloads folder.
#>
param(
    [ValidateSet('Light', 'Dev', 'LTS')]
    [string]$Edition = 'Light',
    [string]$OutDir = (Join-Path $env:USERPROFILE 'Downloads')
)

$ids = @{
    Light = 'ShiningLight.OpenSSL.Light'
    Dev   = 'ShiningLight.OpenSSL.Dev'
    LTS   = 'ShiningLight.OpenSSL.LTS.Light'
}

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error 'winget not found. Install "App Installer" from the Microsoft Store, or get OpenSSL from https://slproweb.com/products/Win32OpenSSL.html'
    exit 1
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
winget download --id $ids[$Edition] --exact --download-directory $OutDir --accept-package-agreements --accept-source-agreements

if ($LASTEXITCODE -eq 0) { Write-Host "Saved to: $OutDir" -ForegroundColor Green }
else { Write-Error "Download failed (exit code $LASTEXITCODE)." }
