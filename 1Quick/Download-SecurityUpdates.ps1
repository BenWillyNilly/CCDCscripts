<#
.SYNOPSIS
    Downloads ONLY Windows security updates. Nothing else is downloaded.

.DESCRIPTION
    Uses the built-in Windows Update Agent COM API (no modules required).
    Searches for pending software updates, keeps only those in the
    "Security Updates" category, and downloads them. Drivers, feature updates,
    optional/preview updates, and Defender definition updates are skipped.

    By default this script ONLY downloads. Add -Install if you also want to
    install what was downloaded.

.PARAMETER Install
    Also install the downloaded security updates.

.EXAMPLE
    .\Download-SecurityUpdates.ps1

.EXAMPLE
    .\Download-SecurityUpdates.ps1 -Install

.NOTES
    Must be run from an elevated (Administrator) PowerShell session.
#>

[CmdletBinding()]
param(
    [switch]$Install
)

# --- Require admin ---------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Microsoft's fixed category ID for "Security Updates"
$SecurityCategoryId = '0fa1201d-4330-4fa8-8ae9-b877473b6441'

try {
    Write-Host "Searching for pending updates..." -ForegroundColor Cyan

    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    # Software only (excludes drivers), not installed, not hidden
    $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

    # Keep only updates categorized as Security Updates
    $securityUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $result.Updates) {
        $isSecurity = $false
        foreach ($category in $update.Categories) {
            if ($category.CategoryID -eq $SecurityCategoryId) {
                $isSecurity = $true
                break
            }
        }
        if ($isSecurity) {
            if (-not $update.EulaAccepted) { $update.AcceptEula() }
            [void]$securityUpdates.Add($update)
        }
    }

    if ($securityUpdates.Count -eq 0) {
        Write-Host "No pending security updates found." -ForegroundColor Green
        exit 0
    }

    Write-Host "`nFound $($securityUpdates.Count) security update(s):" -ForegroundColor Yellow
    foreach ($u in $securityUpdates) {
        $sizeMB = [math]::Round($u.MaxDownloadSize / 1MB, 1)
        Write-Host ("  - {0} ({1} MB)" -f $u.Title, $sizeMB)
    }

    # Only download what isn't already downloaded
    $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $securityUpdates) {
        if (-not $u.IsDownloaded) { [void]$toDownload.Add($u) }
    }

    if ($toDownload.Count -gt 0) {
        Write-Host "`nDownloading $($toDownload.Count) update(s)..." -ForegroundColor Cyan
        $downloader         = $session.CreateUpdateDownloader()
        $downloader.Updates = $toDownload
        $dlResult           = $downloader.Download()

        # ResultCode: 2 = Succeeded, 3 = Succeeded with errors
        switch ($dlResult.ResultCode) {
            2       { Write-Host "Download complete." -ForegroundColor Green }
            3       { Write-Warning "Download finished with some errors." }
            default { Write-Error "Download failed. ResultCode: $($dlResult.ResultCode)"; exit 1 }
        }
    }
    else {
        Write-Host "`nAll security updates are already downloaded." -ForegroundColor Green
    }

    # Optional install step
    if ($Install) {
        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $securityUpdates) {
            if ($u.IsDownloaded) { [void]$toInstall.Add($u) }
        }

        if ($toInstall.Count -gt 0) {
            Write-Host "`nInstalling $($toInstall.Count) update(s)..." -ForegroundColor Cyan
            $installer         = $session.CreateUpdateInstaller()
            $installer.Updates = $toInstall
            $instResult        = $installer.Install()

            Write-Host "Install ResultCode: $($instResult.ResultCode)"
            if ($instResult.RebootRequired) {
                Write-Warning "A reboot is required to finish installing updates."
            }
        }
    }
    else {
        Write-Host "`nDownload only - nothing was installed. Re-run with -Install to install." -ForegroundColor DarkGray
    }
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}
