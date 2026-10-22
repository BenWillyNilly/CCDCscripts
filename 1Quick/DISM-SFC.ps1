# Run as Administrator

DISM.exe /Online /Cleanup-Image /RestoreHealth

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nDISM completed successfully. Starting SFC..." -ForegroundColor Green
    sfc /scannow
} else {
    Write-Host "`nDISM failed. Skipping SFC." -ForegroundColor Red
}

Pause