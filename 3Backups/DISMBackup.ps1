# ============================================
# Upload DISM Recovery Package to GitHub Repo
# ============================================

$RepoFolder = "C:\RecoveryRepo"

$Build = (Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

$Target = "$RepoFolder\packages\$Build"

Write-Host "[INFO] Build detected: $Build"

New-Item -ItemType Directory -Force -Path $Target | Out-Null

# DISM executable

Copy-Item `
"C:\Windows\System32\dism.exe" `
"$Target\dism.exe" `
-Force

# DISM folder

Copy-Item `
"C:\Windows\System32\Dism" `
"$Target\Dism" `
-Recurse `
-Force

# Generate hashes

Get-ChildItem $Target -Recurse | Where-Object {
    -not $_.PSIsContainer
} | ForEach-Object {

    $Hash = Get-FileHash $_.FullName -Algorithm SHA256

    "$($Hash.Hash)  $($_.Name)" |
        Out-File `
        "$Target\SHA256SUMS.txt" `
        -Append
}

Write-Host "[INFO] Hashes generated"

# Git commands

Set-Location $RepoFolder

git add .

git commit -m "DISM package build $Build"

git push origin main

Write-Host "[PASS] Upload complete"