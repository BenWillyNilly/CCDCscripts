<#
.SYNOPSIS
    Lists every certificate in the Windows certificate stores and checks each one with OpenSSL.

.DESCRIPTION
    For every certificate in Cert:\LocalMachine\* and Cert:\CurrentUser\* the script:
      1. Displays store, subject, issuer, validity dates and thumbprint.
      2. Exports the certificate to PEM and has OpenSSL parse it
         (subject, issuer, notAfter, SHA-256 fingerprint) and cross-checks the
         fingerprint against the one computed by .NET.
      3. Uses `openssl x509 -checkend` to flag expired / soon-to-expire certs.
      4. Uses `openssl verify` to validate the chain against the Windows
         Root + AuthRoot stores (trust anchors) and the CA store (intermediates).
    A CSV report is written at the end.

.PARAMETER OpenSslPath
    Full path to openssl.exe. Auto-detected if omitted.

.PARAMETER OutputCsv
    Where to write the CSV report. Default: .\cert-report.csv

.PARAMETER WarnDays
    Certificates expiring within this many days are flagged "Expiring". Default: 30

.PARAMETER SkipVerify
    Skip the (slower) `openssl verify` chain check.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Check-Certificates.ps1

.EXAMPLE
    .\Check-Certificates.ps1 -OpenSslPath "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" -WarnDays 60

.NOTES
    Run from an elevated prompt if you want complete LocalMachine store access.
    Works with Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [string]$OpenSslPath,
    [string]$OutputCsv = (Join-Path (Get-Location) 'cert-report.csv'),
    [int]$WarnDays = 30,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- locate OpenSSL
function Find-OpenSsl {
    param([string]$Hint)

    if ($Hint) {
        if (Test-Path $Hint) { return (Resolve-Path $Hint).Path }
        throw "OpenSSL not found at '$Hint'."
    }

    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
        "$env:ProgramFiles\OpenSSL\bin\openssl.exe",
        "${env:ProgramFiles(x86)}\OpenSSL-Win32\bin\openssl.exe",
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
        "C:\OpenSSL-Win64\bin\openssl.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }

    throw "openssl.exe not found. Install it (e.g. 'winget install ShiningLight.OpenSSL.Light') or pass -OpenSslPath."
}

$openssl = Find-OpenSsl -Hint $OpenSslPath
Write-Host "Using OpenSSL: $openssl" -ForegroundColor Cyan
Write-Host (& $openssl version) -ForegroundColor Cyan

# ---------------------------------------------------------------- helpers
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-Pem {
    param([byte[]]$Der)
    $b64 = [Convert]::ToBase64String($Der, [Base64FormattingOptions]::InsertLineBreaks) -replace "`r`n", "`n"
    return "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
}

function Invoke-OpenSsl {
    param([string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $openssl @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    [pscustomobject]@{ Output = ($out -join "`n").Trim(); ExitCode = $code }
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '') }
    finally { $sha.Dispose() }
}

# ---------------------------------------------------------------- temp workspace
$work = Join-Path ([IO.Path]::GetTempPath()) ("certcheck_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

try {
    # ------------------------------------------------------------ enumerate certs
    Write-Host "`nEnumerating certificate stores..." -ForegroundColor Cyan

    # Uses the .NET X509Store API directly (does not depend on the Cert: drive).
    $all = New-Object System.Collections.Generic.List[object]

    $storeLocations = @{
        'LocalMachine' = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        'CurrentUser'  = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    }
    $registryRoots = @{
        'LocalMachine' = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates'
        'CurrentUser'  = 'HKCU:\SOFTWARE\Microsoft\SystemCertificates'
    }
    $wellKnownStores = 'My', 'Root', 'CA', 'AuthRoot', 'TrustedPeople',
                       'TrustedPublisher', 'Disallowed', 'AddressBook', 'ThirdPartyRoot'
    $openFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
                 [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly

    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        # Hashtables are case-insensitive in PowerShell, so this de-duplicates store names.
        $storeNames = @{}
        foreach ($n in $wellKnownStores) { $storeNames[$n] = $true }
        if (Test-Path $registryRoots[$loc]) {
            foreach ($k in (Get-ChildItem $registryRoots[$loc] -ErrorAction SilentlyContinue)) {
                $storeNames[$k.PSChildName] = $true
            }
        }

        foreach ($name in ($storeNames.Keys | Sort-Object)) {
            $store = $null
            $count = 0
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, $storeLocations[$loc])
                $store.Open($openFlags)
                foreach ($c in $store.Certificates) {
                    if (-not $c.RawData) { continue }
                    $all.Add([pscustomobject]@{
                        Location = $loc
                        Store    = $name
                        Cert     = $c
                    })
                    $count++
                }
            } catch {
                Write-Warning ("Could not read {0}\{1}: {2}" -f $loc, $name, $_.Exception.Message)
            } finally {
                if ($store) { $store.Close() }
            }
            if ($count -gt 0) { Write-Host ("  {0}\{1}: {2}" -f $loc, $name, $count) -ForegroundColor DarkGray }
        }
    }
    Write-Host ("Found {0} certificate entries ({1} unique thumbprints)." -f `
        $all.Count, ($all.Cert.Thumbprint | Sort-Object -Unique).Count)

    if ($all.Count -eq 0) {
        Write-Warning "No certificates could be read from the Windows stores."
        Write-Warning "Check that you're running as Administrator and that PowerShell isn't in Constrained Language Mode (`$ExecutionContext.SessionState.LanguageMode)."
        return
    }

    # ------------------------------------------------------------ build trust bundles
    $rootPem  = Join-Path $work 'roots.pem'
    $interPem = Join-Path $work 'intermediates.pem'

    function Write-Bundle {
        param([string]$Path, [string[]]$StoreNames)
        $seen = @{}
        $sb = New-Object System.Text.StringBuilder
        foreach ($e in $all) {
            if ($StoreNames -notcontains $e.Store) { continue }
            if ($seen.ContainsKey($e.Cert.Thumbprint)) { continue }
            $seen[$e.Cert.Thumbprint] = $true
            [void]$sb.Append((ConvertTo-Pem $e.Cert.RawData))
        }
        [IO.File]::WriteAllText($Path, $sb.ToString(), $utf8NoBom)
        return $seen.Count
    }

    $nRoots = Write-Bundle -Path $rootPem  -StoreNames @('Root', 'AuthRoot')
    $nInter = Write-Bundle -Path $interPem -StoreNames @('CA')
    Write-Host "Trust anchors: $nRoots   Intermediates: $nInter"

    # ------------------------------------------------------------ check each cert
    $cache   = @{}   # thumbprint -> openssl results (avoid re-running for duplicates)
    $report  = New-Object System.Collections.Generic.List[object]
    $i = 0
    $total = $all.Count
    $warnSeconds = $WarnDays * 86400

    foreach ($entry in $all) {
        $i++
        $c = $entry.Cert
        Write-Progress -Activity 'Checking certificates with OpenSSL' `
            -Status ("{0}\{1}  ({2}/{3})" -f $entry.Location, $entry.Store, $i, $total) `
            -PercentComplete ([int](100 * $i / $total))

        $tp = $c.Thumbprint

        if (-not $cache.ContainsKey($tp)) {
            $pemFile = Join-Path $work ("$tp.pem")
            [IO.File]::WriteAllText($pemFile, (ConvertTo-Pem $c.RawData), $utf8NoBom)

            $res = [ordered]@{
                Parsed     = $false
                OsslSubj   = ''
                OsslIssuer = ''
                OsslEnd    = ''
                FpMatch    = $false
                Expiry     = 'Unknown'
                Chain      = 'Skipped'
            }

            # 1) Parse
            $p = Invoke-OpenSsl @('x509', '-in', $pemFile, '-noout',
                                  '-subject', '-issuer', '-enddate', '-fingerprint', '-sha256')
            if ($p.ExitCode -eq 0) {
                $res.Parsed = $true
                foreach ($line in ($p.Output -split "`n")) {
                    if     ($line -match '^subject\s*=\s*(.*)$')              { $res.OsslSubj   = $Matches[1] }
                    elseif ($line -match '^issuer\s*=\s*(.*)$')               { $res.OsslIssuer = $Matches[1] }
                    elseif ($line -match '^notAfter\s*=\s*(.*)$')             { $res.OsslEnd    = $Matches[1] }
                    elseif ($line -match 'Fingerprint\s*=\s*([0-9A-Fa-f:]+)') {
                        $fp = $Matches[1] -replace ':', ''
                        $res.FpMatch = ($fp -ieq (Get-Sha256Hex $c.RawData))
                    }
                }

                # 2) Expiry
                $e0 = Invoke-OpenSsl @('x509', '-in', $pemFile, '-noout', '-checkend', '0')
                if ($e0.ExitCode -ne 0) {
                    $res.Expiry = 'Expired'
                } else {
                    $eW = Invoke-OpenSsl @('x509', '-in', $pemFile, '-noout', '-checkend', "$warnSeconds")
                    $res.Expiry = if ($eW.ExitCode -ne 0) { 'Expiring' } else { 'Valid' }
                }

                # 3) Chain verification
                if (-not $SkipVerify) {
                    $v = Invoke-OpenSsl @('verify', '-CAfile', $rootPem, '-untrusted', $interPem, $pemFile)
                    if ($v.ExitCode -eq 0 -and $v.Output -match ':\s*OK\s*$') {
                        $res.Chain = 'OK'
                    } else {
                        $err = ($v.Output -split "`n" | Where-Object { $_ -match '^error\s+\d+' } | Select-Object -First 1)
                        if (-not $err) { $err = ($v.Output -split "`n" | Select-Object -First 1) }
                        $res.Chain = "FAIL: $err"
                    }
                }
            } else {
                $res.Expiry = 'ParseError'
                $res.Chain  = "FAIL: $($p.Output)"
            }

            $cache[$tp] = [pscustomobject]$res
            Remove-Item $pemFile -Force -ErrorAction SilentlyContinue
        }

        $r = $cache[$tp]
        $report.Add([pscustomobject]@{
            Location       = $entry.Location
            Store          = $entry.Store
            Subject        = $c.Subject
            Issuer         = $c.Issuer
            NotBefore      = $c.NotBefore.ToString('yyyy-MM-dd')
            NotAfter       = $c.NotAfter.ToString('yyyy-MM-dd')
            Thumbprint     = $tp
            HasPrivateKey  = $c.HasPrivateKey
            OpenSSLParsed  = $r.Parsed
            FingerprintOK  = $r.FpMatch
            Expiry         = $r.Expiry
            ChainCheck     = $r.Chain
        })
    }
    Write-Progress -Activity 'Checking certificates with OpenSSL' -Completed

    # ------------------------------------------------------------ display
    Write-Host "`n=== Certificate report ===" -ForegroundColor Green
    $report |
        Sort-Object Location, Store, Subject |
        Format-Table Location, Store,
            @{ n = 'Subject'; e = { if ($_.Subject.Length -gt 55) { $_.Subject.Substring(0, 52) + '...' } else { $_.Subject } } },
            NotAfter, Expiry, FingerprintOK,
            @{ n = 'Chain'; e = { if ($_.ChainCheck.Length -gt 45) { $_.ChainCheck.Substring(0, 42) + '...' } else { $_.ChainCheck } } } `
            -AutoSize

    # ------------------------------------------------------------ summary
    $uniq = $report | Sort-Object Thumbprint -Unique
    Write-Host "=== Summary (unique certificates: $($uniq.Count)) ===" -ForegroundColor Green
    $uniq | Group-Object Expiry | Sort-Object Name | ForEach-Object {
        $color = switch ($_.Name) { 'Valid' { 'Green' } 'Expiring' { 'Yellow' } default { 'Red' } }
        Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count) -ForegroundColor $color
    }
    if (-not $SkipVerify) {
        $ok   = ($uniq | Where-Object { $_.ChainCheck -eq 'OK' }).Count
        $fail = $uniq.Count - $ok
        Write-Host ("  Chain OK     {0}" -f $ok)   -ForegroundColor Green
        Write-Host ("  Chain FAIL   {0}" -f $fail) -ForegroundColor $(if ($fail) { 'Yellow' } else { 'Green' })
    }
    $badFp = ($uniq | Where-Object { -not $_.FingerprintOK -and $_.OpenSSLParsed }).Count
    if ($badFp) { Write-Host "  Fingerprint mismatches: $badFp" -ForegroundColor Red }

    # ------------------------------------------------------------ export
    $report | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nFull report written to: $OutputCsv" -ForegroundColor Cyan
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
