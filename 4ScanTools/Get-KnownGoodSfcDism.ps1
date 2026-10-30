#Requires -Version 5.1
<#
.SYNOPSIS
    Detects the running Windows build, looks up the matching sfc.exe / dism.exe in
    Winbindex (winbindex.m417z.com), obtains HASH-VERIFIED known-good copies, and
    checks the copies installed on this machine against them.

.DESCRIPTION
    1. Detects Windows version / build / UBR / architecture.
    2. Downloads the Winbindex index for each file and selects the entry matching
       this build + architecture:
         Exact         - file version == <build>.<UBR> of the running OS
         NearestLower  - newest version at or below your UBR (Windows only bumps a
                         file's version when that file changes - this is normal)
         NearestHigher - last resort (only with -MatchMode Nearest)
    3. Examines the installed file in System32: SHA-256, version, size, timestamps,
       owner, signature - and compares the hash with the whole Winbindex index.
       Also flags files that are byte-for-byte identical to EACH OTHER.
    4. Obtains a known-good copy, in this order:
         a) the local component store (WinSxS): any copy whose SHA-256 appears in
            Winbindex for this build/architecture is genuine Microsoft code;
         b) Microsoft's symbol server (msdl.microsoft.com), using the key from
            the index.
       IMPORTANT: the symbol server sometimes serves a different (development /
       unsigned) variant under the same key, so a symbol-server file is only
       accepted as known-good if its SHA-256 equals the Winbindex hash. Files
       that don't match are saved under "unverified\" and clearly labelled.
    5. Writes manifest.json, SHA256SUMS.txt (verified files only) and
       expected-hashes.csv (every genuine hash Winbindex has for this build, so
       you can check any candidate file on a trusted machine).

    Nothing is ever written to System32.

.PARAMETER Files
    Files to look up. Default: sfc.exe, dism.exe.

.PARAMETER OutputDir
    Base output folder. Default: .\KnownGood (results go in <build>.<ubr>-<arch>).

.PARAMETER TargetVersion
    Override the detected version, e.g. "17763.3650" or "10.0.17763.3650".

.PARAMETER Architecture
    Auto (default), x64, x86 or arm64.

.PARAMETER MatchMode
    Nearest (default) or ExactOnly.

.PARAMETER ListOnly
    Analyse and compare only; download/copy nothing.

.PARAMETER SkipLocalSearch
    Don't search WinSxS for genuine copies.

.PARAMETER SkipDownload
    Don't contact the symbol server.

.PARAMETER Force
    Re-obtain files even if a verified copy is already present.

.PARAMETER NoCache / CacheHours
    Control caching of the Winbindex index (default 24 h).

.PARAMETER Proxy
    Optional proxy URL.

.PARAMETER LogPath
    Optional log file path.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-KnownGoodSfcDism.ps1

.EXAMPLE
    .\Get-KnownGoodSfcDism.ps1 -ListOnly

.EXAMPLE
    .\Get-KnownGoodSfcDism.ps1 -Files sfc.exe,dism.exe,sfc_os.dll,dismapi.dll,dismcore.dll

.NOTES
    Exit codes: 0 = a verified copy was obtained for every file, 1 = at least one
    file has no verified copy, 2 = fatal error. Admin rights recommended (WinSxS,
    ownership info). Works on Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [string[]]$Files = @('sfc.exe', 'dism.exe'),
    [string]$OutputDir,
    [string]$TargetVersion,
    [ValidateSet('Auto', 'x64', 'x86', 'arm64')]
    [string]$Architecture = 'Auto',
    [ValidateSet('Nearest', 'ExactOnly')]
    [string]$MatchMode = 'Nearest',
    [string]$Proxy,
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 4,
    [ValidateRange(10, 1800)]
    [int]$TimeoutSec = 120,
    [ValidateRange(0, 720)]
    [int]$CacheHours = 24,
    [switch]$NoCache,
    [switch]$Force,
    [switch]$ListOnly,
    [switch]$SkipLocalSearch,
    [switch]$SkipDownload,
    [string]$LogPath
)

$script:IndexBase    = 'https://winbindex.m417z.com/data/by_filename_compressed'
$script:SymbolBase   = 'https://msdl.microsoft.com/download/symbols'
$script:UserAgent    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) KnownGoodFetcher/2.0'
$script:MachineTypes = @{ 'x64' = 0x8664; 'x86' = 0x014C; 'arm64' = 0xAA64 }
$script:LogFile      = $null
$script:SysDir       = $null
$script:CacheDir     = $null

# =============================================================================
# Helpers
# =============================================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'DEBUG')][string]$Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('HH:mm:ss')
    $line  = "[$stamp] [$Level] $Message"
    $color = switch ($Level) {
        'INFO'  { 'Gray' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'OK'    { 'Green' }
        'DEBUG' { 'DarkGray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Get-Val {
    # Safe lookup for dictionaries (Hashtable / Dictionary<string,object>) and PSCustomObjects.
    param($Dict, [string]$Key)
    if ($null -eq $Dict) { return $null }
    if ($Dict -is [System.Collections.IDictionary]) {
        if ($Dict.ContainsKey($Key)) { return $Dict[$Key] }
        return $null
    }
    $p = $Dict.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function Initialize-Network {
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    } catch {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    }
}

function Invoke-Download {
    # Downloads $Uri to $OutFile with retry/back-off. 403/404 are not retried.
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$OutFile)

    $attempt = 0
    while ($true) {
        $attempt++
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
        try {
            $p = @{
                Uri             = $Uri
                OutFile         = $OutFile
                UseBasicParsing = $true
                TimeoutSec      = $TimeoutSec
                UserAgent       = $script:UserAgent
                ErrorAction     = 'Stop'
            }
            if ($Proxy) { $p['Proxy'] = $Proxy; $p['ProxyUseDefaultCredentials'] = $true }
            Invoke-WebRequest @p | Out-Null
            return
        } catch {
            $status = $null
            try { if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } } catch { }
            if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
            if ($status -eq 404 -or $status -eq 403) { throw }
            if ($attempt -ge $MaxRetries) { throw }
            $delay = [Math]::Min(30, [Math]::Pow(2, $attempt))
            Write-Log ("Attempt {0}/{1} failed ({2}). Retrying in {3}s..." -f $attempt, $MaxRetries, $_.Exception.Message, $delay) 'WARN'
            Start-Sleep -Seconds $delay
        }
    }
}

function Read-GzipText {
    param([Parameter(Mandatory)][string]$Path)
    $fs = [IO.File]::OpenRead($Path)
    try {
        $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
        try {
            $sr = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
            try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
        } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
}

function ConvertFrom-JsonLarge {
    # Windows PowerShell 5.1's ConvertFrom-Json chokes on very large documents,
    # so use JavaScriptSerializer there. Both paths return IDictionary objects.
    param([Parameter(Mandatory)][string]$Json)
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return (ConvertFrom-Json -InputObject $Json -AsHashtable)
    }
    Add-Type -AssemblyName System.Web.Extensions
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength  = [int]::MaxValue
    $ser.RecursionLimit = 256
    return $ser.DeserializeObject($Json)
}

function Get-SignatureInfo {
    param([Parameter(Mandatory)][string]$Path)
    $o = [pscustomobject]@{ Status = 'Unavailable'; Signer = '' }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $o.Status = $s.Status.ToString()
        if ($s.SignerCertificate) { $o.Signer = $s.SignerCertificate.Subject }
    } catch { }
    return $o
}

# =============================================================================
# OS detection
# =============================================================================

function Get-OsInfo {
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop

    $arch = $Architecture
    if ($arch -eq 'Auto') {
        $raw = $env:PROCESSOR_ARCHITEW6432          # set when a 32-bit process runs on a 64-bit OS
        if (-not $raw) { $raw = $env:PROCESSOR_ARCHITECTURE }
        switch -Regex ($raw) {
            '^(AMD64|x64)$' { $arch = 'x64';   break }
            '^ARM64$'       { $arch = 'arm64'; break }
            '^x86$'         { $arch = 'x86';   break }
            default         { throw "Unrecognised processor architecture '$raw'. Use -Architecture." }
        }
    }

    $major = 10; $minor = 0
    if ($cv.PSObject.Properties['CurrentMajorVersionNumber']) {
        $major = [int]$cv.CurrentMajorVersionNumber
        $minor = [int]$cv.CurrentMinorVersionNumber
    } elseif ($cv.PSObject.Properties['CurrentVersion']) {
        $parts = ([string]$cv.CurrentVersion).Split('.')
        $major = [int]$parts[0]; $minor = [int]$parts[1]
    }
    $build = [int]$cv.CurrentBuildNumber
    $ubr   = 0
    if ($cv.PSObject.Properties['UBR'] -and $null -ne $cv.UBR) { $ubr = [int]$cv.UBR }

    $product = [string]$cv.ProductName
    if ($build -ge 22000 -and $product -match 'Windows 10') { $product = $product -replace 'Windows 10', 'Windows 11' }

    $display = ''
    if ($cv.PSObject.Properties['DisplayVersion'])   { $display = [string]$cv.DisplayVersion }
    elseif ($cv.PSObject.Properties['ReleaseId'])    { $display = [string]$cv.ReleaseId }

    $installType = ''
    if ($cv.PSObject.Properties['InstallationType']) { $installType = [string]$cv.InstallationType }

    $diskVersion = $null
    $ntdll = Join-Path $script:SysDir 'ntdll.dll'
    if (Test-Path -LiteralPath $ntdll) {
        $vi = (Get-Item -LiteralPath $ntdll).VersionInfo
        $diskVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    }

    $isOverride = $false
    if ($TargetVersion) {
        if (-not ($TargetVersion.Trim() -match '^(?:(\d+)\.(\d+)\.)?(\d+)\.(\d+)$')) {
            throw "-TargetVersion '$TargetVersion' is not valid. Use e.g. 17763.3650 or 10.0.17763.3650."
        }
        if ($Matches[1]) { $major = [int]$Matches[1]; $minor = [int]$Matches[2] }
        $build = [int]$Matches[3]; $ubr = [int]$Matches[4]
        $isOverride = $true
    }

    [pscustomobject]@{
        ProductName    = $product
        DisplayVersion = $display
        Edition        = [string]$cv.EditionID
        InstallType    = $installType
        Major          = $major
        Minor          = $minor
        Build          = $build
        Ubr            = $ubr
        FullVersion    = '{0}.{1}.{2}.{3}' -f $major, $minor, $build, $ubr
        DiskVersion    = $diskVersion
        Architecture   = $arch
        MachineType    = [int]$script:MachineTypes[$arch]
        IsOverride     = $isOverride
    }
}

# =============================================================================
# Winbindex
# =============================================================================

function Get-WinbindexIndex {
    param([Parameter(Mandatory)][string]$FileName)

    $gz  = Join-Path $script:CacheDir "$FileName.json.gz"
    $url = "$($script:IndexBase)/$FileName.json.gz"

    $useCache = $false
    if (-not $NoCache -and (Test-Path -LiteralPath $gz)) {
        $age = (Get-Date) - (Get-Item -LiteralPath $gz).LastWriteTime
        if ($age.TotalHours -lt $CacheHours) { $useCache = $true }
    }

    for ($pass = 1; $pass -le 2; $pass++) {
        if (-not $useCache) {
            Write-Log "Downloading Winbindex index: $url"
            $part = "$gz.part"
            try {
                Invoke-Download -Uri $url -OutFile $part
            } catch {
                $msg = $_.Exception.Message
                if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue }
                throw "Could not download the Winbindex index for '$FileName' (is the name correct / is the site reachable?): $msg"
            }
            Move-Item -LiteralPath $part -Destination $gz -Force
        } else {
            Write-Log "Using cached Winbindex index for $FileName" 'DEBUG'
        }

        try {
            $json  = Read-GzipText -Path $gz
            $index = ConvertFrom-JsonLarge -Json $json
            if ($index -isnot [System.Collections.IDictionary]) { throw 'Unexpected JSON structure (root is not an object).' }
            return $index
        } catch {
            Write-Log "Index for $FileName is unreadable ($($_.Exception.Message)); discarding it." 'WARN'
            Remove-Item -LiteralPath $gz -Force -ErrorAction SilentlyContinue
            $useCache = $false
        }
    }
    throw "Could not obtain a valid Winbindex index for '$FileName'."
}

function Select-BestEntry {
    param($Index, [int]$MachineType, [int]$OsBuild, [int]$OsUbr)

    $cands    = New-Object System.Collections.Generic.List[object]
    $allBuild = New-Object System.Collections.Generic.List[object]
    $forBuild = 0

    foreach ($sha in $Index.Keys) {
        $entry = $Index[$sha]
        $fi = Get-Val $entry 'fileInfo'
        if ($null -eq $fi) { continue }

        $mt = Get-Val $fi 'machineType'
        if ($null -eq $mt -or [int]$mt -ne $MachineType) { continue }

        $ver = [string](Get-Val $fi 'version')
        if (-not ($ver -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)')) { continue }
        if ([int]$Matches[3] -ne $OsBuild) { continue }
        $ubr = [int]$Matches[4]
        $forBuild++

        $shaLower = ([string]$sha).ToLowerInvariant()
        $allBuild.Add([pscustomobject]@{ Version = $ver; Ubr = $ubr; Sha256 = $shaLower })

        $ts = Get-Val $fi 'timestamp'
        $vs = Get-Val $fi 'virtualSize'
        if ($null -eq $ts -or $null -eq $vs) { continue }      # no symbol-server key => cannot download

        $cands.Add([pscustomobject]@{
            Sha256      = $shaLower
            Version     = $ver
            Ubr         = $ubr
            Timestamp   = [uint32]$ts
            VirtualSize = [uint32]$vs
            Size        = Get-Val $fi 'size'
            MachineType = [int]$mt
            Entry       = $entry
        })
    }

    $result = [pscustomobject]@{
        Selected = $null; Tier = $null; Alternates = 0
        ForBuild = $forBuild; Downloadable = $cands.Count; Reason = $null
        Hashes   = @($allBuild | Sort-Object -Property Ubr)
    }

    if ($forBuild -eq 0) {
        $result.Reason = "Winbindex has no entry for build $OsBuild on this architecture."
        return $result
    }
    if ($cands.Count -eq 0) {
        $result.Reason = "Winbindex lists $forBuild entries for build $OsBuild, but none carry download information."
        return $result
    }

    $pool = @(); $tier = $null
    $exact = @($cands | Where-Object { $_.Ubr -eq $OsUbr })
    if ($exact.Count -gt 0) {
        $pool = $exact; $tier = 'Exact'
    } elseif ($MatchMode -eq 'Nearest') {
        $lower = @($cands | Where-Object { $_.Ubr -lt $OsUbr })
        if ($lower.Count -gt 0) {
            $m = ($lower | Measure-Object -Property Ubr -Maximum).Maximum
            $pool = @($lower | Where-Object { $_.Ubr -eq $m }); $tier = 'NearestLower'
        } else {
            $higher = @($cands | Where-Object { $_.Ubr -gt $OsUbr })
            if ($higher.Count -gt 0) {
                $m = ($higher | Measure-Object -Property Ubr -Minimum).Minimum
                $pool = @($higher | Where-Object { $_.Ubr -eq $m }); $tier = 'NearestHigher'
            }
        }
    }

    if ($pool.Count -eq 0) {
        $result.Reason = "No entry with version $OsBuild.$OsUbr (MatchMode=$MatchMode)."
        return $result
    }

    $result.Selected   = $pool | Sort-Object -Property Timestamp -Descending | Select-Object -First 1
    $result.Tier       = $tier
    $result.Alternates = $pool.Count - 1
    return $result
}

# =============================================================================
# Local files
# =============================================================================

function Get-LocalFileInfo {
    param([Parameter(Mandatory)][string]$Name)
    $p = Join-Path $script:SysDir $Name
    if (-not (Test-Path -LiteralPath $p)) { return $null }

    $item = Get-Item -LiteralPath $p -Force
    $vi   = $item.VersionInfo
    $ver  = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart

    $owner = ''
    try { $owner = (Get-Acl -LiteralPath $p -ErrorAction Stop).Owner } catch { }
    $sig = Get-SignatureInfo -Path $p

    [pscustomobject]@{
        Path          = $p
        Sha256        = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        Version       = $ver
        NoVersionInfo = ((-not $vi.FileVersion) -or $ver -eq '0.0.0.0')
        Size          = $item.Length
        CreatedUtc    = $item.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        ModifiedUtc   = $item.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        Owner         = $owner
        Signature     = $sig.Status
        Signer        = $sig.Signer
    }
}

function Find-GenuineLocalCopies {
    # Searches the component store for copies of $Name whose SHA-256 appears in the
    # Winbindex index for this CPU architecture. Such a copy is genuine Microsoft code.
    param([Parameter(Mandatory)][string]$Name, $Index, [int]$MachineType)

    $root  = Join-Path $env:windir 'WinSxS'
    $found = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $root)) { return ,@() }

    $seen  = @{}
    $items = Get-ChildItem -LiteralPath $root -Recurse -Filter $Name -File -Force -ErrorAction SilentlyContinue
    foreach ($f in $items) {
        $h = $null
        try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { continue }
        if (-not $h) { continue }
        $h = $h.ToLowerInvariant()
        if ($seen.ContainsKey($h)) { continue }
        $seen[$h] = $true
        if (-not $Index.ContainsKey($h)) { continue }

        $fi = Get-Val $Index[$h] 'fileInfo'
        $mt = Get-Val $fi 'machineType'
        if ($null -eq $mt -or [int]$mt -ne $MachineType) { continue }
        $ver = [string](Get-Val $fi 'version')
        if (-not ($ver -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)')) { continue }

        $found.Add([pscustomobject]@{
            Path = $f.FullName; Sha256 = $h; Version = $ver
            Build = [int]$Matches[3]; Ubr = [int]$Matches[4]
        })
    }
    return ,@($found)
}

# =============================================================================
# Verification + download
# =============================================================================

function Test-DownloadedFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Sel)

    $r = [ordered]@{
        Sha256 = ''; Sha256Ok = $false; SizeOk = $null
        PeOk = $false; MachineOk = $false; Passed = $false; Problems = @()
    }

    $r.Sha256   = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $r.Sha256Ok = ($r.Sha256 -eq $Sel.Sha256)
    if (-not $r.Sha256Ok) { $r.Problems += "SHA-256 differs from the Winbindex hash (got $($r.Sha256), index says $($Sel.Sha256))" }

    if ($null -ne $Sel.Size) {
        $len = (Get-Item -LiteralPath $Path).Length
        $r.SizeOk = ($len -eq [int64]$Sel.Size)
        if (-not $r.SizeOk) { $r.Problems += "Size differs ($len bytes vs $($Sel.Size) in the index)" }
    }

    $fs = $null; $br = $null
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $br = New-Object IO.BinaryReader($fs)
        if ($fs.Length -ge 0x40 -and $br.ReadUInt16() -eq 0x5A4D) {                 # 'MZ'
            $fs.Position = 0x3C
            $peOffset = $br.ReadUInt32()
            if ($peOffset -lt ($fs.Length - 24)) {
                $fs.Position = $peOffset
                if ($br.ReadUInt32() -eq 0x00004550) {                              # 'PE\0\0'
                    $machine = $br.ReadUInt16()
                    $r.PeOk = $true
                    $r.MachineOk = ([int]$machine -eq $Sel.MachineType)
                }
            }
        }
    } finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Dispose() }
    }
    if (-not $r.PeOk)          { $r.Problems += 'Not a valid PE file' }
    elseif (-not $r.MachineOk) { $r.Problems += 'PE machine type does not match the requested architecture' }

    $r.Passed = ($r.Sha256Ok -and $r.PeOk -and $r.MachineOk -and ($r.SizeOk -ne $false))
    return [pscustomobject]$r
}

function Save-KnownGoodFile {
    # Downloads from the symbol server. Returns Verified=$true only if the SHA-256
    # equals the Winbindex hash; otherwise the file is parked in .\unverified.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Sel, [Parameter(Mandatory)][string]$DestDir)

    $dest = Join-Path $DestDir $Name
    $out  = [ordered]@{
        Path = $dest; Url = ''; Verified = $false; Reused = $false
        Verification = $null; DownloadedVersion = ''; DownloadedSha256 = ''
    }

    if ((Test-Path -LiteralPath $dest) -and -not $Force) {
        $existing = Test-DownloadedFile -Path $dest -Sel $Sel
        if ($existing.Passed) {
            $out.Verified = $true; $out.Reused = $true; $out.Verification = $existing
            return [pscustomobject]$out
        }
    }

    # Symbol-server key = TimeDateStamp (8 uppercase hex) + SizeOfImage (hex; Winbindex uses lowercase).
    $k1   = '{0:X8}{1:x}' -f $Sel.Timestamp, $Sel.VirtualSize
    $k2   = '{0:X8}{1:X}' -f $Sel.Timestamp, $Sel.VirtualSize
    $keys = @($k1)
    if ($k2 -cne $k1) { $keys += $k2 }

    $part = "$dest.part"
    $ok = $false; $lastErr = $null
    foreach ($k in $keys) {
        $url = "$($script:SymbolBase)/$Name/$k/$Name"
        Write-Log "Downloading $url"
        try {
            Invoke-Download -Uri $url -OutFile $part
            $out.Url = $url
            $ok = $true
            break
        } catch {
            $lastErr = $_.Exception.Message
            Write-Log "Download failed: $lastErr" 'WARN'
        }
    }
    if (-not $ok) { throw "Download failed from the symbol server: $lastErr" }

    $v = Test-DownloadedFile -Path $part -Sel $Sel
    $out.Verification     = $v
    $out.DownloadedSha256 = $v.Sha256

    if (-not $v.PeOk -or -not $v.MachineOk) {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        throw 'The server did not return a valid PE image for this architecture (possibly an error page or a proxy/interception page).'
    }

    if ($v.Passed) {
        Move-Item -LiteralPath $part -Destination $dest -Force
        $out.Verified = $true
        return [pscustomobject]$out
    }

    # Different variant served: keep it, but quarantine it under "unverified".
    $uDir = Join-Path $DestDir 'unverified'
    New-Item -ItemType Directory -Path $uDir -Force | Out-Null
    $uDest = Join-Path $uDir $Name
    Move-Item -LiteralPath $part -Destination $uDest -Force
    $vi = (Get-Item -LiteralPath $uDest).VersionInfo
    $out.Path = $uDest
    $out.DownloadedVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    return [pscustomobject]$out
}

# =============================================================================
# Main
# =============================================================================

$exitCode = 0
$oldProgress = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'     # Invoke-WebRequest is dramatically faster without the progress bar (5.1)
$ErrorActionPreference = 'Stop'

try {
    if ($LogPath) {
        $logDir = Split-Path -Parent $LogPath
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $script:LogFile = $LogPath
    }

    Initialize-Network

    # Use Sysnative if running 32-bit PowerShell on 64-bit Windows so we see the real System32.
    $script:SysDir = Join-Path $env:windir 'System32'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $script:SysDir = Join-Path $env:windir 'Sysnative'
        Write-Log '32-bit PowerShell on 64-bit Windows detected; using Sysnative to read the real System32.' 'DEBUG'
    }

    if (-not $OutputDir) {
        $base = $PSScriptRoot
        if (-not $base) { $base = (Get-Location).Path }
        $OutputDir = Join-Path $base 'KnownGood'
    }
    $script:CacheDir = Join-Path $OutputDir '.cache'
    New-Item -ItemType Directory -Path $script:CacheDir -Force | Out-Null

    # ---- 1. detect OS ----
    $os = Get-OsInfo
    Write-Log ('OS            : {0} {1} ({2}{3})' -f $os.ProductName, $os.DisplayVersion, $os.Edition, $(if ($os.InstallType) { ', ' + $os.InstallType } else { '' }))
    Write-Log ('Version       : {0}   Architecture: {1}{2}' -f $os.FullVersion, $os.Architecture, $(if ($os.IsOverride) { '   (overridden by -TargetVersion)' } else { '' }))

    # A file on disk being OLDER than the OS update level is normal (files only change in some updates).
    # A file that is NEWER than the registry's update level suggests an update awaiting reboot.
    if (-not $os.IsOverride -and $os.DiskVersion -match '^\d+\.\d+\.(\d+)\.(\d+)$') {
        if ([int]$Matches[1] -eq $os.Build -and [int]$Matches[2] -gt $os.Ubr) {
            Write-Log "ntdll.dll on disk ($($os.DiskVersion)) is newer than the running update level ($($os.FullVersion)); an update is probably awaiting a reboot." 'WARN'
        }
    }
    if ($os.Major -lt 10) {
        Write-Log 'Winbindex only indexes Windows 10 / Server 2016 and later; expect no matches on this OS.' 'WARN'
    }

    $destDir = Join-Path $OutputDir ('{0}.{1}-{2}' -f $os.Build, $os.Ubr, $os.Architecture)
    if (-not $ListOnly) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    # ---- 2..5. per file ----
    $results   = New-Object System.Collections.Generic.List[object]
    $allowRows = New-Object System.Collections.Generic.List[object]

    foreach ($file in $Files) {
        $name = ([string]$file).Trim().ToLowerInvariant()
        $res  = [ordered]@{
            File = $name; Status = 'Failed'; Source = ''; Path = ''
            ExpectedVersion = ''; ExpectedSha256 = ''; MatchTier = ''
            ProvidedVersion = ''; ProvidedSha256 = ''
            SymbolServer = ''; SymbolServerUrl = ''; UnverifiedPath = ''; WindowsReleases = ''
            LocalStatus = ''; LocalVersion = ''; LocalSha256 = ''; LocalSize = ''
            LocalModifiedUtc = ''; LocalOwner = ''; LocalSignature = ''
            ExpectedHashesThisBuild = @(); Error = ''
        }

        try {
            if ($name -notmatch '^[a-z0-9_.\-]+$') { throw "Invalid file name '$file'." }
            Write-Log "==== $name ===="

            $index = Get-WinbindexIndex -FileName $name
            Write-Log ("Index contains {0} indexed file versions." -f $index.Count) 'DEBUG'

            $sel = Select-BestEntry -Index $index -MachineType $os.MachineType -OsBuild $os.Build -OsUbr $os.Ubr
            $res.ExpectedHashesThisBuild = @($sel.Hashes)
            foreach ($h in $sel.Hashes) {
                $allowRows.Add([pscustomobject]@{ File = $name; Version = $h.Version; Sha256 = $h.Sha256 })
            }
            if (-not $sel.Selected) { throw $sel.Reason }

            $best = $sel.Selected
            $res.MatchTier       = $sel.Tier
            $res.ExpectedVersion = $best.Version
            $res.ExpectedSha256  = $best.Sha256

            $rels = Get-Val $best.Entry 'windowsVersions'
            if ($rels -is [System.Collections.IDictionary]) { $res.WindowsReleases = (@($rels.Keys) -join ', ') }

            switch ($sel.Tier) {
                'Exact'         { Write-Log ("Expected {0}: version {1} (exact match for OS {2}.{3})." -f $name, $best.Version, $os.Build, $os.Ubr) 'OK' }
                'NearestLower'  { Write-Log ("No file version exactly {0}.{1}. Expecting {2}, the newest version at or below your update level (normal when a file did not change in recent updates)." -f $os.Build, $os.Ubr, $best.Version) 'WARN' }
                'NearestHigher' { Write-Log ("No file version at or below {0}.{1}. Using the closest NEWER version {2}." -f $os.Build, $os.Ubr, $best.Version) 'WARN' }
            }
            Write-Log "Expected SHA-256: $($best.Sha256)"
            Write-Log ("Winbindex knows {0} genuine variant(s) of {1} for build {2} ({3})." -f $sel.Hashes.Count, $name, $os.Build, $os.Architecture) 'DEBUG'

            # ---- examine the installed copy ----
            $local = Get-LocalFileInfo -Name $name
            if (-not $local) {
                $res.LocalStatus = 'NotFoundInSystem'
                Write-Log "$name not found in $($script:SysDir)." 'WARN'
            } else {
                $res.LocalVersion = $local.Version; $res.LocalSha256 = $local.Sha256
                $res.LocalSize = $local.Size; $res.LocalModifiedUtc = $local.ModifiedUtc
                $res.LocalOwner = $local.Owner; $res.LocalSignature = $local.Signature

                Write-Log ("Installed copy: {0} bytes, version {1}, modified {2} UTC, owner {3}, signature {4}" -f `
                    $local.Size, $local.Version, $local.ModifiedUtc, $local.Owner, $local.Signature)
                Write-Log "Installed SHA-256: $($local.Sha256)"

                if ($local.NoVersionInfo) {
                    Write-Log "Installed $name has NO version resource (reports 0.0.0.0). Genuine Microsoft system binaries always carry one." 'ERROR'
                }
                if ($local.Owner -and $local.Owner -notmatch 'TrustedInstaller') {
                    Write-Log "Owner is '$($local.Owner)'; genuine system files are normally owned by NT SERVICE\TrustedInstaller." 'WARN'
                }
                if ($local.Signature -ne 'Valid') {
                    Write-Log "Signature status is '$($local.Signature)' (a genuine, unmodified Windows binary normally validates as 'Valid')." 'WARN'
                }

                if ($local.Sha256 -eq $best.Sha256) {
                    $res.LocalStatus = 'Identical'
                    Write-Log "Installed $name is IDENTICAL to the expected Microsoft file." 'OK'
                } elseif ($index.ContainsKey($local.Sha256)) {
                    $lv = Get-Val (Get-Val $index[$local.Sha256] 'fileInfo') 'version'
                    $res.LocalStatus = "GenuineOtherVersion ($lv)"
                    Write-Log "Installed $name is a genuine Microsoft file, but version $lv rather than the expected $($best.Version)." 'WARN'
                } else {
                    $res.LocalStatus = 'UnknownToWinbindex'
                    Write-Log "Installed $name is NOT in Winbindex (it may be modified/replaced, or an update newer than the index)." 'ERROR'
                }
            }

            # ---- obtain a verified known-good copy ----
            if ($ListOnly) {
                $res.Status = 'Matched (not downloaded)'
            } else {
                $verifiedPath = $null
                $destFile = Join-Path $destDir $name

                # (a) a copy we already trust: the installed file if identical, else a genuine copy in WinSxS
                $pick = $null
                if ($local -and $res.LocalStatus -eq 'Identical') {
                    $pick = [pscustomobject]@{ Path = $local.Path; Sha256 = $local.Sha256; Version = $best.Version; Where = 'System32 (hash-verified)' }
                } elseif (-not $SkipLocalSearch -and -not $os.IsOverride) {
                    Write-Log 'Searching the component store (WinSxS) for genuine copies - this can take a minute...'
                    $found = @(Find-GenuineLocalCopies -Name $name -Index $index -MachineType $os.MachineType)
                    Write-Log ("Found {0} genuine copy/copies of {1} in WinSxS." -f $found.Count, $name) 'DEBUG'
                    $cand = @($found | Where-Object { $_.Build -eq $os.Build })
                    $p1 = $cand | Where-Object { $_.Sha256 -eq $best.Sha256 } | Select-Object -First 1
                    if (-not $p1) {
                        $lowers = @($cand | Where-Object { $_.Ubr -le $os.Ubr })
                        if ($lowers.Count -gt 0) { $p1 = $lowers | Sort-Object -Property Ubr -Descending | Select-Object -First 1 }
                    }
                    if ($p1) {
                        $pick = [pscustomobject]@{ Path = $p1.Path; Sha256 = $p1.Sha256; Version = $p1.Version; Where = 'WinSxS (hash-verified)' }
                    } else {
                        Write-Log "No genuine copy of $name found in WinSxS." 'WARN'
                    }
                }

                if ($pick) {
                    Copy-Item -LiteralPath $pick.Path -Destination $destFile -Force
                    $copyHash = (Get-FileHash -LiteralPath $destFile -Algorithm SHA256).Hash.ToLowerInvariant()
                    if ($copyHash -eq $pick.Sha256) {
                        $verifiedPath = $destFile
                        $res.Source = $pick.Where
                        $res.ProvidedVersion = $pick.Version
                        $res.ProvidedSha256  = $pick.Sha256
                        if ($pick.Sha256 -eq $best.Sha256) {
                            Write-Log "Verified known-good $name copied from $($pick.Path)" 'OK'
                        } else {
                            Write-Log "Verified genuine $name (version $($pick.Version)) copied from $($pick.Path); it is not the exact expected version but is real Microsoft code for this build." 'WARN'
                        }
                    } else {
                        Remove-Item -LiteralPath $destFile -Force -ErrorAction SilentlyContinue
                        Write-Log "Copy of $($pick.Path) failed hash re-check; discarded." 'WARN'
                    }
                }

                # (b) symbol server
                if (-not $SkipDownload) {
                    try {
                        $saved = Save-KnownGoodFile -Name $name -Sel $best -DestDir $destDir
                        $res.SymbolServerUrl = $saved.Url
                        if ($saved.Reused) {
                            $res.SymbolServer = 'Skipped (verified copy already present)'
                        } elseif ($saved.Verified) {
                            $res.SymbolServer = 'Verified (hash matches Winbindex)'
                            Write-Log "Symbol-server download of $name matches the Winbindex hash." 'OK'
                            if (-not $verifiedPath) {
                                $verifiedPath = $saved.Path
                                $res.Source = 'Symbol server (hash-verified)'
                                $res.ProvidedVersion = $best.Version
                                $res.ProvidedSha256  = $best.Sha256
                            }
                        } else {
                            $res.SymbolServer  = 'UNVERIFIED variant (hash differs from Winbindex)'
                            $res.UnverifiedPath = $saved.Path
                            Write-Log ("The symbol server returned a DIFFERENT variant of {0} (SHA-256 {1}, version {2}). Winbindex's author notes it sometimes serves unsigned development builds under the same key. Saved to '{3}' for reference only - do NOT treat it as known-good." -f `
                                $name, $saved.DownloadedSha256, $saved.DownloadedVersion, $saved.Path) 'WARN'
                            foreach ($pr in $saved.Verification.Problems) { Write-Log "  - $pr" 'DEBUG' }
                        }
                    } catch {
                        $res.SymbolServer = 'Failed: ' + $_.Exception.Message
                        Write-Log "Symbol server: $($_.Exception.Message)" 'WARN'
                        if (-not $verifiedPath) { $res.Error = $_.Exception.Message }
                    }
                }

                if ($verifiedPath) {
                    $res.Status = 'OK'
                    $res.Path   = $verifiedPath
                    $res.Error  = ''
                    Write-Log "Result: verified known-good $name -> $verifiedPath" 'OK'
                } elseif ($res.UnverifiedPath) {
                    $res.Status = 'Unverified'
                    $res.Path   = $res.UnverifiedPath
                    $exitCode = 1
                    Write-Log "Result: only an UNVERIFIED $name is available. Get a genuine copy from a trusted machine or the install media and check its SHA-256 against expected-hashes.csv." 'ERROR'
                } else {
                    $res.Status = 'Failed'
                    $exitCode = 1
                    Write-Log "Result: no verified copy of $name could be obtained." 'ERROR'
                }
            }
        } catch {
            $res.Status = 'Failed'
            $res.Error  = $_.Exception.Message
            Write-Log "$name : $($res.Error)" 'ERROR'
            $exitCode = 1
        }

        $results.Add([pscustomobject]$res)
    }

    # ---- cross-file checks ----
    $dupes = @($results | Where-Object { $_.LocalSha256 } | Group-Object -Property LocalSha256 | Where-Object { $_.Count -gt 1 })
    foreach ($g in $dupes) {
        $names = ($g.Group | ForEach-Object { $_.File }) -join ' and '
        Write-Log "Installed $names are BYTE-FOR-BYTE IDENTICAL (SHA-256 $($g.Name)). These are different programs and cannot legitimately be the same file - they have almost certainly been replaced." 'ERROR'
        foreach ($r in $g.Group) { $r.LocalStatus = 'IDENTICAL-TO-OTHER-FILE; ' + $r.LocalStatus }
    }

    # ---- report ----
    Write-Host ''
    Write-Log '==== Summary ====' 'OK'
    $results | Select-Object File, Status, Source, ExpectedVersion, LocalStatus |
        Format-Table -AutoSize | Out-String -Width 220 | Write-Host

    if (-not $ListOnly) {
        $manifest = [pscustomobject]@{
            GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
            Computer     = $env:COMPUTERNAME
            OS           = $os
            Source       = [pscustomobject]@{ Index = $script:IndexBase; Symbols = $script:SymbolBase }
            Results      = $results
        }
        $manifestPath = Join-Path $destDir 'manifest.json'
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

        $sums = foreach ($r in $results) { if ($r.Status -eq 'OK') { '{0} *{1}' -f $r.ProvidedSha256, $r.File } }
        if ($sums) { Set-Content -Path (Join-Path $destDir 'SHA256SUMS.txt') -Value $sums -Encoding ASCII }

        $csvPath = Join-Path $destDir 'expected-hashes.csv'
        $allowRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

        Write-Log "Output folder : $destDir"
        Write-Log "Manifest      : $manifestPath"
        Write-Log "Genuine hashes: $csvPath (every Winbindex hash for this build - check candidate files against it)"
    }

    $bad = @($results | Where-Object { $_.LocalStatus -and $_.LocalStatus -ne 'Identical' -and $_.LocalStatus -ne 'NotFoundInSystem' })
    if ($bad.Count -gt 0) {
        Write-Log ("{0} installed file(s) do NOT match the expected Microsoft copy: {1}" -f $bad.Count, (($bad | ForEach-Object { $_.File }) -join ', ')) 'WARN'
    }
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" 'ERROR'
    $exitCode = 2
}
finally {
    $ProgressPreference = $oldProgress
}

exit $exitCode
