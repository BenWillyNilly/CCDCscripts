#Requires -Version 5.1
<#
.SYNOPSIS
    Detects the running Windows build, finds the matching sfc.exe and dism.exe in
    Winbindex (winbindex.m417z.com), downloads known-good copies from Microsoft's
    public symbol server, and verifies them.

.DESCRIPTION
    1. Detects Windows version/build/UBR/architecture (registry + ntdll cross-check).
    2. Downloads the Winbindex index for each requested file
       (https://winbindex.m417z.com/data/by_filename_compressed/<file>.json.gz).
    3. Picks the entry that matches this OS build + UBR + CPU architecture:
         Exact         - file version == <build>.<UBR> of the running OS
         NearestLower  - highest version for this build that is <= your UBR
                         (Windows only bumps a file's version when it changes)
         NearestHigher - last resort, only with -MatchMode Nearest
    4. Downloads the binary from msdl.microsoft.com using the PE TimeDateStamp +
       SizeOfImage key from the index, with retries.
    5. Verifies the download: SHA-256 equals the index key, file size, PE header,
       CPU architecture. Authenticode status is reported for information.
    6. Compares the copy installed in System32 against the known-good copy and
       against the whole Winbindex index (a hash Winbindex has never seen is a red
       flag for a replaced/modified file - or an update newer than the index).
    7. Writes manifest.json and SHA256SUMS.txt next to the downloads.

    Nothing is ever written to System32. The downloaded files are for comparison,
    hashing and offline analysis.

.PARAMETER Files
    Files to look up. Default: sfc.exe, dism.exe. Add more (e.g. sfc_os.dll,
    dismapi.dll, dismcore.dll) if you want them too.

.PARAMETER OutputDir
    Base download folder. Default: .\KnownGood (files go in a subfolder named
    <build>.<ubr>-<arch>).

.PARAMETER TargetVersion
    Override the detected version, e.g. "26100.7920" or "10.0.26100.7920"
    (useful for fetching files for a different machine).

.PARAMETER Architecture
    Auto (default), x64, x86 or arm64.

.PARAMETER MatchMode
    Nearest (default) or ExactOnly.

.PARAMETER ListOnly
    Show which files would be downloaded, but download nothing.

.PARAMETER Force
    Re-download even if a verified copy is already present.

.PARAMETER NoCache / CacheHours
    Control caching of the Winbindex index files (default 24 h).

.PARAMETER Proxy
    Optional proxy URL. Default system proxy settings are used otherwise.

.PARAMETER LogPath
    Optional path of a log file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-KnownGoodSfcDism.ps1

.EXAMPLE
    .\Get-KnownGoodSfcDism.ps1 -ListOnly

.EXAMPLE
    .\Get-KnownGoodSfcDism.ps1 -Files sfc.exe,dism.exe,sfc_os.dll,dismapi.dll,dismcore.dll -OutputDir C:\Evidence

.EXAMPLE
    .\Get-KnownGoodSfcDism.ps1 -TargetVersion 10.0.22621.3007 -Architecture x64

.NOTES
    Exit codes: 0 = everything succeeded, 1 = at least one file failed, 2 = fatal error.
    Works on Windows PowerShell 5.1 and PowerShell 7+. Needs internet access to
    winbindex.m417z.com and msdl.microsoft.com (HTTPS). Admin rights not required.
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
    [string]$LogPath
)

$script:IndexBase    = 'https://winbindex.m417z.com/data/by_filename_compressed'
$script:SymbolBase   = 'https://msdl.microsoft.com/download/symbols'
$script:UserAgent    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) KnownGoodFetcher/1.0'
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
    # Safe lookup that works for dictionaries (Hashtable / Dictionary<string,object>) and PSCustomObjects.
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

# =============================================================================
# OS detection
# =============================================================================

function Get-OsInfo {
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop

    # --- architecture ---
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

    # --- version ---
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

    # --- cross-check against the on-disk ntdll.dll (differs while a reboot is pending) ---
    $diskVersion = $null
    $ntdll = Join-Path $script:SysDir 'ntdll.dll'
    if (Test-Path -LiteralPath $ntdll) {
        $vi = (Get-Item -LiteralPath $ntdll).VersionInfo
        $diskVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    }

    $isOverride = $false
    if ($TargetVersion) {
        if (-not ($TargetVersion.Trim() -match '^(?:(\d+)\.(\d+)\.)?(\d+)\.(\d+)$')) {
            throw "-TargetVersion '$TargetVersion' is not valid. Use e.g. 26100.7920 or 10.0.26100.7920."
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

    $cands        = New-Object System.Collections.Generic.List[object]
    $forBuild     = 0
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

        $ts = Get-Val $fi 'timestamp'
        $vs = Get-Val $fi 'virtualSize'
        if ($null -eq $ts -or $null -eq $vs) { continue }      # no symbol-server key => cannot download

        $cands.Add([pscustomobject]@{
            Sha256      = ([string]$sha).ToLowerInvariant()
            Version     = $ver
            Ubr         = $ubr
            Timestamp   = [uint32]$ts
            VirtualSize = [uint32]$vs
            Size        = Get-Val $fi 'size'
            MachineType = [int]$mt
            Entry       = $entry
        })
    }

    $result = [pscustomobject]@{ Selected = $null; Tier = $null; Alternates = 0; ForBuild = $forBuild; Downloadable = $cands.Count; Reason = $null }

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
# Local file + verification
# =============================================================================

function Get-LocalFileInfo {
    param([Parameter(Mandatory)][string]$Name)
    $p = Join-Path $script:SysDir $Name
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $vi = (Get-Item -LiteralPath $p).VersionInfo
    [pscustomobject]@{
        Path    = $p
        Sha256  = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        Version = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    }
}

function Test-DownloadedFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Sel)

    $r = [ordered]@{
        Sha256 = ''; Sha256Ok = $false; SizeOk = $null
        PeOk = $false; MachineOk = $false; Passed = $false; Problems = @()
    }

    $r.Sha256   = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $r.Sha256Ok = ($r.Sha256 -eq $Sel.Sha256)
    if (-not $r.Sha256Ok) { $r.Problems += "SHA-256 mismatch (got $($r.Sha256), expected $($Sel.Sha256))" }

    if ($null -ne $Sel.Size) {
        $len = (Get-Item -LiteralPath $Path).Length
        $r.SizeOk = ($len -eq [int64]$Sel.Size)
        if (-not $r.SizeOk) { $r.Problems += "Size mismatch ($len vs $($Sel.Size))" }
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
    if (-not $r.PeOk)      { $r.Problems += 'Not a valid PE file' }
    elseif (-not $r.MachineOk) { $r.Problems += 'PE machine type does not match the requested architecture' }

    $r.Passed = ($r.Sha256Ok -and $r.PeOk -and $r.MachineOk -and ($r.SizeOk -ne $false))
    return [pscustomobject]$r
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

function Save-KnownGoodFile {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Sel, [Parameter(Mandatory)][string]$DestDir)

    $dest = Join-Path $DestDir $Name
    $out  = [ordered]@{ Path = $dest; Url = ''; Reused = $false; Verification = $null }

    if ((Test-Path -LiteralPath $dest) -and -not $Force) {
        $h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($h -eq $Sel.Sha256) {
            Write-Log "$Name already present and hash-verified; skipping download (use -Force to re-download)." 'OK'
            $out.Reused       = $true
            $out.Verification = Test-DownloadedFile -Path $dest -Sel $Sel
            return [pscustomobject]$out
        }
        Write-Log "$Name exists but its hash does not match the expected file; re-downloading." 'WARN'
    }

    # Symbol-server key = TimeDateStamp (8 uppercase hex) + SizeOfImage (hex). Winbindex uses
    # lowercase for the size; try uppercase as a fallback in case the server is case-sensitive.
    $k1   = '{0:X8}{1:x}' -f $Sel.Timestamp, $Sel.VirtualSize
    $k2   = '{0:X8}{1:X}' -f $Sel.Timestamp, $Sel.VirtualSize
    $keys = @($k1)
    if ($k2 -cne $k1) { $keys += $k2 }

    $part    = "$dest.part"
    $ok      = $false
    $lastErr = $null
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
    if (-not $v.Passed) {
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        throw ('Downloaded file failed verification and was deleted: ' + ($v.Problems -join '; '))
    }

    Move-Item -LiteralPath $part -Destination $dest -Force
    $out.Verification = $v
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

    # System directory (use Sysnative if running 32-bit PowerShell on 64-bit Windows so we see the real files)
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
    if (-not $os.IsOverride -and $os.DiskVersion -and $os.DiskVersion -ne $os.FullVersion) {
        Write-Log "ntdll.dll on disk is $($os.DiskVersion) but the registry reports $($os.FullVersion). A reboot may be pending after an update; matches may differ from what is on disk." 'WARN'
    }
    if ($os.Major -lt 10) {
        Write-Log 'Winbindex only indexes Windows 10 / Server 2016 and later; expect no matches on this OS.' 'WARN'
    }

    $destDir = Join-Path $OutputDir ('{0}.{1}-{2}' -f $os.Build, $os.Ubr, $os.Architecture)
    if (-not $ListOnly) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    # ---- 2..6. per file ----
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($file in $Files) {
        $name = ([string]$file).Trim().ToLowerInvariant()
        $res  = [ordered]@{
            File = $name; Status = 'Failed'; MatchTier = ''; Version = ''; Sha256 = ''; Url = ''; Path = ''
            WindowsReleases = ''; LocalStatus = ''; LocalVersion = ''; LocalSha256 = ''
            Signature = ''; Signer = ''; Error = ''
        }

        try {
            if ($name -notmatch '^[a-z0-9_.\-]+$') { throw "Invalid file name '$file'." }
            Write-Log "==== $name ===="

            $index = Get-WinbindexIndex -FileName $name
            Write-Log ("Index contains {0} indexed file versions." -f $index.Count) 'DEBUG'

            $sel = Select-BestEntry -Index $index -MachineType $os.MachineType -OsBuild $os.Build -OsUbr $os.Ubr
            if (-not $sel.Selected) { throw $sel.Reason }

            $best = $sel.Selected
            $res.MatchTier = $sel.Tier
            $res.Version   = $best.Version
            $res.Sha256    = $best.Sha256

            $rels = Get-Val $best.Entry 'windowsVersions'
            if ($rels -is [System.Collections.IDictionary]) { $res.WindowsReleases = (@($rels.Keys) -join ', ') }

            switch ($sel.Tier) {
                'Exact'         { Write-Log ("Matched {0} version {1} (exact match for OS {2}.{3})." -f $name, $best.Version, $os.Build, $os.Ubr) 'OK' }
                'NearestLower'  { Write-Log ("No file version exactly {0}.{1}. Using {2}, the newest version at or below your update level (normal when the file did not change in recent updates)." -f $os.Build, $os.Ubr, $best.Version) 'WARN' }
                'NearestHigher' { Write-Log ("No file version at or below {0}.{1}. Using the closest NEWER version {2}." -f $os.Build, $os.Ubr, $best.Version) 'WARN' }
            }
            if ($sel.Alternates -gt 0) { Write-Log "$($sel.Alternates) other index entr$(if ($sel.Alternates -eq 1) {'y'} else {'ies'}) share this version; newest build timestamp chosen." 'DEBUG' }
            if ($res.WindowsReleases) { Write-Log "Winbindex lists this file in: $($res.WindowsReleases)" 'DEBUG' }
            Write-Log "SHA-256 expected: $($best.Sha256)"

            # ---- local comparison ----
            $local = Get-LocalFileInfo -Name $name
            if (-not $local) {
                $res.LocalStatus = 'NotFoundInSystem'
                Write-Log "$name not found in $($script:SysDir)." 'WARN'
            } else {
                $res.LocalVersion = $local.Version
                $res.LocalSha256  = $local.Sha256
                if ($local.Sha256 -eq $best.Sha256) {
                    $res.LocalStatus = 'Identical'
                    Write-Log "Installed $name is IDENTICAL to Microsoft's copy." 'OK'
                } elseif ($index.ContainsKey($local.Sha256)) {
                    $lv = Get-Val (Get-Val $index[$local.Sha256] 'fileInfo') 'version'
                    $res.LocalStatus = "GenuineOtherVersion ($lv)"
                    Write-Log "Installed $name is a genuine Microsoft file but a different version ($lv) than expected ($($best.Version)). Could be a pending update, or an old file swapped in." 'WARN'
                } else {
                    $res.LocalStatus = 'UnknownToWinbindex'
                    Write-Log "Installed $name (SHA-256 $($local.Sha256), version $($local.Version)) is NOT in Winbindex. It may be modified/replaced - or an update newer than the index. Investigate." 'ERROR'
                }
            }

            # ---- download ----
            if ($ListOnly) {
                $res.Status = 'Matched (not downloaded)'
            } else {
                $saved = Save-KnownGoodFile -Name $name -Sel $best -DestDir $destDir
                $res.Path = $saved.Path
                $res.Url  = $saved.Url
                $sig = Get-SignatureInfo -Path $saved.Path
                $res.Signature = $sig.Status
                $res.Signer    = $sig.Signer
                $res.Status    = if ($saved.Reused) { 'OK (already present)' } else { 'OK' }
                Write-Log "Verified: SHA-256, size and PE header match. Saved to $($saved.Path)" 'OK'
                Write-Log ("Authenticode: {0}{1}" -f $sig.Status, $(if ($sig.Status -eq 'NotSigned') { ' (normal for catalog-signed Windows binaries; the SHA-256 match above is the authoritative check)' } else { '' })) 'DEBUG'
            }
        } catch {
            $res.Status = 'Failed'
            $res.Error  = $_.Exception.Message
            Write-Log "$name : $($res.Error)" 'ERROR'
            $exitCode = 1
        }

        $results.Add([pscustomobject]$res)
    }

    # ---- 7. report ----
    Write-Host ''
    Write-Log '==== Summary ====' 'OK'
    $results | Select-Object File, Status, MatchTier, Version,
        @{ n = 'SHA256'; e = { if ($_.Sha256) { $_.Sha256.Substring(0, 16) + '...' } else { '' } } },
        LocalStatus | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

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

        $sums = foreach ($r in $results) { if ($r.Status -like 'OK*') { '{0} *{1}' -f $r.Sha256, $r.File } }
        if ($sums) { Set-Content -Path (Join-Path $destDir 'SHA256SUMS.txt') -Value $sums -Encoding ASCII }

        Write-Log "Output folder : $destDir"
        Write-Log "Manifest      : $manifestPath"
    }

    $bad = @($results | Where-Object { $_.LocalStatus -eq 'UnknownToWinbindex' -or $_.LocalStatus -like 'GenuineOtherVersion*' })
    if ($bad.Count -gt 0) {
        Write-Log ("{0} installed file(s) differ from the expected Microsoft copy: {1}" -f $bad.Count, (($bad | ForEach-Object { $_.File }) -join ', ')) 'WARN'
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
