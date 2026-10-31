#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Show who can RDP into this server, and add/remove users.

.NOTES
    RDP access is granted to members of "Remote Desktop Users" and
    "Administrators". The script checks both. Group names are resolved by
    SID so it works on any language install.
#>

$RdpGroup   = (Get-LocalGroup -SID 'S-1-5-32-555').Name   # Remote Desktop Users
$AdminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name   # Administrators

function Show-RdpState {
    $ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tcp = "$ts\WinStations\RDP-Tcp"
    $enabled = (Get-ItemProperty $ts -Name fDenyTSConnections).fDenyTSConnections -eq 0
    $nla     = (Get-ItemProperty $tcp -Name UserAuthentication).UserAuthentication -eq 1
    $port    = (Get-ItemProperty $tcp -Name PortNumber).PortNumber

    Write-Host "RDP enabled : $enabled" -ForegroundColor Cyan
    Write-Host "RDP port    : $port"    -ForegroundColor Cyan
    Write-Host "NLA required: $nla"     -ForegroundColor Cyan
    Write-Host ""
}

function Get-RdpReport {
    $rdp = @(Get-LocalGroupMember -Group $RdpGroup   -ErrorAction SilentlyContinue)
    $adm = @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction SilentlyContinue)
    $rdpSids = @($rdp | ForEach-Object { $_.SID.Value })
    $admSids = @($adm | ForEach-Object { $_.SID.Value })

    $with    = @()
    $without = @()
    $localUsers = Get-LocalUser
    $localSids  = @($localUsers | ForEach-Object { $_.SID.Value })

    # Local user accounts
    foreach ($u in $localUsers) {
        $sid = $u.SID.Value
        $via = @()
        if ($admSids -contains $sid) { $via += $AdminGroup }
        if ($rdpSids -contains $sid) { $via += $RdpGroup }

        $obj = [pscustomobject]@{
            Name    = $u.Name
            Enabled = $u.Enabled
            Via     = ($via -join ', ')
        }
        if ($via.Count -gt 0) { $with += $obj } else { $without += $obj }
    }

    # Domain users/groups or other local groups that are members
    $others = @{}
    foreach ($pair in @(@($rdp, $RdpGroup), @($adm, $AdminGroup))) {
        foreach ($m in $pair[0]) {
            if ($localSids -contains $m.SID.Value) { continue }
            if (-not $others.ContainsKey($m.Name)) { $others[$m.Name] = @() }
            $others[$m.Name] += $pair[1]
        }
    }
    foreach ($name in $others.Keys) {
        $with += [pscustomobject]@{
            Name    = $name
            Enabled = $null
            Via     = ($others[$name] -join ', ')
        }
    }

    [pscustomobject]@{ With = $with; Without = $without }
}

function Show-RdpAccess {
    Clear-Host
    Show-RdpState
    $r = Get-RdpReport

    Write-Host "Users with access:" -ForegroundColor White
    if ($r.With.Count -eq 0) { Write-Host "  (none)" }
    foreach ($u in ($r.With | Sort-Object Name)) {
        $tag = if ($u.Enabled -eq $false) { ' [DISABLED]' } else { '' }
        Write-Host ("[!] {0}{1}  <- {2}" -f $u.Name, $tag, $u.Via) -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "User without access:" -ForegroundColor White
    if ($r.Without.Count -eq 0) { Write-Host "  (none)" }
    foreach ($u in ($r.Without | Sort-Object Name)) {
        $tag = if ($u.Enabled -eq $false) { ' [DISABLED]' } else { '' }
        Write-Host ("[*] {0}{1}" -f $u.Name, $tag) -ForegroundColor Green
    }
    Write-Host ""
}

function Add-RdpUser {
    $name = Read-Host "Username to ADD to $RdpGroup (DOMAIN\user for domain accounts)"
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    try {
        Add-LocalGroupMember -Group $RdpGroup -Member $name -ErrorAction Stop
        Write-Host "Added $name to $RdpGroup." -ForegroundColor Green
    }
    catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        Write-Host "$name is already in $RdpGroup." -ForegroundColor Yellow
    }
    catch {
        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Remove-RdpUser {
    $name = Read-Host "Username to REMOVE from RDP access"
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    $match = {
        param($m)
        $m.Name -ieq $name -or $m.Name -ieq "$env:COMPUTERNAME\$name"
    }

    $inRdp = @(Get-LocalGroupMember -Group $RdpGroup   -ErrorAction SilentlyContinue | Where-Object { & $match $_ })
    $inAdm = @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction SilentlyContinue | Where-Object { & $match $_ })

    if ($inRdp.Count -eq 0 -and $inAdm.Count -eq 0) {
        Write-Host "$name is not in $RdpGroup or $AdminGroup." -ForegroundColor Yellow
        return
    }

    if ($inRdp.Count -gt 0) {
        try {
            Remove-LocalGroupMember -Group $RdpGroup -Member $inRdp[0] -ErrorAction Stop
            Write-Host "Removed $name from $RdpGroup." -ForegroundColor Green
        }
        catch { Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red }
    }

    if ($inAdm.Count -gt 0) {
        Write-Host "$name is also in $AdminGroup, which still allows RDP." -ForegroundColor Yellow

        $me = "$env:COMPUTERNAME\$env:USERNAME"
        if ($inAdm[0].Name -ieq $me) {
            Write-Host "That is the account you are logged in as. Not removing it." -ForegroundColor Yellow
            return
        }

        $ans = Read-Host "Remove $name from $AdminGroup too? (y/N)"
        if ($ans -match '^[yY]') {
            try {
                Remove-LocalGroupMember -Group $AdminGroup -Member $inAdm[0] -ErrorAction Stop
                Write-Host "Removed $name from $AdminGroup." -ForegroundColor Green
            }
            catch { Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
}

# ---- Main loop ----
do {
    Show-RdpAccess
    Write-Host "[A] Add user   [R] Remove user   [F] Refresh   [Q] Quit"
    $choice = (Read-Host "Choice").Trim().ToUpper()

    switch ($choice) {
        'A' { Add-RdpUser;    Read-Host "Press Enter to continue" | Out-Null }
        'R' { Remove-RdpUser; Read-Host "Press Enter to continue" | Out-Null }
    }
} while ($choice -ne 'Q')
