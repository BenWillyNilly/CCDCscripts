#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lists every local user, marks admins with [!] and everyone else with [*],
    and lets you remove admin privileges (Administrators group membership).
#>

$AdminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name   # Administrators
$Me         = "$env:COMPUTERNAME\$env:USERNAME"

function Get-AdminSids {
    @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction SilentlyContinue |
        ForEach-Object { $_.SID.Value })
}

function Show-Users {
    Clear-Host
    $adminMembers = @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction SilentlyContinue)
    $adminSids    = @($adminMembers | ForEach-Object { $_.SID.Value })
    $users        = @(Get-LocalUser | Sort-Object Name)
    $userSids     = @($users | ForEach-Object { $_.SID.Value })

    Write-Host "All users  ([!] = admin, [*] = standard)" -ForegroundColor White
    Write-Host ""

    # Local users
    foreach ($u in $users) {
        $tag = if ($u.Enabled -eq $false) { '  [DISABLED]' } else { '' }
        if ($adminSids -contains $u.SID.Value) {
            Write-Host ("[!] {0}{1}" -f $u.Name, $tag) -ForegroundColor Red
        } else {
            Write-Host ("[*] {0}{1}" -f $u.Name, $tag) -ForegroundColor Green
        }
    }

    # Admin members that are not local users (domain accounts, groups)
    foreach ($m in $adminMembers) {
        if ($userSids -notcontains $m.SID.Value) {
            Write-Host ("[!] {0}  ({1})" -f $m.Name, $m.ObjectClass) -ForegroundColor Red
        }
    }
    Write-Host ""
}

function Remove-AdminRights {
    param([string[]]$Names)

    $members = @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction SilentlyContinue)

    foreach ($raw in $Names) {
        $name = $raw.Trim()
        if (-not $name) { continue }

        $m = $members | Where-Object {
            $_.Name -ieq $name -or $_.Name -ieq "$env:COMPUTERNAME\$name"
        } | Select-Object -First 1

        if (-not $m) {
            Write-Host "$name is not an administrator." -ForegroundColor Yellow
            continue
        }

        if ($m.SID.Value -match '-500$') {
            Write-Host "$name is the built-in Administrator and cannot be removed from $AdminGroup. Rename or disable it instead." -ForegroundColor Yellow
            continue
        }

        if ($m.Name -ieq $Me) {
            $c = Read-Host "$name is the account you are logged in as. Remove anyway? (y/N)"
            if ($c -notmatch '^[yY]') { continue }
        }

        try {
            Remove-LocalGroupMember -Group $AdminGroup -Member $m -ErrorAction Stop
            Write-Host "Removed admin privileges from $($m.Name)." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed on $name : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ---- Main loop ----
do {
    Show-Users
    Write-Host "[R] Remove admin from user(s)   [Q] Quit"
    $choice = (Read-Host "Choice").Trim().ToUpper()

    if ($choice -eq 'R') {
        $input = Read-Host "Username(s) to demote (comma-separated)"
        Remove-AdminRights -Names ($input -split ',')
        Read-Host "Press Enter to continue" | Out-Null
    }
} while ($choice -ne 'Q')
