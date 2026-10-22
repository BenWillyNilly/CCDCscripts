while ($true)
{
    Clear-Host

    Write-Host "Listening Ports - $(Get-Date)" -ForegroundColor Cyan
    Write-Host "===================================================="

    Get-NetTCPConnection -State Listen |
    Sort-Object LocalPort |
    ForEach-Object {

        try {
            $ProcessName = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
        }
        catch {
            $ProcessName = "Unknown"
        }

        [PSCustomObject]@{
            Port    = $_.LocalPort
            Address = $_.LocalAddress
            PID     = $_.OwningProcess
            Process = $ProcessName
        }
    } |
    Format-Table -AutoSize

    Write-Host ""
    Write-Host "Refreshing in 6 seconds..." -ForegroundColor Yellow

    for ($i = 0; $i -le 10; $i++)
    {
        $filled = "=" * $i
        $empty = "-" * (10 - $i)

        Write-Host -NoNewline "`r[$filled$empty]"

        Start-Sleep -Milliseconds 500
    }
}
``