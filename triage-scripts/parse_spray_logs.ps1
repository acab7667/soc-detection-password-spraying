<#
.SYNOPSIS
    SOC Log Parser: Password Spraying Detector & Extractor (PowerShell Native)
.DESCRIPTION
    Memproses log autentikasi JSON dari SIEM/Windows/Entra ID,
    mengesan corak serangan password spraying, dan menandakan akaun yang telah ditembusi.
.EXAMPLE
    .\parse_spray_logs.ps1 -LogFile "..\test-data\simulation_scenario.json" -OutputIps "suspicious_ips.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$LogFile,

    [Parameter(Position = 1)]
    [int]$Threshold = 3,

    [Parameter(Position = 2)]
    [string]$OutputIps
)

if (-not (Test-Path $LogFile)) {
    Write-Error "[-] Fail log tidak ditemui: $LogFile"
    exit 1
}

Write-Host "[*] Membaca log: $LogFile" -ForegroundColor Cyan
$Content = Get-Content -Path $LogFile -Raw | ConvertFrom-Json

# Normalize events array
$Events = if ($Content -is [array]) { $Content } elseif ($Content.records) { $Content.records } elseif ($Content.value) { $Content.value } else { @($Content) }

Write-Host "[*] Menjumpai $($Events.Count) rekod log autentikasi.`n"

$IpStats = @{}

foreach ($entry in $Events) {
    # Normalize IP
    $ip = $null
    foreach ($f in @("IpAddress", "IPAddress", "ip", "SourceIP", "c-ip", "client_ip")) {
        if ($entry.$f) { $ip = $entry.$f; break }
    }

    # Normalize User
    $user = $null
    foreach ($f in @("TargetUserName", "UserPrincipalName", "AccountUpn", "user", "username", "account")) {
        if ($entry.$f) { $user = $entry.$f; break }
    }

    # Normalize EventID
    $eventID = $null
    foreach ($f in @("EventID", "event_id", "ResultType", "status_code", "ActionType")) {
        if ($entry.$f -ne $null) { $eventID = [string]$entry.$f; break }
    }

    # Noise filter
    if (-not $ip -or $ip -in @("-", "127.0.0.1", "::1") -or $ip.StartsWith("192.168.")) { continue }
    if (-not $user -or $user.EndsWith('$')) { continue }

    $isSuccess = $eventID -in @("4624", "0", "success", "LogonSuccess")
    $isFailure = $eventID -in @("4625", "4771", "50126", "failure", "LogonFailed")

    if (-not $IpStats.ContainsKey($ip)) {
        $IpStats[$ip] = [PSCustomObject]@{
            FailedUsers  = [System.Collections.Generic.HashSet[string]]::new()
            SuccessUsers = [System.Collections.Generic.HashSet[string]]::new()
            TotalEvents  = 0
        }
    }

    $stat = $IpStats[$ip]
    $stat.TotalEvents++

    if ($isSuccess) {
        $null = $stat.SuccessUsers.Add($user)
    } elseif ($isFailure -or -not $isSuccess) {
        $null = $stat.FailedUsers.Add($user)
    }
}

Write-Host ("=" * 85) -ForegroundColor DarkGray
Write-Host (" " * 22 + "LAPORAN ANALISIS PASSWORD SPRAYING (SOC TRIAGE)") -ForegroundColor Yellow
Write-Host ("=" * 85) -ForegroundColor DarkGray
Write-Host ("{0,-18} | {1,-12} | {2,-14} | {3,-26}" -f "Source IP", "Akaun Gagal", "Akaun Berjaya", "Status Ancaman") -ForegroundColor White
Write-Host ("-" * 85) -ForegroundColor DarkGray

$SuspiciousList = @()

foreach ($ip in $IpStats.Keys) {
    $stat = $IpStats[$ip]
    $failedCount = $stat.FailedUsers.Count
    $successCount = $stat.SuccessUsers.Count

    if ($failedCount -ge $Threshold) {
        $SuspiciousList += $ip
        if ($successCount -gt 0) {
            $threat = "CRITICAL (COMPROMISED)"
            $color = "Red"
        } else {
            $threat = "HIGH (Spray Suspected)"
            $color = "Yellow"
        }
    } elseif ($successCount -gt 0 -and $failedCount -gt 0) {
        $threat = "MEDIUM (Anomaly)"
        $color = "DarkYellow"
    } else {
        continue
    }

    Write-Host ("{0,-18} | {1,-12} | {2,-14} | " -f $ip, $failedCount, $successCount) -NoNewline
    Write-Host ("{0,-26}" -f $threat) -ForegroundColor $color
}

Write-Host ("=" * 85) -ForegroundColor DarkGray

if ($SuspiciousList.Count -gt 0) {
    Write-Host "`n[!] PERINCIAN KESELAMATAN BAGI IP MENCURIGAKAN:" -ForegroundColor Magenta
    foreach ($ip in $SuspiciousList) {
        $stat = $IpStats[$ip]
        Write-Host "`n[+] IP Sasaran: $ip" -ForegroundColor Cyan
        Write-Host "    - Jumlah Percubaan Log    : $($stat.TotalEvents)"
        Write-Host "    - Akaun Gagal Disasar     : $(($stat.FailedUsers | Select-Object -First 10) -join ', ')"
        if ($stat.SuccessUsers.Count -gt 0) {
            Write-Host "    - 🚨 AKAUN BERJAYA DITEMBUSI : $(($stat.SuccessUsers) -join ', ')" -ForegroundColor Red
            Write-Host "      [TINDAKAN SEGERA] Revoke sesi & Reset password bagi akaun di atas!" -ForegroundColor Red
        } else {
            Write-Host "    - Status Penembusan       : TIADA (Perimeter berjaya bertahan)." -ForegroundColor Green
        }
    }

    if ($OutputIps) {
        $SuspiciousList | Out-File -FilePath $OutputIps -Encoding utf8
        Write-Host "`n[+] Senarai IP suspek berjaya diekstrak ke: $OutputIps" -ForegroundColor Green
    }
} else {
    Write-Host "`n[+] Tiada aktiviti password spraying dikesan melebihi nilai ambang." -ForegroundColor Green
}
