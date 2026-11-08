<#
.SYNOPSIS
    SOC Triage Helper: IP Reputation & Threat Intel Enrichment (PowerShell Native)
.DESCRIPTION
    Menyemak Geolocation, ASN, Status Proxy/Hosting, VirusTotal v3, dan AbuseIPDB v2.
.EXAMPLE
    .\enrich_ip.ps1 -Ips "185.220.101.5" -VtKey "..." -AbuseKey "..."
    .\enrich_ip.ps1 -File "suspicious_ips.txt" -Csv "laporan_triage.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Ips,

    [string]$File,
    [string]$VtKey = $env:VT_API_KEY,
    [string]$AbuseKey = $env:ABUSEIPDB_API_KEY,
    [string]$Csv
)

$Targets = @()
if ($Ips) { $Targets += $Ips }
if ($File -and (Test-Path $File)) {
    $Lines = Get-Content -Path $File | Where-Object { $_.Trim() -and -not $_.StartsWith("#") }
    $Targets += $Lines
}

if ($Targets.Count -eq 0) {
    Write-Host "Penggunaan: .\enrich_ip.ps1 <IP1> [IP2...] [-File ips.txt] [-VtKey key] [-AbuseKey key] [-Csv out.csv]"
    exit 1
}

Write-Host "[*] Memulakan semakan reputasi untuk $($Targets.Count) alamat IP...`n" -ForegroundColor Cyan

$Results = @()

foreach ($ip in $Targets) {
    $ip = $ip.Trim()
    
    # 1. Semakan Geolocation via ip-api.com
    $GeoUrl = "http://ip-api.com/json/$ip?fields=status,message,country,city,isp,org,as,proxy,hosting,query"
    $GeoData = $null
    try {
        $GeoData = Invoke-RestMethod -Uri $GeoUrl -Method Get -TimeoutSec 5 -ErrorAction Stop
    } catch {
        Write-Warning "[-] Ralat menyambung ke ip-api untuk $ip"
    }

    # 2. Semakan VirusTotal v3
    $VtSummary = "N/A (Tiada API Key)"
    $VtMalicious = 0
    if ($VtKey) {
        $VtUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
        $VtHeaders = @{ "x-apikey" = $VtKey }
        try {
            $VtResp = Invoke-RestMethod -Uri $VtUrl -Headers $VtHeaders -Method Get -TimeoutSec 8 -ErrorAction Stop
            $Stats = $VtResp.data.attributes.last_analysis_stats
            $Rep = $VtResp.data.attributes.reputation
            $VtMalicious = $Stats.malicious
            $Total = $Stats.malicious + $Stats.suspicious + $Stats.harmless + $Stats.undetected
            $VtSummary = "$($Stats.malicious)/$Total vendor dikesan bahaya (Reputasi: $Rep)"
        } catch {
            $VtSummary = "Ralat semakan VT ($_)"
        }
    }

    # 3. Semakan AbuseIPDB v2
    $AbuseSummary = "N/A (Tiada API Key)"
    $AbuseScore = 0
    $IsTor = $false
    $UsageType = "N/A"
    if ($AbuseKey) {
        $AbuseUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90&verbose"
        $AbuseHeaders = @{ "Key" = $AbuseKey; "Accept" = "application/json" }
        try {
            $AbuseResp = Invoke-RestMethod -Uri $AbuseUrl -Headers $AbuseHeaders -Method Get -TimeoutSec 8 -ErrorAction Stop
            $Data = $AbuseResp.data
            $AbuseScore = $Data.abuseConfidenceScore
            $UsageType = $Data.usageType
            $IsTor = $Data.isTor
            $AbuseSummary = "Keyakinan Serangan: $($Data.abuseConfidenceScore)% ($($Data.totalReports) laporan)"
        } catch {
            $AbuseSummary = "Ralat semakan AbuseIPDB ($_)"
        }
    }

    # Paparan Terminal
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    Write-Host "  HASIL ANALISIS THREAT INTEL: $ip" -ForegroundColor Yellow
    Write-Host ("=" * 68) -ForegroundColor DarkGray
    if ($GeoData -and $GeoData.status -eq "success") {
        Write-Host "  Negara           : $($GeoData.country)"
        Write-Host "  Bandar           : $($GeoData.city)"
        Write-Host "  ISP              : $($GeoData.isp)"
        Write-Host "  Organisasi       : $($GeoData.org)"
        Write-Host "  ASN              : $($GeoData.as)"
        Write-Host "  Datacenter/Host  : $(if ($GeoData.hosting) { 'YA' } else { 'TIDAK' })"
        Write-Host "  Proxy / VPN      : $(if ($GeoData.proxy) { 'YA' } else { 'TIDAK' })"
        Write-Host "  Jenis Penggunaan : $UsageType"
        if ($IsTor) {
            Write-Host "  🚨 PENGESAHAN TOR: YA (IP adalah nod keluar Tor!)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [-] Maklumat Geolocation tidak dapat diperoleh."
    }
    Write-Host ("-" * 68) -ForegroundColor DarkGray
    Write-Host "  🛡️ VirusTotal v3 : $VtSummary" -ForegroundColor Cyan
    Write-Host "  🚨 AbuseIPDB v2  : $AbuseSummary" -ForegroundColor Magenta
    Write-Host ("-" * 68) -ForegroundColor DarkGray
    Write-Host "  [+] Pautan Siasatan Pantas:"
    Write-Host "      • VirusTotal : https://www.virustotal.com/gui/ip-address/$ip"
    Write-Host "      • AbuseIPDB  : https://www.abuseipdb.com/check/$ip"
    Write-Host "      • Shodan     : https://www.shodan.io/host/$ip"
    Write-Host ("=" * 68 + "`n") -ForegroundColor DarkGray

    $Results += [PSCustomObject]@{
        IP          = $ip
        Country     = $GeoData.country
        City        = $GeoData.city
        ISP         = $GeoData.isp
        Org         = $GeoData.org
        ASN         = $GeoData.as
        IsHosting   = $GeoData.hosting
        IsProxy     = $GeoData.proxy
        IsTor       = $IsTor
        UsageType   = $UsageType
        VirusTotal  = $VtSummary
        VTMalicious = $VtMalicious
        AbuseIPDB   = $AbuseSummary
        AbuseScore  = $AbuseScore
    }
}

if ($Csv) {
    $Results | Export-Csv -Path $Csv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Laporan berjaya dieksport ke fail CSV: $Csv" -ForegroundColor Green
}
