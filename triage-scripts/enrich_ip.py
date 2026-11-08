#!/usr/bin/env python3
"""
SOC Triage Helper: IP Reputation & Threat Intelligence Enrichment
Tujuan: Membantu analis menyemak Geolocation, ASN, status VPN/Tor/Proxy,
        serta skor reputasi IP penyerang secara pukal (bulk) atau satu persatu.
Penggunaan:
    python enrich_ip.py 203.0.113.45
    python enrich_ip.py 203.0.113.45 198.51.100.10
    python enrich_ip.py -f suspicious_ips.txt --csv report.csv
"""

import sys
import os
import json
import csv
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List

def query_ip_api(ip: str) -> Dict[str, Any]:
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Triage-Tool/2.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query"),
                        "country": data.get("country", "Unknown"),
                        "city": f"{data.get('city', '')}, {data.get('regionName', '')}",
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False),
                        "status": "Success"
                    }
    except Exception as e:
        return {"ip": ip, "status": f"Error: {e}"}
    return {"ip": ip, "status": "Failed to resolve"}

def check_abuseipdb(ip: str, api_key: str) -> str:
    if not api_key:
        return "N/A (Tiada API Key)"
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": "SOC-Triage-Tool/2.0"
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                res = json.loads(resp.read().decode("utf-8"))
                score = res.get("data", {}).get("abuseConfidenceScore", 0)
                reports = res.get("data", {}).get("totalReports", 0)
                return f"{score}% ({reports} laporan)"
    except Exception as e:
        return f"Error ({e})"
    return "N/A"

def print_result_terminal(info: Dict[str, Any], abuse_score: str):
    print("=" * 60)
    print(f"  HASIL ANALISIS IP: {info['ip']}")
    print("=" * 60)
    if info.get("status") != "Success":
        print(f"  [-] Ralat: {info.get('status')}")
    else:
        print(f"  Negara           : {info.get('country')}")
        print(f"  Bandar / Wilayah : {info.get('city')}")
        print(f"  ISP              : {info.get('isp')}")
        print(f"  Organisasi       : {info.get('org')}")
        print(f"  ASN              : {info.get('asn')}")
        print(f"  Datacenter/Host  : {'YA' if info.get('is_hosting') else 'TIDAK'}")
        print(f"  Proxy / VPN      : {'YA' if info.get('is_proxy') else 'TIDAK'}")
        print(f"  Skor AbuseIPDB   : {abuse_score}")
    print("-" * 60)
    print("  [+] Pautan Siasatan Pantas:")
    print(f"      • AbuseIPDB  : https://www.abuseipdb.com/check/{info['ip']}")
    print(f"      • VirusTotal : https://www.virustotal.com/gui/ip-address/{info['ip']}")
    print(f"      • Shodan     : https://www.shodan.io/host/{info['ip']}")
    print("=" * 60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="SOC IP Reputation & Intelligence Enrichment Tool")
    parser.add_argument("ips", nargs="*", help="Alamat IP untuk disemak (satu atau lebih)")
    parser.add_argument("-f", "--file", help="Fail teks yang mengandungi senarai IP (satu per baris)")
    parser.add_argument("--csv", help="Laluan fail CSV untuk eksport hasil laporan")
    args = parser.parse_args()

    targets = []
    if args.ips:
        targets.extend(args.ips)
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        targets.append(clean)
        else:
            print(f"[-] Fail tidak ditemui: {args.file}")
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    abuse_api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    results = []

    print(f"[*] Memulakan semakan reputasi untuk {len(targets)} alamat IP...\n")
    for ip in targets:
        info = query_ip_api(ip)
        abuse_score = check_abuseipdb(ip, abuse_api_key)
        info["abuse_score"] = abuse_score
        results.append(info)
        print_result_terminal(info, abuse_score)

    if args.csv:
        fieldnames = ["ip", "country", "city", "isp", "org", "asn", "is_hosting", "is_proxy", "abuse_score", "status"]
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"[+] Laporan berjaya dieksport ke CSV: {args.csv}")

if __name__ == "__main__":
    main()
