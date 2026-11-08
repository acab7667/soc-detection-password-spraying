#!/usr/bin/env python3
"""
SOC Triage Helper: IP Reputation & Threat Intelligence Enrichment (v3.1)
Tujuan: Membantu analis menyemak Geolocation, ASN, status VPN/Tor/Proxy,
        AbuseIPDB API v2, serta VirusTotal API v3 secara automatik (single atau bulk).
Penggunaan:
    python enrich_ip.py 203.0.113.45 --vt-key <VT_KEY> --abuse-key <ABUSE_KEY>
    python enrich_ip.py -f suspicious_ips.txt --csv report.csv
"""

import sys
import os
import json
import csv
import time
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, List

def query_ip_api(ip: str) -> Dict[str, Any]:
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Triage-Tool/3.1'})
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

def check_virustotal(ip: str, api_key: str) -> Dict[str, Any]:
    """Semakan reputasi IP menggunakan VirusTotal API v3."""
    if not api_key:
        return {"result": "N/A (Tiada API Key)", "malicious": 0, "suspicious": 0, "reputation": 0}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key.strip(),
        "Accept": "application/json",
        "User-Agent": "SOC-Triage-Tool/3.1"
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected
                reputation = attributes.get("reputation", 0)

                summary = f"{malicious}/{total} vendor flag bahaya (Skor Reputasi: {reputation})"
                return {
                    "result": summary,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "reputation": reputation
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"result": "IP tiada rekod dalam VT", "malicious": 0, "suspicious": 0, "reputation": 0}
        elif e.code == 401:
            return {"result": "Ralat API Key (Unauthorized)", "malicious": 0, "suspicious": 0, "reputation": 0}
        elif e.code == 429:
            return {"result": "Ralat Had Kuota (Rate Limit: 4 req/min)", "malicious": 0, "suspicious": 0, "reputation": 0}
        return {"result": f"HTTP {e.code}", "malicious": 0, "suspicious": 0, "reputation": 0}
    except Exception as e:
        return {"result": f"Ralat ({e})", "malicious": 0, "suspicious": 0, "reputation": 0}

    return {"result": "Tiada maklumat", "malicious": 0, "suspicious": 0, "reputation": 0}

def check_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """Semakan terperinci reputasi IP menggunakan AbuseIPDB API v2."""
    if not api_key:
        return {
            "result": "N/A (Tiada API Key)",
            "score": 0,
            "reports": 0,
            "usage_type": "N/A",
            "is_tor": False
        }

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    headers = {
        "Key": api_key.strip(),
        "Accept": "application/json",
        "User-Agent": "SOC-Triage-Tool/3.1"
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                res = json.loads(resp.read().decode("utf-8"))
                data = res.get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                users = data.get("numDistinctUsers", 0)
                usage_type = data.get("usageType", "Unknown")
                is_tor = data.get("isTor", False)
                last_rep = data.get("lastReportedAt", "N/A")

                summary = f"Keyakinan Serangan: {score}% ({reports} laporan dari {users} pengadu)"
                return {
                    "result": summary,
                    "score": score,
                    "reports": reports,
                    "usage_type": usage_type,
                    "is_tor": is_tor,
                    "last_reported": last_rep
                }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"result": "Ralat API Key AbuseIPDB (Unauthorized)", "score": 0, "reports": 0, "usage_type": "N/A", "is_tor": False}
        elif e.code == 429:
            return {"result": "Ralat Had Kuota AbuseIPDB (Rate Limit)", "score": 0, "reports": 0, "usage_type": "N/A", "is_tor": False}
        return {"result": f"HTTP {e.code}", "score": 0, "reports": 0, "usage_type": "N/A", "is_tor": False}
    except Exception as e:
        return {"result": f"Ralat ({e})", "score": 0, "reports": 0, "usage_type": "N/A", "is_tor": False}

    return {"result": "Tiada maklumat", "score": 0, "reports": 0, "usage_type": "N/A", "is_tor": False}

def print_result_terminal(info: Dict[str, Any], vt_info: Dict[str, Any], abuse_info: Dict[str, Any]):
    print("=" * 68)
    print(f"  HASIL ANALISIS IP: {info['ip']}")
    print("=" * 68)
    if info.get("status") != "Success":
        print(f"  [-] Ralat Rangkaian: {info.get('status')}")
    else:
        print(f"  Negara           : {info.get('country')}")
        print(f"  Bandar / Wilayah : {info.get('city')}")
        print(f"  ISP              : {info.get('isp')}")
        print(f"  Organisasi       : {info.get('org')}")
        print(f"  ASN              : {info.get('asn')}")
        print(f"  Datacenter/Host  : {'YA' if info.get('is_hosting') else 'TIDAK'}")
        print(f"  Proxy / VPN      : {'YA' if info.get('is_proxy') else 'TIDAK'}")
        if abuse_info.get("usage_type") != "N/A":
            print(f"  Jenis Penggunaan : {abuse_info.get('usage_type')}")
        if abuse_info.get("is_tor"):
            print(f"  🚨 PENGESAHAN TOR: YA (IP adalah nod keluar Tor!)")
    
    # OSINT Threat Intel
    print("-" * 68)
    print(f"  🛡️ VirusTotal v3 : {vt_info.get('result')}")
    print(f"  🚨 AbuseIPDB v2  : {abuse_info.get('result')}")
    print("-" * 68)
    print("  [+] Pautan Siasatan Pantas:")
    print(f"      • VirusTotal : https://www.virustotal.com/gui/ip-address/{info['ip']}")
    print(f"      • AbuseIPDB  : https://www.abuseipdb.com/check/{info['ip']}")
    print(f"      • Shodan     : https://www.shodan.io/host/{info['ip']}")
    print("=" * 68 + "\n")

def main():
    parser = argparse.ArgumentParser(description="SOC IP Reputation & Threat Intelligence Enrichment Tool")
    parser.add_argument("ips", nargs="*", help="Alamat IP untuk disemak (satu atau lebih)")
    parser.add_argument("-f", "--file", help="Fail teks yang mengandungi senarai IP (satu per baris)")
    parser.add_argument("--vt-key", help="API Key untuk VirusTotal (atau tetapkan env VT_API_KEY)")
    parser.add_argument("--abuse-key", help="API Key untuk AbuseIPDB (atau tetapkan env ABUSEIPDB_API_KEY)")
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

    vt_key = args.vt_key or os.environ.get("VT_API_KEY", "")
    abuse_key = args.abuse_key or os.environ.get("ABUSEIPDB_API_KEY", "")

    results = []
    print(f"[*] Memulakan semakan reputasi untuk {len(targets)} alamat IP...\n")
    if vt_key:
        print("[+] Integrasi VirusTotal v3: AKTIF")
    if abuse_key:
        print("[+] Integrasi AbuseIPDB v2: AKTIF")
    print()

    for idx, ip in enumerate(targets):
        info = query_ip_api(ip)
        vt_info = check_virustotal(ip, vt_key)
        abuse_info = check_abuseipdb(ip, abuse_key)

        info["virustotal"] = vt_info.get("result")
        info["vt_malicious"] = vt_info.get("malicious", 0)
        info["abuseipdb"] = abuse_info.get("result")
        info["abuse_score"] = abuse_info.get("score", 0)
        info["abuse_reports"] = abuse_info.get("reports", 0)
        info["is_tor"] = abuse_info.get("is_tor", False)
        info["usage_type"] = abuse_info.get("usage_type", "")
        results.append(info)

        print_result_terminal(info, vt_info, abuse_info)

        # Rate limiting sleep for VirusTotal Free API (4 requests/minute) jika lebih dari 1 IP
        if vt_key and idx < len(targets) - 1:
            time.sleep(15)

    if args.csv:
        fieldnames = [
            "ip", "country", "city", "isp", "org", "asn", "is_hosting", 
            "is_proxy", "is_tor", "usage_type", "virustotal", "vt_malicious", 
            "abuseipdb", "abuse_score", "abuse_reports", "status"
        ]
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"[+] Laporan berjaya dieksport ke CSV: {args.csv}")

if __name__ == "__main__":
    main()
