#!/usr/bin/env python3
"""
SOC Log Parser: Password Spraying Detector & Extractor
Tujuan: Memproses log autentikasi (JSON/CSV) dari SIEM atau Windows EVTX,
        mengesan corak serangan password spraying (banyak akaun gagal dari 1 IP),
        serta mengenal pasti jika ada akaun yang telah berjaya ditembusi (Compromised).
Penggunaan:
    python parse_spray_logs.py test-data/sample_spray_events.json
    python parse_spray_logs.py my_logs.json --threshold 3 --output-ips suspicious_ips.txt
"""

import sys
import json
import argparse
from collections import defaultdict
from typing import List, Dict, Any

def normalize_field(record: Dict[str, Any], candidates: List[str]) -> Any:
    for c in candidates:
        if c in record:
            return record[c]
    return None

def analyze_logs(file_path: str, threshold: int, output_ips_file: str = None):
    print(f"[*] Membuka dan membaca fail log: {file_path}")
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[-] Ralat membaca fail JSON: {e}")
        sys.exit(1)

    if isinstance(data, dict):
        # Handle wrap like {"records": [...]} or {"value": [...]}
        for key in ["records", "value", "events"]:
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]

    print(f"[*] Menjumpai {len(data)} rekod acara autentikasi.")

    # Storage for analysis
    # ip -> { "failed_users": set(), "success_users": set(), "events_count": 0, "timestamps": [] }
    ip_stats = defaultdict(lambda: {
        "failed_users": set(),
        "success_users": set(),
        "events_count": 0,
        "timestamps": []
    })

    for entry in data:
        ip = normalize_field(entry, ["IpAddress", "IPAddress", "ip", "SourceIP", "c-ip", "client_ip"])
        user = normalize_field(entry, ["TargetUserName", "UserPrincipalName", "user", "username", "account"])
        event_id = normalize_field(entry, ["EventID", "event_id", "ResultType", "status_code"])
        timestamp = normalize_field(entry, ["Timestamp", "TimeGenerated", "time", "@timestamp"])

        if not ip or ip in ["-", "127.0.0.1", "::1"]:
            continue
        if not user or user.endswith("$"):  # Abaikan akaun komputer tempatan
            continue

        str_event = str(event_id).lower() if event_id is not None else ""
        
        # Pengelasan Berjaya atau Gagal
        # 4624 = Windows Logon Success, 0 = Entra ID Success
        is_success = str_event in ["4624", "0", "success"]
        # 4625 = Windows Bad Password, 4771 = Kerberos Preauth fail, 50126 = Entra ID Bad Password
        is_failure = str_event in ["4625", "4771", "50126", "failure"]

        stats = ip_stats[ip]
        stats["events_count"] += 1
        if timestamp:
            stats["timestamps"].append(timestamp)

        if is_success:
            stats["success_users"].add(user)
        elif is_failure or not is_success:
            stats["failed_users"].add(user)

    # Analisis dan Laporan
    suspicious_ips = []
    print("\n" + "=" * 80)
    print("                    LAPORAN ANALISIS PASSWORD SPRAYING")
    print("=" * 80)
    print(f"{'Source IP':<18} | {'Akaun Gagal':<12} | {'Akaun Berjaya':<14} | {'Status Ancaman':<20}")
    print("-" * 80)

    for ip, stat in ip_stats.items():
        failed_count = len(stat["failed_users"])
        success_count = len(stat["success_users"])

        if failed_count >= threshold:
            suspicious_ips.append(ip)
            if success_count > 0:
                threat_level = "🚨 CRITICAL (COMPROMISED)"
            else:
                threat_level = "⚠️ HIGH (Spray Suspected)"
        elif success_count > 0 and failed_count > 0:
            threat_level = "🟡 MEDIUM (Anomaly)"
        else:
            continue

        print(f"{ip:<18} | {failed_count:<12} | {success_count:<14} | {threat_level:<20}")

    print("=" * 80)

    # Butiran lanjut bagi setiap IP mencurigakan
    if suspicious_ips:
        print("\n[!] PERINCIAN KESELAMATAN BAGI IP MENCURIGAKAN:")
        for ip in suspicious_ips:
            stat = ip_stats[ip]
            print(f"\n[+] IP Sasaran: {ip}")
            print(f"    - Jumlah Acara          : {stat['events_count']}")
            print(f"    - Akaun Gagal Sasaran   : {', '.join(list(stat['failed_users'])[:10])}" + 
                  (" (dan lain-lain...)" if len(stat['failed_users']) > 10 else ""))
            if stat["success_users"]:
                print(f"    - 🚨 AKAUN BERJAYA DITEMBUSI : {', '.join(stat['success_users'])}")
                print(f"      [TINDAKAN SEGERA] Revoke sesi & Reset password bagi akaun di atas!")
            else:
                print(f"    - Akaun Berjaya Ditembusi: TIADA (Serangan gagal menembusi perimeter).")

        if output_ips_file:
            with open(output_ips_file, "w", encoding="utf-8") as out:
                for ip in suspicious_ips:
                    out.write(f"{ip}\n")
            print(f"\n[+] Senarai IP mencurigakan telah diekstrak ke: {output_ips_file}")
            print(f"    Tip: Jalankan `python triage-scripts/enrich_ip.py -f {output_ips_file}` untuk semak reputasi.")
    else:
        print("\n[+] Tiada aktiviti password spraying dikesan melebihi nilai ambang (Threshold).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Log Parser for Password Spraying Detection")
    parser.add_argument("logfile", help="Laluan ke fail log JSON")
    parser.add_argument("--threshold", type=int, default=3, help="Nilai minimum akaun unik gagal (Lalaim: 3)")
    parser.add_argument("--output-ips", help="Fail teks untuk menyimpan senarai IP mencurigakan")

    args = parser.parse_args()
    analyze_logs(args.logfile, args.threshold, args.output_ips)
