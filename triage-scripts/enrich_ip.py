#!/usr/bin/env python3
"""
Triage Helper: IP Reputation & ASN Lookup
Tujuan: Membantu SOC Analyst membuat semakan pantas reputasi IP penyerang 
        tanpa perlu membuka pelbagai tab pelayar atau membazir token LLM.
Penggunaan:
    python enrich_ip.py 192.0.2.1
"""

import sys
import json
import urllib.request
import urllib.error

def check_ip_info(ip: str):
    print(f"[*] Menyemak maklumat IP: {ip} ...\n")
    
    # 1. Semakan Geolocation & ASN percuma via ip-api.com
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SOC-Triage-Tool/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                if data.get("status") == "success":
                    print("=" * 45)
                    print("  HASIL SEMAKAN REPUTASI & GEOLOKASI")
                    print("=" * 45)
                    print(f"  IP Address : {data.get('query')}")
                    print(f"  Negara     : {data.get('country')}")
                    print(f"  Bandar     : {data.get('city')}, {data.get('regionName')}")
                    print(f"  ISP        : {data.get('isp')}")
                    print(f"  Organisasi : {data.get('org')}")
                    print(f"  ASN        : {data.get('as')}")
                    print("=" * 45)
                else:
                    print(f"[-] Ralat penyedia maklumat: {data.get('message')}")
    except urllib.error.URLError as e:
        print(f"[-] Gagal menyambung ke servis semakan: {e}")

    # 2. Pautan Pantas untuk Analis (Manual Quick-Links)
    print("\n[+] Pautan Siasatan Pantas untuk Analis:")
    print(f"  - AbuseIPDB   : https://www.abuseipdb.com/check/{ip}")
    print(f"  - VirusTotal  : https://www.virustotal.com/gui/ip-address/{ip}")
    print(f"  - Shodan      : https://www.shodan.io/host/{ip}")
    print(f"  - Cisco Talos : https://talosintelligence.com/reputation_center/lookup?search={ip}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Penggunaan: python enrich_ip.py <ALAMAT_IP>")
        sys.exit(1)
    
    target_ip = sys.argv[1].strip()
    check_ip_info(target_ip)
