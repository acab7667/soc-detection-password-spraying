# SOC Detection: Password Spraying (MITRE ATT&CK T1110.003)

Repository ini dibangunkan khas untuk menyokong operasi harian **Detection Engineer** dan **SOC Analyst** dalam mengesan, menyaring, dan bertindak balas (*incident response*) terhadap serangan **Password Spraying**.

---

## 🎯 Objektif Projek

1. **Detection Engineering:**
   * Menyediakan logik pengesanan standard (**Sigma**) yang boleh dieksport ke pelbagai platform SIEM (Splunk, Microsoft Sentinel, Elastic, QRadar).
   * Membina korelasi antara percubaan gagal (*failed logins*) dengan log masuk yang berjaya (*successful authentication*).
   * Meminimumkan kadar *False Positive* (FP) daripada pengimbas keselamatan dalaman (*vulnerability scanners*) dan servis automatik.

2. **SOC Operational Efficiency:**
   * Membekalkan **Incident Response Playbook (v2.0)** bertaraf perusahaan untuk analis L1/L2 merangkumi kriteria *Severity*, perintah pembendungan (*containment*), dan templat emel.
   * Menyediakan skrip pembantu (*triage scripts*) untuk memproses log dan menyemak reputasi IP penyerang secara automatik menggunakan **VirusTotal API v3**, **AbuseIPDB**, dan **ip-api**.
   * Mempercepatkan *Mean Time to Detect (MTTD)* dan *Mean Time to Respond (MTTR)*.

---

## 🗺️ Pemetaan MITRE ATT&CK

* **Tactic:** Credential Access (`TA0006`)
* **Technique:** Brute Force (`T1110`)
* **Sub-technique:** Password Spraying (`T1110.003`)
* **Log Sources:**
  * Windows Event Logs (Event ID `4625` - Status `0xC000006A`, Event ID `4771` - Failure Code `0x18`)
  * Microsoft Entra ID / Azure AD (`SigninLogs` - Error Code `50126`)
  * VPN / Reverse Proxy / SSO Logs

---

## 📁 Struktur Projek

```text
soc-detection-password-spraying/
├── detections/
│   ├── sigma/            # Rule universal Sigma
│   │   └── win_password_spray_kerberos_ntlm.yml
│   └── kql/              # Query Microsoft Sentinel
│       └── entra_id_password_spray.kql
├── playbooks/
│   └── IR_Playbook_Password_Spraying.md   # SOP & Triage Playbook (L1/L2)
├── triage-scripts/
│   ├── parse_spray_logs.py # Pengesan corak password spray & pengekstrakan IP
│   └── enrich_ip.py        # Semakan automatik Geolocation, ASN, VirusTotal v3 & AbuseIPDB
├── test-data/
│   └── sample_spray_events.json # Data ujian simulasi log serangan
└── README.md
```

---

## 🚀 Panduan Penggunaan Harian untuk SOC Analyst

### 1. Ekstrak & Kesan Corak Serangan dari Log:
```bash
python triage-scripts/parse_spray_logs.py test-data/sample_spray_events.json --output-ips suspicious_ips.txt
```
Skrip ini akan memaparkan jadual ringkasan impak, akaun sasaran, dan menandakan akaun yang berjaya ditembusi (*Compromised*).

### 2. Semak Reputasi IP Menggunakan VirusTotal v3 & OSINT:
```bash
# Menggunakan hujah baris perintah (--vt-key):
python triage-scripts/enrich_ip.py -f suspicious_ips.txt --vt-key <VIRUSTOTAL_API_KEY> --csv laporan_triage.csv

# ATAU tetapkan sebagai pembolehubah persekitaran (Environment Variable):
export VT_API_KEY="kunci_api_virustotal_anda"
python triage-scripts/enrich_ip.py -f suspicious_ips.txt --csv laporan_triage.csv
```

### 3. Jalankan Tindakan Pembendungan mengikut Playbook:
Buka [**`playbooks/IR_Playbook_Password_Spraying.md`**](playbooks/IR_Playbook_Password_Spraying.md) untuk langkah pembendungan akaun Active Directory / Entra ID dan templat komunikasi insiden.
