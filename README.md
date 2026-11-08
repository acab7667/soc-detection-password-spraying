# SOC Detection: Password Spraying (MITRE ATT&CK T1110.003)

Repository ini dibangunkan khas untuk menyokong operasi harian **Detection Engineer** dan **SOC Analyst** dalam mengesan, menyaring, dan bertindak balas (*incident response*) terhadap serangan **Password Spraying**.

Projek ini serasi sepenuhnya secara *native* dengan ekosistem **Microsoft Azure (Entra ID)**, **Microsoft Sentinel**, dan **Microsoft Defender XDR (Advanced Hunting)**.

---

## 🎯 Objektif Projek

1. **Detection Engineering:**
   * Menyediakan logik pengesanan standard (**Sigma**) dan query **KQL** khusus untuk **Microsoft Sentinel** serta **Microsoft Defender XDR (Advanced Hunting)**.
   * Membina korelasi antara percubaan gagal (*failed logins*) dengan log masuk yang berjaya (*successful authentication*).
   * Meminimumkan kadar *False Positive* (FP) daripada pengimbas keselamatan dalaman (*vulnerability scanners*) dan servis automatik.

2. **SOC Operational Efficiency:**
   * Membekalkan **Incident Response Playbook (v2.0)** bertaraf perusahaan untuk analis L1/L2 merangkumi kriteria *Severity*, perintah pembendungan (*containment*), dan templat emel.
   * Menyediakan skrip pembantu (*triage scripts*) untuk memproses log dan menyemak reputasi IP penyerang secara automatik menggunakan **VirusTotal API v3**, **AbuseIPDB API v2**, dan **ip-api**.
   * Mempercepatkan *Mean Time to Detect (MTTD)* dan *Mean Time to Respond (MTTR)*.

---

## 🗺️ Pemetaan MITRE ATT&CK & Sumber Log Microsoft

* **Tactic:** Credential Access (`TA0006`)
* **Technique:** Brute Force (`T1110`)
* **Sub-technique:** Password Spraying (`T1110.003`)
* **Log Sources:**
  * **Microsoft Defender XDR:** Jadual `IdentityLogonEvents` (Advanced Hunting)
  * **Microsoft Sentinel / Azure Log Analytics:** Jadual `SigninLogs` (Error `50126` & Success `0`)
  * **Windows Event Logs:** Event ID `4625` (Status `0xC000006A`), Event ID `4771` (Failure Code `0x18`), Event ID `4624` (Success)
  * **VPN / SSO Logs:** Okta, PingFederate, GlobalProtect

---

## 📁 Struktur Projek

```text
soc-detection-password-spraying/
├── detections/
│   ├── sigma/            # Rule universal Sigma
│   │   └── win_password_spray_kerberos_ntlm.yml
│   └── kql/              # Query Microsoft Sentinel & Defender XDR
│       ├── entra_id_password_spray.kql           # Microsoft Sentinel (SigninLogs)
│       └── defender_advanced_hunting_spray.kql   # Microsoft Defender XDR (IdentityLogonEvents)
├── playbooks/
│   └── IR_Playbook_Password_Spraying.md   # SOP & Triage Playbook (L1/L2)
├── triage-scripts/
│   ├── parse_spray_logs.py # Pengesan corak password spray & pengekstrakan IP
│   └── enrich_ip.py        # Semakan automatik Geolocation, ASN, VirusTotal v3 & AbuseIPDB v2
├── test-data/
│   └── sample_spray_events.json # Data ujian simulasi log serangan
└── README.md
```

---

## 🛡️ Penggunaan Query KQL dalam Ekosistem Microsoft

### A. Microsoft Defender XDR (Advanced Hunting)
1. Buka portal [Microsoft Defender](https://security.microsoft.com).
2. Pergi ke **Hunting ➡️ Advanced Hunting**.
3. Salin kandungan fail [`detections/kql/defender_advanced_hunting_spray.kql`](detections/kql/defender_advanced_hunting_spray.kql) dan klik **Run query**.
4. Query ini menggunakan jadual `IdentityLogonEvents` untuk memantau cubaan semburan kata laluan merentasi On-Prem Active Directory dan Cloud Identities serentak.

### B. Microsoft Sentinel / Azure Log Analytics
1. Buka portal Azure ➡️ **Microsoft Sentinel ➡️ Logs**.
2. Buka fail [`detections/kql/entra_id_password_spray.kql`](detections/kql/entra_id_password_spray.kql) untuk menganalisis jadual `SigninLogs`.

---

## 🚀 Panduan Penggunaan Harian untuk SOC Analyst

### 1. Ekstrak & Kesan Corak Serangan dari Log:
```bash
python triage-scripts/parse_spray_logs.py test-data/sample_spray_events.json --output-ips suspicious_ips.txt
```
Skrip ini akan memaparkan jadual ringkasan impak, akaun sasaran, dan menandakan akaun yang berjaya ditembusi (*Compromised*).

### 2. Semak Reputasi IP Menggunakan VirusTotal v3 & AbuseIPDB:
```bash
# Menggunakan hujah baris perintah (--vt-key & --abuse-key):
python triage-scripts/enrich_ip.py -f suspicious_ips.txt --vt-key <VT_KEY> --abuse-key <ABUSE_KEY> --csv laporan_triage.csv

# ATAU tetapkan sebagai pembolehubah persekitaran (Environment Variable):
export VT_API_KEY="kunci_api_virustotal"
export ABUSEIPDB_API_KEY="kunci_api_abuseipdb"
python triage-scripts/enrich_ip.py -f suspicious_ips.txt --csv laporan_triage.csv
```

### 3. Jalankan Tindakan Pembendungan mengikut Playbook:
Buka [**`playbooks/IR_Playbook_Password_Spraying.md`**](playbooks/IR_Playbook_Password_Spraying.md) untuk langkah pembendungan akaun Active Directory / Entra ID dan templat komunikasi insiden.
