# SOC Detection: Password Spraying (MITRE ATT&CK T1110.003)

Repository ini dibangunkan khas untuk menyokong operasi harian **Detection Engineer** dan **SOC Analyst** dalam mengesan, menyaring, dan bertindak balas (*incident response*) terhadap serangan **Password Spraying**.

Projek ini serasi sepenuhnya secara *native* dengan ekosistem **Microsoft Azure (Entra ID)**, **Microsoft Sentinel**, dan **Microsoft Defender XDR (Advanced Hunting)** serta menyediakan skrip dwibahasa (**Python & PowerShell**) untuk fleksibiliti analis di persekitaran Windows mahupun Linux.

---

## 🎯 Objektif Projek

1. **Detection Engineering:**
   * Menyediakan logik pengesanan standard (**Sigma**) dan query **KQL** khusus untuk **Microsoft Sentinel** serta **Microsoft Defender XDR (Advanced Hunting)**.
   * Membina korelasi antara percubaan gagal (*failed logins*) dengan log masuk yang berjaya (*successful authentication*).
   * Meminimumkan kadar *False Positive* (FP) daripada pengimbas keselamatan dalaman (*vulnerability scanners*) dan servis automatik.

2. **SOC Operational Efficiency:**
   * Membekalkan **Incident Response Playbook (v2.0)** bertaraf perusahaan untuk analis L1/L2 merangkumi kriteria *Severity*, perintah pembendungan (*containment*), dan templat emel.
   * Menyediakan skrip pembantu (*triage scripts*) dalam **Python** dan **PowerShell Native** untuk memproses log dan menyemak reputasi IP penyerang secara automatik menggunakan **VirusTotal API v3**, **AbuseIPDB API v2**, dan **ip-api**.
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
│   ├── parse_spray_logs.py   # Log parser (Python)
│   ├── parse_spray_logs.ps1  # Log parser (PowerShell Native)
│   ├── enrich_ip.py          # Threat Intel Enrichment (Python)
│   └── enrich_ip.ps1         # Threat Intel Enrichment (PowerShell Native)
├── test-data/
│   ├── sample_spray_events.json  # Data ujian Windows Event Log
│   └── simulation_scenario.json  # Data simulasi senario pencerobohan sebenar
└── README.md
```

---

## 🚀 Panduan Pantas Menjalankan Simulasi (Hands-On Simulation)

Anda boleh menjalankan simulasi penuh pengesanan menggunakan **PowerShell** (tiada pemasangan pakej tambahan diperlukan):

```powershell
# Langkah 1: Analisis log simulasi & ekstrak IP suspek
.\triage-scripts\parse_spray_logs.ps1 -LogFile ".\test-data\simulation_scenario.json" -OutputIps "suspicious_ips.txt"

# Langkah 2: Semak reputasi IP suspek menggunakan Threat Intelligence (VirusTotal & AbuseIPDB)
.\triage-scripts\enrich_ip.ps1 -File "suspicious_ips.txt" -Csv "laporan_simulasi_soc.csv"
```
*(Bagi pengguna persekitaran Linux/macOS, perintah yang sama boleh dijalankan menggunakan `python triage-scripts/parse_spray_logs.py` dan `python triage-scripts/enrich_ip.py`).*
