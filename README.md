# SOC Detection: Password Spraying (MITRE ATT&CK T1110.003)

Repository ini dibangunkan khas untuk membantu tugasan harian **Detection Engineer** dan **SOC Analyst** dalam mengesan, menyaring, dan bertindak balas (*incident response*) terhadap serangan **Password Spraying**.

---

## 🎯 Objektif Projek

1. **Detection Engineering:**
   * Menyediakan logik pengesanan standard (**Sigma**) yang boleh dieksport ke pelbagai platform SIEM (Splunk, Microsoft Sentinel, Elastic, QRadar).
   * Membina korelasi antara percubaan gagal (*failed logins*) dengan log masuk yang berjaya (*successful authentication*).
   * Meminimumkan kadar *False Positive* (FP) daripada pengimbas keselamatan dalaman (*vulnerability scanners*) dan servis automatik.

2. **SOC Operational Efficiency:**
   * Membekalkan **Incident Response Playbook** langkah demi langkah untuk analis L1/L2.
   * Menyediakan skrip pembantu (*triage scripts*) untuk menyemak reputasi IP secara pantas tanpa perlu menampal log mentah.
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
│   └── IR_Playbook_Password_Spraying.md   # SOP & Triage Playbook
├── triage-scripts/
│   └── enrich_ip.py      # Skrip pantas pengesanan reputasi IP
└── README.md
```

---

## 🚀 Panduan Penggunaan

1. **Uji Pengesanan:** Rujuk query di dalam direktori `detections/` dan sesuaikan nilai ambang (*threshold*, cth: $\ge 5$ akaun dalam 10 minit) mengikut persekitaran organisasi anda.
2. **Tindakan Alert:** Ikuti panduan di `playbooks/IR_Playbook_Password_Spraying.md` apabila alert dicetuskan.
3. **Automasi Triage:** Jalankan `python triage-scripts/enrich_ip.py <IP>` untuk semakan awal penyerang.
