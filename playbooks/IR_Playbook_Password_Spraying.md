# Standard Operating Procedure (SOP): Password Spraying Triage & Response Playbook

* **Classification:** Incident Response / SOC Triage Playbook
* **Target Attack:** MITRE ATT&CK T1110.003 (Password Spraying)
* **Target Roles:** SOC Analyst L1, SOC Analyst L2, Incident Responder

---

## 🧭 Flowchart Triage Ringkas

```text
Alert Triggered (Password Spraying)
          │
          ▼
[Step 1: Pengesahan Sumber IP]
  ├─ Adakah IP VPN / Proxy / Vulnerability Scanner Rasmi? ──► [Ya: Mark as False Positive & Tune]
  └─ [Tidak: Sumber Luar / Tidak Dikenali]
          │
          ▼
[Step 2: Semakan Akaun Berjaya (Critical Compromise)]
  ├─ Adakah terdapat Event 4624 / ResultType 0 dari IP ini?
  │       ├─ [Ya] ──► 🚨 SEVERITY CRITICAL: Akaun Telah Ditembusi (Lihat Fasa 4)
  │       └─ [Tidak] ──► ⚠️ SEVERITY HIGH: Percubaan Password Spraying Gagal
          │
          ▼
[Step 3: Tindakan Pembendungan (Containment)]
  ├─ Sekat IP sumber pada Perimeter Firewall / WAF
  └─ Jika ada akaun berjaya: Revoke session tokens & Reset password serta-merta
```

---

## 📋 Langkah-langkah Triage Terperinci

### Fasa 1: Pengesahan & Pengenalpastian Skop (Scoping)
1. **Dapatkan Senarai Penunjuk (IoCs):**
   * Alamat IP Sumber (`SourceIP`)
   * User-Agent / Protokol (cth: Exchange ActiveSync, PowerShell, RDP, Azure Portal)
   * Senarai akaun yang disasarkan (`TargetUserName` / `UserPrincipalName`)
2. **Kategori Sasaran:**
   * Semak sama ada akaun yang disasarkan merangkumi akaun istimewa (Domain Admin, VIP, C-Suite, IT Helpdesk).

---

### Fasa 2: Semakan False Positive (FP Tuning)
Sebelum mengambil tindakan menyekat:
* **Vulnerability Assessment:** Semak jadual *penetration test* atau *vulnerability scanning* dalaman (Qualys, Nessus, Rapid7).
* **Exchange / ActiveSync Glitch:** Kadangkala telefon bimbit pekerja yang menukar kata laluan akan terus mencuba kata laluan lama berulang kali, tetapi biasanya hanya melibatkan **satu** akaun sahaja.

---

### Fasa 3: Penilaian Impak (Compromise Assessment)
* **Korelasi Kejayaan:**
  Lakukan carian pada SIEM untuk IP sumber yang sama:
  * Windows Event ID: `4625` (Gagal) disusuli `4624` (Berjaya)
  * Entra ID: ResultType `50126` disusuli `0`
* **Jika TIADA kejayaan:**
  * Penyerang belum berjaya menembusi akaun. Kategori: **Attempted Attack / Blocked**.
* **Jika ADA kejayaan:**
  * Akaun tersebut telah **COMPROMISED**. Teruskan ke Fasa 4 serta-merta.

---

### Fasa 4: Tindakan Respons & Pembendungan (Containment)

1. **Bagi Percubaan Gagal (Tiada Akaun Ditembusi):**
   * Sekat IP sumber pada Perimeter Firewall / WAF / Cloudflare selama 48–72 jam.
   * Laporkan IP kepada AbuseIPDB jika disahkan berbahaya.

2. **Bagi Akaun yang Berjaya Ditembusi (Compromised):**
   * **Langkah 1:** *Force Password Reset* bagi pengguna terlibat.
   * **Langkah 2:** *Revoke All Active Sessions / Refresh Tokens* (dalam Azure AD: `Revoke-AzureADUserAllRefreshToken`).
   * **Langkah 3:** Semak sama ada MFA diaktifkan untuk akaun tersebut. Jika tiada, wajibkan MFA.
   * **Langkah 4:** Periksa aktiviti pos-eksploitasi (Contoh: pembikinan inbox forwarding rules, muat turun data dari OneDrive, pendaftaran peranti MFA baharu yang tidak dikenali).

---

## ✉️ Templat Komunikasi kepada Pengguna (User Notification Template)

> **Subjek:** [Pemberitahuan Keselamatan IT] Pengesanan Percubaan Log Masuk Luar Biasa ke Akaun Anda
>
> Salam [Nama Pengguna],
>
> Pasukan Keselamatan Siber (SOC) telah mengesan beberapa percubaan log masuk yang mencurigakan ke akaun organisasi anda daripada alamat IP luar negara ([IP_Address]).
>
> Sebagai langkah keselamatan proaktif:
> 1. Sesi log masuk anda telah ditamatkan.
> 2. Sila kemas kini kata laluan anda melalui portal rasmi kami: [Pautan Portal Rasmi].
> 3. Jangan sesekali meluluskan sebarang permintaan notifikasi MFA (Authenticator Prompt) yang tidak dimulakan oleh anda sendiri.
>
> Jika anda mempunyai sebarang soalan, sila hubungi meja bantuan SOC di [Emel/Nombor SOC].
