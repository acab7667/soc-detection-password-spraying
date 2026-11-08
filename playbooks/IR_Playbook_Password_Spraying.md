# 🛡️ Enterprise Incident Response Playbook: Password Spraying (MITRE ATT&CK T1110.003)

* **Versi:** 2.0 (SOC Production Ready)
* **Klasifikasi:** Standard Operating Procedure (SOP) & IR Playbook
* **Sasaran Peranan:** SOC Analyst L1, SOC Analyst L2, Incident Response Lead
* **Skop Ancaman:** Active Directory Domain Services (On-Prem), Microsoft Entra ID (Azure AD), Okta, VPN Gateway, & Reverse Proxy

---

## 1. 🧭 Ringkasan Eksekutif & Carta Alir Triage (5-Minute Fast Track)

```text
[ SIEM / EDR Alert: Password Spraying Triggered ]
                        │
                        ▼
            [ LANGKAH 1: IDENTIFIKASI ]
    • Kumpul: Source IP, Targeted Users, Protokol, User-Agent
    • Semak sama ada IP adalah Internal Scanner / VPN Gateways
          │
          ├─► [FAKTA: Internal / Authorized] ──► [FP: Dokumentasi & Tune SIEM]
          │
          ▼
      [ LANGKAH 2: PENENTUAN SEVERITI ]
    • Adakah terdapat Log Masuk BERJAYA (Event 4624 / ResultType 0)?
          │
          ├─► [YA: AKAUN DITEMBUSI] ──────────► 🚨 SEVERITY: CRITICAL
          │                                      (Jalankan Protokol Pembendungan Penuh)
          │
          └─► [TIDAK: HANYA PERCUBAAN GAGAL] ──► ⚠️ SEVERITY: HIGH / MEDIUM
                                                 (Sekat IP & Pantau Akaun Sasaran)
```

---

## 2. 🎯 Matriks Penentuan Tahap Keterukan (Severity Matrix)

| Tahap Keterukan | Syarat Pengesanan | SLA Respons (L1/L2) | Tindakan Segera |
| :--- | :--- | :--- | :--- |
| 🔴 **CRITICAL** | Terdapat sekurang-kurangnya **1 log masuk berjaya** (Event 4624 / ResultType 0) dari IP penyerang ATAU melibatkan akaun Domain Admin / VIP. | **< 15 Minit** | Sekat IP, tamatkan sesi aktif (*Revoke tokens*), reset kata laluan, dan mulakan siasatan forensik (*post-compromise*). |
| 🟠 **HIGH** | Serangan berskala besar ($\ge 20$ akaun unik) dari IP luaran yang tidak dikenali, tetapi **tiada** log masuk berjaya. | **< 30 Minit** | Sekat IP pada Firewall/WAF perimeter, semak dasar *account lockout*, laporkan IP penyerang. |
| 🟡 **MEDIUM** | Serangan berskala kecil (5–19 akaun) dan disekat oleh dasar *Conditional Access* atau geoblocking. | **< 1 Jam** | Tambah IP ke senarai pemantauan (*watchlist*), semak pendedahan kelayakan di Threat Intel. |
| 🟢 **LOW / INFO** | Percubaan log masuk gagal yang tersebar atau disahkan daripada pengimbas kelemahan (*internal scanner*). | **< 4 Jam** | Sahkan dengan pasukan IT/Penetration Testing, tutup tiket sebagai FP berjadual. |

---

## 3. 🔍 Prosedur Siasatan Terperinci Langkah Demi Langkah

### Langkah 3.1: Pengesahan & Pengumpulan Bukti Awal (Scoping)
1. **Dapatkan Senarai Penunjuk (IoCs):**
   * **Source IP:** Semak pembekal hosting (cth: DigitalOcean, AWS, Tor Exit Node, Residential Proxy).
   * **User-Agent:** Cari corak mencurigakan (cth: `BAV2ROPC`, PowerShell `curl`, Python `requests`, atau User-Agent lapuk).
   * **Protokol:** Tentukan laluan serangan (Kerberos port 88, NTLM RPC, O365 ROPC, Exchange ActiveSync).
2. **Semak Profil Akaun yang Disasarkan:**
   * Adakah nama akaun tersusun mengikut turutan abjad (cth: `a.ali`, `a.abu`, `b.badrul` — petanda *dictionary attack*)?
   * Adakah terdapat akaun perkhidmatan (*service accounts*) atau akaun pentadbir (*admin*)?

### Langkah 3.2: Penyingkiran False Positive (FP Verification)
Sebelum membuat sekatan drastik:
* Semak jadual ujian penembusan (*penetration test*) syarikat.
* Semak sama ada IP dimiliki oleh *mail gateway* dalaman atau integrasi pihak ketiga (cth: Salesforce, ServiceNow).
* *ActiveSync Loop:* Kadangkala telefon pintar pekerja yang menukar kata laluan akan menghantar ratusan request dengan kata laluan lama. **Perbezaan:** ActiveSync glitch hanya menyasarkan **1 akaun**, manakala Password Spray menyasarkan **banyak akaun berbeza**.

### Langkah 3.3: Semakan Integriti Akaun (Compromise Verification)
Jalankan query korelasi pada SIEM:
```kql
// Semakan log masuk berjaya sejurus selepas siri kegagalan dari IP yang sama
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where ResultType == "0" // 0 = Logon Success
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
```
* **Jika TIADA rekod berjaya:** Teruskan ke Fasa Pembendungan Biasa (Sekat IP).
* **Jika ADA rekod berjaya:** Akaun tersebut **SAH DITEMBUSI (*COMPROMISED*)**. Ikuti Langkah 4.2 serta-merta!

---

## 4. 🛑 Prosedur Pembendungan & Pemulihan (Containment & Eradication)

### 4.1 Pembendungan Perimeter (Rangkaian / Firewall)
1. Masukkan IP sumber ke dalam blok *Drop/Deny* pada Perimeter Firewall (Palo Alto, Fortinet, Checkpoint) atau Cloudflare WAF selama **72 jam minimum**.
2. Jika serangan menggunakan rangkaian proksi berputar (*rotating residential proxies*), pertimbangkan sekatan sementara berasaskan negara (*Geo-IP Block*) atau sekatan bersyarat MFA wajib.

### 4.2 Pembendungan Akaun yang Telah Ditembusi (Compromised Account Actions)

#### A. Tindakan pada Microsoft Entra ID / Office 365 (PowerShell):
```powershell
# 1. Sambung ke Microsoft Graph PowerShell
Connect-MgGraph -Scopes "User.ReadWrite.All"

# 2. Batalkan semua sesi token aktif serta-merta (Kick attacker out)
Revoke-MgUserSignInSession -UserId "mangsa@domainanda.com"

# 3. Kunci/Nyahaktifkan akaun sementara waktu (jika perlu)
Update-MgUser -UserId "mangsa@domainanda.com" -AccountEnabled $false

# 4. Semak sama ada penyerang telah mendaftarkan peranti MFA baharu
Get-MgUserAuthenticationMethod -UserId "mangsa@domainanda.com"
```

#### B. Tindakan pada Active Directory Tempatan (On-Premises AD):
```powershell
# 1. Nyahaktifkan akaun
Disable-ADAccount -Identity "nama_pengguna"

# 2. Paksa tukar kata laluan pada log masuk seterusnya
Set-ADUser -Identity "nama_pengguna" -ChangePasswordAtLogon $true

# 3. Kosongkan tiket Kerberos yang aktif di Domain Controller
# (Jalankan klist purge pada workstation mangsa jika ada akses EDR)
```

### 4.3 Siasatan Forensik Pos-Pencerobohan (Post-Exploitation Forensics)
Selepas pembendungan, lakukan semakan berikut pada akaun mangsa:
1. **Inbox Forwarding Rules:** Semak sama ada penyerang membuat rule untuk memajukan emel syarikat ke emel luaran:
   ```powershell
   Get-InboxRule -Mailbox "mangsa@domainanda.com" | Select-Object Name, ForwardTo, RedirectTo
   ```
2. **OAuth App Consents:** Semak sama ada penyerang meluluskan akses aplikasi pihak ketiga berniat jahat (*illegitimate enterprise apps*).
3. **Audit Log:** Periksa fail yang dimuat turun dari SharePoint/OneDrive dalam tempoh 2 jam selepas log masuk berjaya.

---

## 5. 📝 Templat Dokumentasi & Komunikasi SOC

### Templat Tiket Penyelesaian (ServiceNow / Jira Service Desk)
```text
[INCIDENT CLOSURE SUMMARY: PASSWORD SPRAYING]
- Incident ID         : INC-20261108-XXXX
- Threat Classification: MITRE ATT&CK T1110.003 (Password Spraying)
- Attacker Source IP   : [IP_PENYERANG] (ISP / Negara: [ISP_NEGARA])
- Targeted Accounts    : [Bilangan] akaun (cth: user1, user2, user3)
- Successful Logins    : TIADA / 1 Akaun ([user_terjejas])
- Containment Actions  :
  [x] IP disekat pada Firewall Perimeter (Ticket FW-XXXX)
  [x] Akaun mangsa dibatalkan sesi token (Revoke-MgUserSignInSession)
  [x] Kata laluan akaun telah direset
  [x] Semakan peti masuk mengesahkan TIADA forward rule berniat jahat
- Status               : CLOSED (Mitigated)
- Root Cause / Rec.    : Laksanakan dasar MFA wajib dan sekat protokol autentikasi warisan (Legacy Auth).
```

### Templat Emel kepada Pengguna Terjejas
```text
Subjek: [PENTING] Tindakan Keselamatan: Penetapan Semula Kata Laluan Akaun Anda

Salam [Nama Pengguna],

Pasukan Keselamatan Siber (SOC) telah mengesan percubaan akses yang tidak dibenarkan terhadap akaun anda daripada lokasi [Negara/IP].

Demi menjaga keselamatan data syarikat dan akaun anda:
1. Sesi log masuk anda telah ditamatkan secara automatik.
2. Kata laluan anda perlu ditetapkan semula melalui portal rasmi kami: https://passwordreset.domainanda.com
3. Sila pastikan anda TIDAK meluluskan sebarang notifikasi pengesahan MFA (Authenticator prompt) pada telefon anda yang bukan dimulakan oleh anda.

Jika anda memerlukan bantuan, sila hubungi meja bantuan SOC di sambungan talian [Nombor Telefon] atau emel soc@domainanda.com.

Sekian, terima kasih.
Pasukan Keselamatan Maklumat (SOC)
```
