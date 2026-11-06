# SOC Detection Engineering: Password Spraying

Projek ini membina dan menguji aturan pengesanan ancaman (*Detection Rules*) khusus untuk mengenal pasti serangan **Password Spraying (MITRE ATT&CK: T1110.003)**. Projek ini mengamalkan prinsip *Detection-as-Code*, di mana aturan keselamatan diurus, diuji, dan disahkan melalui saluran CI/CD GitHub.

## 📂 Struktur Repositori

```text
soc-detection-password-spraying/
├── .github/
│   └── workflows/
│       └── validate_rules.yml    # Pipeline CI/CD untuk pengesahan sintaks & aturan
├── rules/
│   ├── yaral/                    # Aturan YARA-L (Google SecOps / Chronicle)
│   └── sigma/                    # Aturan Sigma (Generik / SIEM agnostic)
├── telemetry/
│   ├── attack_samples/           # Sampel log simulasi serangan (JSON)
│   └── baseline_samples/         # Sampel log trafik normal (benign)
├── scripts/
│   └── generate_telemetry.py     # Skrip Python untuk menjana data log simulasi
└── README.md
