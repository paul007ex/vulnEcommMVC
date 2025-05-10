Absolutely — here’s a **badass, developer-ready `README.md`** for your `VulnerableECommerceMVC` repo. It explains the purpose, architecture, key features, vulnerabilities, testing, and how to run the lab. I wrote it like a **professional masterclass** for security engineers, devs, and hiring managers alike:

---

````markdown
# 🔥 VulnerableECommerceMVC

A purposely vulnerable ASP.NET Core MVC application designed to simulate insecure legacy e-commerce systems — for red teamers, blue teamers, compliance pros, and AppSec engineers.

> ✅ Realistic | 💥 Intentionally Broken | 🧠 Educational | ⚙️ SSDLC-Ready

---

## 🚀 Project Goals

- Simulate common legacy authentication flaws in .NET-based e-commerce apps
- Contrast insecure vs secure implementations of HTTP Basic Auth
- Map remediation efforts to **NIST SSDF**, **OWASP SAMM**, and **MITRE ATT&CK**
- Serve as a practical **SSDLC demo** with curl-based testing and lab-ready reports

---

## 🧱 Architecture

```ascii
  [Browser / Curl]
         │
         ▼
 ┌────────────────────┐
 │ Insecure Route (/) │ ──► Base64 Creds over HTTP
 └────────────────────┘

 ┌────────────────────────┐
 │ Secure Route (/secure) │ ──► HTTPS + SHA-256 Password Hash
 └────────────────────────┘
````

* **Insecure Auth:** `HomeController.cs` (no HTTPS, plaintext passwords)
* **Secure Auth:** `SecureLoginController.cs` (HTTPS, hashed, role-mapped)
* **Form-based Login:** `LoginController.cs` (CSRF-missing legacy POST)
* **Data Store:** `DataStore.cs` with hardcoded in-memory users + roles

---

## 🛡️ Vulnerabilities Demonstrated

| 🐞 Vulnerability         | Location        | Severity  |
| ------------------------ | --------------- | --------- |
| Plaintext Passwords      | Insecure route  | 🔴 High   |
| No HTTPS Enforcement     | Insecure route  | 🔴 High   |
| No Rate Limiting         | All controllers | 🔴 High   |
| Missing Input Validation | LoginController | 🟠 Medium |
| No CSRF Protection       | LoginController | 🟠 Medium |
| Overly Coupled Logic     | HomeController  | 🟡 Low    |

> 🎯 CVSS scoring & STRIDE modeling included in [SSDLC Report](./REPORT.MD)

---

## 🧪 How to Run Locally

> ⚠️ Don’t deploy this to production. It's designed to be vulnerable.

```bash
# Trust local HTTPS certs
dotnet dev-certs https --trust

# Run insecure + secure endpoints
dotnet run
```

* Open [http://localhost:8080](http://localhost:8080) → Insecure endpoint
* Open [https://localhost:8443](https://localhost:8443) → Secure endpoint

---

## 🧪 Testing via Curl

```bash
# 🔓 Insecure login (HTTP - Base64)
curl -i http://localhost:8080/insecure
curl -i -H "Authorization: Basic $(echo -n 'john:password' | base64)" http://localhost:8080/insecure

# 🔐 Secure login (HTTPS - SHA-256)
curl -k -i https://localhost:8443/secure
curl -k -i -H "Authorization: Basic $(echo -n 'admin:password' | base64)" https://localhost:8443/secure
```

---

## 📊 SSDLC & Compliance Mapping

| Domain                 | Framework Alignment                   |
| ---------------------- | ------------------------------------- |
| Secure Design          | NIST SSDF PW\.1, OWASP SAMM Design    |
| Implementation         | SSDF PW\.3, OWASP SAMM Implementation |
| Verification & Testing | SSDF RV.1, OWASP SAMM Verification    |
| Governance & Oversight | SSDF PO.1, OWASP SAMM Governance      |

See full report: [Comprehensive SSDLC Framework (PDF)](./Comprehensive%20SSDLC%20Framework%20Aligned%20to%20NIST%20SSDF%20&%20OWASP%20SAMM%20.pdf)

---

## 🔄 Roadmap to Production

* [ ] Add rate limiting middleware
* [ ] Replace Basic Auth with ASP.NET `AuthenticationHandler`
* [ ] Integrate Azure Key Vault for secrets
* [ ] Deploy to Azure App Services + Front Door WAF
* [ ] Enable Application Insights for telemetry
* [ ] Run ZAP scanner against `/login` and `/insecure`

---

## 🧠 Who Is This For?

* 🔐 **Security Architects** building SSDLC workflows
* 🧑‍💻 **Developers** learning how not to build authentication
* 📈 **Red & Blue Teams** practicing real-world exploits
* 🧾 **Compliance Pros** mapping technical risk to frameworks

---

## 📁 Project Tree (Simplified)

```
VulnerableECommerceMVC/
├── Controllers/
│   ├── HomeController.cs         # Insecure Basic Auth
│   ├── SecureLoginController.cs  # Secure Basic Auth
│   └── LoginController.cs        # Legacy Form Login
├── Models/
│   ├── User.cs
│   └── DataStore.cs
├── tests.sh                      # Curl-based test script
├── Program.cs                    # Kestrel config (8080/8443)
├── .gitignore
└── REPORT.MD                     # SSDLC Report (Markdown)
```

---

## 👨‍💻 Credits

Built by **Paul Volosen** as part of a secure software lifecycle lab simulating legacy .NET e-commerce risk scenarios.

---

## ⚠️ Disclaimer

This project is intentionally insecure. Use it only in test/lab environments. All vulnerabilities are **by design** for educational purposes.

---

```

---

Would you like me to generate a GitHub-friendly badge block or turn this into a `README.docx` with formatting for sending to stakeholders?
```
