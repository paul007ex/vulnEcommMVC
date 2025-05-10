
````markdown
# 🛠️ VulnerableECommerceMVC

> ⚠️ A purposely vulnerable .NET 7.0 e-commerce web app simulating real-world authentication misconfigurations, designed for secure SDLC training, compliance workshops, and red/blue team testing.

[![NIST SSDF Aligned](https://img.shields.io/badge/NIST-SSDF-blue)](https://csrc.nist.gov/publications/detail/white-paper/2022/02/04/secure-software-development-framework-ssdf/final)
[![OWASP SAMM](https://img.shields.io/badge/OWASP-SAMM-orange)](https://owaspsamm.org/model/)
[![Built with .NET 7](https://img.shields.io/badge/.NET-7.0-purple)](https://dotnet.microsoft.com/en-us/download/dotnet/7.0)
[![Vulnerable by Design](https://img.shields.io/badge/status-vulnerable-critical)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

---

## 🎯 What Is This?

**VulnerableECommerceMVC** is a realistic legacy simulation of an ASP.NET MVC app — using poor authentication, no HTTPS enforcement, plaintext passwords, and zero rate-limiting.

It's built to:

- Expose legacy authentication pitfalls  
- Teach secure dev principles hands-on  
- Demonstrate attack chains with curl  
- Map remediation to **NIST SSDF** and **OWASP SAMM**  
- Deliver a lab-ready SSDLC review report  

---

## 🧱 Architecture Overview

```ascii
                +---------------------------+
                |     Curl / Browser        |
                +------------+--------------+
                             |
             ┌──────────────▼────────────────┐
             |      Kestrel Web Server       |
             |     - HTTP: 8080              |
             |     - HTTPS: 8443             |
             └──────────────┬────────────────┘
                            │
     ┌──────────────────────▼────────────────────────┐
     │             ASP.NET MVC Controllers           │
     │  ┌──────────────┬────────────────────────────┐│
     │  │ /insecure     │ Base64 + cleartext creds   ││
     │  │ /login (POST) │ Legacy form, no CSRF       ││
     │  │ /secure       │ HTTPS + SHA-256 hashed     ││
     │  └──────────────┴────────────────────────────┘│
     └───────────────────────────────────────────────┘
````

---

## 🩻 Vulnerabilities Demonstrated

| CWE / Category            | Issue                        | Risk Level  | Path                  |
| ------------------------- | ---------------------------- | ----------- | --------------------- |
| CWE-319 / Transport Layer | No HTTPS enforcement         | 🔥 Critical | `/insecure`           |
| CWE-256 / Credential Mgmt | Base64 + plaintext passwords | 🔥 Critical | `/insecure`, `/login` |
| CWE-307 / Auth Bypass     | No rate limiting             | 🔥 Critical | All endpoints         |
| CWE-352 / CSRF            | No anti-forgery tokens       | 🟠 Medium   | `/login`              |
| CWE-116 / Input Handling  | No input validation          | 🟠 Medium   | All forms             |

Full SSDLC threat modeling: [REPORT.MD](./REPORT.MD)

---

## 🔐 Secure vs Insecure Flow Comparison

| Property         | `/insecure`                 | `/securelogin`               |
| ---------------- | --------------------------- | ---------------------------- |
| Protocol         | HTTP (8080)                 | HTTPS (8443)                 |
| Auth Scheme      | Basic, cleartext            | Basic, SHA-256 hashed        |
| Password Storage | `DataStore.Users` plaintext | `_userHashes` in-memory hash |
| Role Logic       | `DataStore.UserRoles`       | `_userRoles` + mapped roles  |
| Security Logging | Console only                | Full log echo via response   |

---

## 🧪 How to Run the Lab

```bash
dotnet dev-certs https --trust
dotnet run
```

Open in browser:

* [http://localhost:8080/insecure](http://localhost:8080/insecure)
* [https://localhost:8443/securelogin](https://localhost:8443/securelogin)

---

## 🧪 Test Matrix (`tests.sh`)

```bash
# Insecure endpoint (HTTP)
curl -v http://localhost:8080/insecure
curl -v -H "Authorization: Basic $(echo -n 'john:password' | base64)" http://localhost:8080/insecure

# Secure endpoint (HTTPS)
curl -kv https://localhost:8443/securelogin
curl -kv -H "Authorization: Basic $(echo -n 'admin:password' | base64)" https://localhost:8443/securelogin
```

---

## 🧠 Learning Objectives

| Role                | Value Delivered                                                                |
| ------------------- | ------------------------------------------------------------------------------ |
| Developers          | See direct contrast of insecure vs secure login flows                          |
| Red Teamers         | Practice credential sniffing, brute force, redirect attacks                    |
| Security Architects | SSDLC mapping to [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) & OWASP SAMM |
| Compliance Teams    | Simulate a "legacy system review" scenario with actionable findings            |

---

## 📊 SSDLC + Compliance Mapping

| Phase                      | Practice             | Mapping                         |
| -------------------------- | -------------------- | ------------------------------- |
| Governance & Oversight     | RACI + policy        | NIST SSDF PO.1, SAMM Governance |
| Secure Design              | STRIDE, threat model | NIST SSDF PW\.1, SAMM Design    |
| Secure Coding              | SHA-256, HTTPS       | NIST SSDF PW\.3, CWE Top 25     |
| Testing & Validation       | curl, sniffing demo  | NIST SSDF RV.1, SAMM Verify     |
| Post-Deployment Monitoring | Logging, roadmap     | NIST SSDF RV.4, SAMM Ops        |

Reference: `Comprehensive SSDLC Framework Aligned to NIST SSDF & OWASP SAMM.pdf`

---

## 🧩 Project Structure

```
📦 VulnerableECommerceMVC/
├── Controllers/
│   ├── HomeController.cs
│   ├── SecureLoginController.cs
│   └── LoginController.cs
├── Models/
│   ├── User.cs
│   └── DataStore.cs
├── wwwroot/
├── Views/
├── tests.sh
├── Program.cs
├── .gitignore
└── REPORT.MD
```

---

## 🗺️ Roadmap

* [ ] Add rate-limiting middleware
* [ ] Upgrade password storage to bcrypt/Argon2
* [ ] Implement DI-based AuthenticationHandler
* [ ] Migrate secrets to Azure Key Vault
* [ ] CI/CD with GitHub Actions and Azure DevOps
* [ ] Add blind redirect scenario: `/vendor?redirect=...`
* [ ] Azure App Service + WAF + Front Door integration
* [ ] DAST scan via ZAP or Burp CLI

---

## 📢 Author

**Paul Volosen**
Security Architect | BreachSafe Labs
“Legacy .NET apps like this are still out there. I built this lab to show how to spot and fix them.”

---

## ⚠️ Legal Notice

This project is intentionally vulnerable. Use only in isolated environments. Educational purposes only.

```

---

