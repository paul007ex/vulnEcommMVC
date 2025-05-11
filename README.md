# 🚀 VulnerableECommerceMVC Lab – Masterclass++ 🚀

**Author:** Paul Volosen, CISSP  
**GitHub:** [paul007ex/vulnEcommMVC](https://github.com/paul007ex/vulnEcommMVC)  
**LinkedIn:** [paulvolosen](https://www.linkedin.com/in/paulvolosen/)  
**Audience:** Developers → AppSec Engineers → Directors → CISOs  

---

## 📋 Table of Contents

1. [Lab Overview](#lab-overview)  
2. [Learning Outcomes](#learning-outcomes)  
3. [Prerequisites & Setup](#prerequisites--setup)  
4. [Project Structure](#project-structure)  
5. [Phase Walkthrough](#phase-walkthrough)  
6. [Use-Case Deep Dives](#use-case-deep-dives)  
   - [Open Redirect](#use-case-1-open-redirect)  
   - [Basic Auth Leak](#use-case-2-basic-auth-leak)  
   - [Base64 Misuse → HMAC](#use-case-3-base64-misuse--hmac)  
7. [Threat Modeling & Compliance](#threat-modeling--compliance)  
8. [Attack & Test Matrix](#attack--test-matrix)  
9. [Extension Ideas](#extension-ideas)  
10. [Resources & Further Reading](#resources--further-reading)  
11. [Feedback & Contributing](#feedback--contributing)  

---

## 🔍 Lab Overview

This hands-on lab simulates **legacy auth mistakes** and **modern remediations** in a .NET MVC app.  
You will **clone**, **compile**, **attack**, **fix**, and **map** everything to real-world frameworks:

> • **STRIDE** threat model  
> • **NIST SSDF**  
> • **OWASP SAMM**  
> • **PCI-DSS v4.0**  
> • **ISO 27001:2022**  
> • **GDPR/CCPA**

---

## 🎓 Learning Outcomes

By completing this lab, you will be able to:

- 🔓 Identify and exploit common auth flaws  
- 🔄 Validate and secure redirect endpoints  
- 🔑 Migrate from Basic-Auth → SHA-256 → HMAC  
- 🛡️ Map fixes to security standards & compliance  
- 📊 Build a repeatable attack/test matrix  
- 🔧 Extend to modern SSO (SAML/OIDC) demos  

---

## ⚙️ Prerequisites & Setup

1. **Install**  
   - [.NET 7 SDK & Runtime](https://dotnet.microsoft.com/download)  
   - `git`, `curl`, **PowerShell** (Windows) / **Bash** (macOS/Linux)  

2. **Clone & Run**

   ```bash
   git clone https://github.com/paul007ex/vulnEcommMVC.git
   cd vulnEcommMVC
   dotnet restore
   dotnet run
   ```

3. **Verify**  
   - App: `http://localhost:5000`  
   - Swagger UI (if enabled): `http://localhost:5000/swagger`

---

## 📂 Project Structure

```
📦 vulnEcommMVC
 ┣ 📜 Program.cs
 ┣ 📜 DataStore.cs       ← In-memory “SQL” tables
 ┣ 📜 User.cs            ← Model + roles
 ┣ 📂 Controllers/
 ┃   ┣ 📜 HomeController.cs       ← Insecure Basic-Auth over HTTP
 ┃   ┣ 📜 SecureLoginController.cs← HTTPS + SHA-256
 ┃   ┣ 📜 LoginController.cs      ← MVC Form login (no CSRF!)
 ┃   ┣ 📜 RedirectController.cs   ← Blind-redirect demo
 ┃   ┗ 📜 HmacController.cs       ← HMAC signature demo
 ┣ 📜 tests.sh           ← curl attack & validation scripts
 ┣ 📜 INSTRUCTIONS.md    ← This master README source
 ┗ 📜 Explanation-*.md   ← Per-feature deep dives
```

---

## 🏗 Phase Walkthrough

```text
1) Hello World Console      → helloworld.cs
2) Minimal HTTP Server      → Program.cs
3) In-Memory Data Store     → DataStore.cs + User.cs
4) Use-Case #1: Open Redirect
5) Use-Case #2: Basic-Auth Leak
6) Use-Case #3: Base64 Misuse → HMAC
```

---

## 📌 Use-Case Deep Dives

### Use-Case 1: Open Redirect

> **Vulnerability:** Unvalidated `returnUrl` parameter allows phishing & credential capture.

```bash
curl -v "http://localhost:5000/redirect?to=https://evil.com"
```

**ASCII Flow – Before**

```
┌─────────┐    GET /redirect?to=https://evil.com    ┌───────────────────┐
│ Browser │ ──────────────────────────────────────► │ RedirectController │
└─────────┘                                         │ no validation      │
                                                    └───────────────────┘
                                                             │
                                                             ▼
                                                      302 Location=https://evil.com
```

**Remediation Fix:**  
```csharp
if (!IsAllowedDomain(returnUrl)) 
    return BadRequest("Invalid redirect");
return Redirect(returnUrl);
```

---

### Use-Case 2: Basic Auth Leak

> **Vulnerability:** HTTP Basic Auth over **plaintext** reveals Base64-encoded creds.

```bash
curl -v -u admin:password http://localhost:5000/secure/basic
```

**ASCII Flow**

```
Browser ──▶ “Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l”
   ↓ decode
HomeController ──► Compare plaintext vs. DataStore
```

**Remediation Fixes:**  
- Enforce **HTTPS only**  
- Migrate credentials to **SHA-256 hashing**  
- Implement **rate limiting** & **account lockouts**

---

### Use-Case 3: Base64 Misuse → HMAC

> **Vulnerability:** Base64 “signature” is trivially forgeable → payload tampering.

#### Before

```
GET /cart/add?item=123&sig=MTIzCg==
```

#### Attack Example

```bash
# Change item → 999, recalc Base64
curl "http://localhost:5000/cart/add?item=999&sig=$(echo -n '999' | base64)"
```

#### After: HMAC Signature

```
GET /auth/hmac?item=123&ts=1610000000&sig=<HMAC_SHA256(item|ts)>
```

```csharp
// HMAC Validation Snippet
string payload = $"{item}|{ts}";
byte[] computed = CryptoUtils.ComputeHMAC(secretKey, payload);
if (!CryptoUtils.FixedTimeEquals(sigBytes, computed))
    return Unauthorized();
```

---

## 🛡️ Threat Modeling & Compliance

| Threat             | STRIDE    | NIST SSDF      | OWASP SAMM   | Compliance Example                       |
|--------------------|-----------|----------------|--------------|-------------------------------------------|
| Open Redirect      | Tampering | RV.1, RV.2     | Design       | ISO 27001 A.14: Secure System Dev         |
| Basic Auth Leak    | Info Disc | PW.3           | Implementation | PCI-DSS 8.3.1–6: Strong Auth               |
| HMAC Bypass        | Spoofing  | PW.4, RV.4     | Verification | GDPR Art 32: Integrity & Confidentiality  |
| CSRF (Form-Login)  | Elevation | RV.3           | Operations   | NIST 800-53 AC-4: Session Integrity       |

> **Legend:**  
> • **PW** – Password & Auth  
> • **RV** – Runtime Validation  

---

## 🧪 Attack & Test Matrix

Execute **`bash tests.sh`** to run all scenarios:

```bash
# 1) Open Redirect Attack
curl -i "http://localhost:5000/redirect?to=https://evil.com"

# 2) Insecure Basic-Auth Attempt
curl -v -u admin:password http://localhost:5000/secure/basic

# 3) Base64 Tampering
curl "http://localhost:5000/cart/add?item=999&sig=$(echo -n '999' | base64)"

# 4) HMAC Tampering
curl "http://localhost:5000/auth/hmac?item=123&ts=0&sig=invalid"
```

---

## ✨ Extension Ideas

- ▶️ **SAML/OIDC Integration**: Simulate NJ SSO broker & validate SAML assertions  
- ▶️ **POST Form Support**: HMAC auth via form POST payloads  
- ▶️ **CI/CD Security Gates**: Integrate checks in GitHub Actions or Azure Pipelines  
- ▶️ **Automated Threat Diagrams**: Export STRIDE via OWASP Threat Dragon  

---

## 📚 Resources & Further Reading

- [NIST SSDF](https://csrc.nist.gov/projects/secure-software-development-framework)  
- [OWASP SAMM](https://owasp.org/www-project-samm/)  
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)  
- [ISO 27001:2022](https://www.iso.org/isoiec-27001-information-security.html)  
- [GDPR Compliance](https://gdpr-info.eu/)  

---

## 🚀 Feedback & Contributing

> Love it? ⭐️ the repo!  
> Found a gap? 🐛 file an issue.  
> Want to contribute? 🔀 submit a PR!

---


