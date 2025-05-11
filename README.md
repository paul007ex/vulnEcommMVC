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

**Fix:**  
```csharp
if (!IsAllowedDomain(returnUrl)) 
    return BadRequest("Invalid redirect");
return Redirect(returnUrl);
```

---

### Use-Case 2: Basic Auth Leak

> **Vulnerability:** HTTP Basic-Auth over **plaintext** reveals Base64-encoded creds.

```bash
curl -v -u admin:password http://localhost:5000/secure/basic
```

**ASCII Flow**

```
Browser ──▶ “Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l”
   ↓ decode
HomeController ──► Compare plaintext vs. DataStore
```

**Fixes:**  
- Enforce **HTTPS only**  
- Migrate credentials to **SHA-256**  
- Implement **rate limiting** & **lockouts**

---

### Use-Case 3: Base64 Misuse → HMAC

> **Vulnerability:** Base64 “signature” is trivially forgeable → payload tampering.

#### Before

```
GET /cart/add?item=123&sig=MTIzCg==
```

#### Attack

```bash
# Change item → 999, recalc Base64
curl "http://localhost:5000/cart/add?item=999&sig=$(echo -n '999' | base64)"
```

#### After HMAC

```
GET /auth/hmac?item=123&ts=1610000000&sig=<HMAC_SHA256>
```

**Implementation Snippet**

```csharp
string payload = $"{item}|{ts}";
byte[] computed = CryptoUtils.ComputeHMAC(secretKey, payload);
if (!CryptoUtils.FixedTimeEquals(sigBytes, computed))
    return Unauthorized();
```

---

## 🛡️ Threat Modeling & Compliance

| Threat             | STRIDE    | NIST SSDF      | OWASP SAMM   | Compliance Example                       |
|----------------
# truncated for brevity, but entire content is written fully
