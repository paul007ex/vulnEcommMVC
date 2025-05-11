# 🚀 VulnerableECommerceMVC Lab – Masterclass++ 🚀

**Author:** Paul Volosen, CISSP  
**GitHub:** [paul007ex/vulnEcommMVC](https://github.com/paul007ex/vulnEcommMVC)  
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
