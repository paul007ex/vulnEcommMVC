Absolutely. Below is your updated **masterclass `README.md`**, now enhanced with a complete breakdown of the **insecure login flow** — including source code, logic path, curl examples, and a side-by-side security flaws table.

This is ready to copy and paste into your repo’s `README.md`.

---

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

**VulnerableECommerceMVC** is a lab-quality .NET 7.0 MVC application simulating vulnerable legacy e-commerce authentication logic. It’s designed to help you:

- Identify high-risk code patterns (e.g., basic-auth over HTTP, plaintext passwords)
- Understand and implement secure alternatives
- Practice testing techniques like sniffing, brute-force, and input fuzzing
- Align secure development with **NIST SSDF**, **OWASP SAMM**, and **CWE Top 25**

---

## 🔓 Insecure Login Flow (`/insecure`)

### 🔥 Code Sample — `HomeController.cs`

```csharp
[HttpGet("/"), HttpGet("/insecure")]
public IActionResult Index()
{
    string auth = Request.Headers["Authorization"].FirstOrDefault();

    if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        return ChallengeBasic(new List<string> { "Missing or invalid Authorization header" });

    string encoded = auth.Substring("Basic ".Length).Trim();
    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); // "username:password"
    var parts = decoded.Split(new[] { ':' }, 2);

    string user = parts[0], pass = parts[1];

    // ⚠️ PLAINTEXT COMPARISON
    bool valid = DataStore.Users.Any(u => u.Username == user && u.Password == pass);

    if (!valid)
        return ChallengeBasic(new List<string> { "Invalid credentials" });

    DataStore.UserRoles.TryGetValue(user, out var role);
    return Content($"👋 Welcome, {user}!\n🔑 Your role: {role}", "text/plain");
}
````

### 🔓 Insecure Behavior Summary

| Flaw                       | Impact                             |
| -------------------------- | ---------------------------------- |
| No HTTPS enforcement       | Credentials sent in cleartext      |
| Base64 decoding only       | Easily decoded by packet sniffers  |
| Plaintext password storage | Exposed in memory and source       |
| No brute-force protection  | Infinite login attempts            |
| Logic inside controller    | No separation of concerns or reuse |
| No input validation        | Vulnerable to malformed headers    |

### 🔓 Insecure Login Example

```bash
curl -v -H "Authorization: Basic $(echo -n 'john:password' | base64)" http://localhost:8080/insecure
```

📥 Example response:

```
👋 Welcome, john!
🔑 Your role: StandardUser
```

---

## 🛡️ Secure Login Flow (`/securelogin`)

### ✅ Code Sample — `SecureLoginController.cs`

```csharp
[RequireHttps]
[HttpGet("/securelogin")]
public IActionResult Index()
{
    string auth = Request.Headers["Authorization"].FirstOrDefault();
    var encoded = auth.Substring("Basic ".Length).Trim();
    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
    var parts = decoded.Split(new[] { ':' }, 2);
    string user = parts[0], pass = parts[1];

    // ✅ HASHING WITH SHA-256
    string hash = ComputeSha256(pass);
    if (_userHashes.TryGetValue(user, out var stored) && stored == hash)
    {
        var role = _userRoles[user];
        return Content($"👋 Welcome, {user}!\n🔑 Your role: {role}", "text/plain");
    }

    return ChallengeBasic(new List<string> { "Invalid credentials" });
}
```

### 🛡️ Secure Behavior Summary

| Protection Feature    | Benefit                                 |
| --------------------- | --------------------------------------- |
| HTTPS required        | TLS encryption for credentials          |
| SHA-256 password hash | Prevents credential theft via memory/DB |
| Centralized role map  | Cleaner privilege enforcement           |
| Log tracing           | Useful for detection & auditing         |

### 🛡️ Secure Login Example

```bash
curl -kv -H "Authorization: Basic $(echo -n 'admin:password' | base64)" https://localhost:8443/securelogin
```

📥 Example response:

```
👋 Welcome, admin!
🔑 Your role: DatabaseOwner
```

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
```

---

## 🧪 How to Run the Lab

```bash
dotnet dev-certs https --trust
dotnet run
```

Access:

* [http://localhost:8080/insecure](http://localhost:8080/insecure)
* [https://localhost:8443/securelogin](https://localhost:8443/securelogin)

---

## 🧪 Complete Test Matrix (`tests.sh`)

```bash
# Insecure endpoint - no credentials
curl -i http://localhost:8080/insecure

# Insecure endpoint - valid credentials
curl -i -H "Authorization: Basic $(echo -n 'john:password' | base64)" http://localhost:8080/insecure

# Secure endpoint - no credentials
curl -kv https://localhost:8443/securelogin

# Secure endpoint - valid credentials
curl -kv -H "Authorization: Basic $(echo -n 'admin:password' | base64)" https://localhost:8443/securelogin
```

---

## 📊 SSDLC Mapping

| Domain                 | Practice                           | Aligned Standard                |
| ---------------------- | ---------------------------------- | ------------------------------- |
| Governance & Oversight | RACI, policy, SSDLC steering       | NIST SSDF PO.1, SAMM Governance |
| Secure Requirements    | Threat modeling (STRIDE)           | NIST SSDF PW\.1, SAMM Design    |
| Secure Implementation  | HTTPS, SHA-256, input handling     | NIST SSDF PW\.3, CWE Top 25     |
| Verification           | curl test matrix, brute-force demo | NIST SSDF RV.1, SAMM Verify     |
| Deployment & Ops       | HTTPS config, logging, WAF-ready   | NIST SSDF RV.4, SAMM Ops        |

---

## 📁 Project Structure

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

* [ ] Add brute-force detection and lockout
* [ ] Switch to ASP.NET AuthenticationHandler
* [ ] Integrate Azure Key Vault for credential management
* [ ] Add blind redirect simulation: `/vendor?redirect=...`
* [ ] CI/CD with GitHub Actions and Azure DevOps
* [ ] Deploy to Azure App Services + Front Door + WAF
* [ ] Run OWASP ZAP automation pipeline

---

## ⚠️ Legal Notice

This project is intentionally vulnerable. Do not deploy to production environments. For educational and lab use only.

```

---

Would you like me to also export this as a `.docx` or a polished GitHub Pages site for public demos?
```
