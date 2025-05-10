# SSDLC Review Report: VulnerableECommerceMVC Login Endpoints

## 1. Executive Summary

<span style="font-weight:bold;">Purpose:</span> Demonstrate common security gaps in legacy authentication implementations and showcase targeted remediations within a controlled lab environment.

<span style="font-weight:bold;">Audience:</span> Directors seeking risk visibility, Developers needing practical guidance, and InfoSec professionals vetting compliance and threat mitigation strategies.

<div style="border-left:4px solid #0078D4; padding-left:10px; margin:10px 0; background:#f1f5f9;">
  In modernizing a critical e-commerce site, we uncovered typical missteps: unencrypted Basic‑Auth, plaintext passwords, and lack of brute‑force defenses. This report contrasts an insecure prototype with an improved, yet not fully hardened, implementation—providing clear steps toward a production‑ready state.
</div>

---

## 2. Scope & Methodology

**Scope:** Only authentication endpoints; integration points and data flows are out-of-scope.

**Methodology:**

1. **Static Code Review** to pinpoint security anti-patterns.
2. **Threat Modeling** aligning with STRIDE and MITRE ATT\&CK frameworks.
3. **Proof-of-Concept Testing** using `curl` to simulate real-world adversaries.
4. **Remediation Analysis** applying practical remediations.
5. **Risk Assessment** scoring via CVSS to prioritize fixes.

---

## 3. Vulnerability Summary & Risk Rating

| Issue                        | Endpoint | Impact          | Risk Level   | CVSS v3.1 Vector             |
| ---------------------------- | -------- | --------------- | ------------ | ---------------------------- |
| Unencrypted Credentials      | Insecure | Credential Leak | **Critical** | AV\:N/AC\:L/PR\:N/UI\:R/S\:U |
| Plain‑Text Password Storage  | Insecure | Data Compromise | **High**     | AV\:L/AC\:L/PR\:N/UI\:N/S\:U |
| No Rate‑Limiting             | Insecure | Brute‑Force     | **High**     | AV\:N/AC\:L/PR\:N/UI\:N/S\:U |
| Logic Coupling in Controller | Insecure | Maintenance     | **Medium**   | N/A                          |
| Missing Input Validation     | Insecure | Injection       | **Medium**   | AV\:N/AC\:L/PR\:N/UI\:N/S\:U |
| HTTPS Only Enforcement       | Secure   | Sniffing        | **Low**      | AV\:N/AC\:H/PR\:N/UI\:R/S\:U |

---

## 4. Insecure Prototype

### 4.1 Code Overview

```csharp
[HttpGet("/"), HttpGet("/insecure")]
public IActionResult Index() { /* Unencrypted Basic-Auth, clear-text store */ }
```

### 4.2 Key Findings

* **Lack of HTTPS**: Credentials sent in Base64 over HTTP.
* **Clear-Text Passwords**: Stored and compared without hashing.
* **Unlimited Login Attempts**: No deterrent against automated attacks.
* **Controller‑Embedded Logic**: Hard to audit and reuse.

> **Business Impact:** Exposure of user credentials can lead to account takeover, regulatory fines (e.g., GDPR), and reputational damage.

---

## 5. Improved Implementation

### 5.1 Code Highlights

```csharp
[RequireHttps]
[HttpGet("/secure"), HttpGet("/securelogin")]
public IActionResult Index() { /* HTTPS, SHA-256 hashing, role map */ }
```

### 5.2 Security Enhancements

* **TLS Encryption Enforced** via `[RequireHttps]`.
* **Password Hashing**: SHA‑256 in-memory store (salt recommended next).
* **Role‑Based Access**: Privilege separation for `DatabaseOwner` vs. `StandardUser`.
* **Isolation of Auth Logic**: Central controller dedicated to auth flow.

> **Residual Risks:** Absent rate‑limiting and advanced input validation; consider WAF and API gateway integration.

---

## 6. Validation & Testing

### 6.1 `curl` Test Matrix

```bash
# Insecure (HTTP): Expect 401 then 200 for valid
curl -v http://localhost:8080/insecure
curl -v -H "Auth: Basic $(base64 john:password)" http://localhost:8080/insecure

# Secure (HTTPS): Expect 401 then 200 for valid
curl -kv https://localhost:8443/secure
curl -kv -H "Auth: Basic $(base64 admin:password)" https://localhost:8443/secure
```

### 6.2 Attack Simulations

* **Sniffing Demo**: Show captured Base64 header.
* **Brute‑Force Loop**: Iterate weak passwords to demonstrate no lockout.

---

## 7. Roadmap to Production

1. **Integrate Rate‑Limiting** at API gateway or WAF.
2. **Adopt Strong Hashing** (bcrypt/Argon2) with unique salts.
3. **Shift to Authentication Middleware** (`BasicAuthenticationHandler`).
4. **Sanitize & Validate** all user inputs and headers.
5. **Use Secure Secret Management** (Azure Key Vault).
6. **Deploy WAF & Front Door** with custom rules and logging.
7. **Implement Monitoring & Alerts** in Application Insights.

---

## 8. Executive Callouts

* **Directors:** Accelerate migration from legacy HTTP auth to secure identity platforms to reduce breach risk and meet compliance.
* **Developers:** Leverage ASP.NET Core built‑in auth handlers to simplify code and avoid pitfalls.
* **InfoSec:** Enforce centralized policies (WAF, rate‑limit) and continuous vulnerability scanning.

---

## Appendix: Full Code Listings

### A. HomeController.cs (Insecure Endpoint)

```csharp
using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using VulnerableECommerceMVC.Models;

namespace VulnerableECommerceMVC.Controllers
{
    [ApiController]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        public HomeController(ILogger<HomeController> logger) => _logger = logger;

        [HttpGet("/"), HttpGet("/insecure")]
        public IActionResult Index()
        {
            var logs = new List<string> { "Received GET request" };
            _logger.LogInformation(logs.Last());

            string auth = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(auth) || !auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return ChallengeBasic(logs);

            string encoded = auth.Substring("Basic ".Length).Trim();
            logs.Add($"Extracted Base64 payload: {encoded}");
            _logger.LogInformation(logs.Last());

            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); // "username:password"
                logs.Add($"Decoded credentials: {decoded}");
                _logger.LogInformation(logs.Last());
            }
            catch
            {
                logs.Add("Failed to decode Base64");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }

            var parts = decoded.Split(new[] { ':' }, 2);
            if (parts.Length != 2)
                return ChallengeBasic(logs);

            string user = parts[0], pass = parts[1];
            logs.Add($"Parsed user='{user}', pass='(redacted)'");
            _logger.LogInformation(logs.Last());

            bool valid = DataStore.Users.Any(u => u.Username == user && u.Password == pass);
            if (!valid)
                return ChallengeBasic(logs);

            DataStore.UserRoles.TryGetValue(user, out var role);
            logs.Add($"Assigned role: {role}");
            _logger.LogInformation(logs.Last());

            logs.Add("Authentication successful");
            _logger.LogInformation(logs.Last());

            var body = new StringBuilder();
            logs.ForEach(line => body.AppendLine(line));
            body.AppendLine();
            body.AppendLine($"Welcome, {user}! Role: {role}");
            return Content(body.ToString(), "text/plain");
        }

        private IActionResult ChallengeBasic(List<string> logs)
        {
            Response.Headers["WWW-Authenticate"] = "Basic realm=\"VulnerableECommerce\"";
            Response.StatusCode = 401;
            var body = new StringBuilder();
            logs.ForEach(line => body.AppendLine(line));
            return Content(body.ToString(), "text/plain");
        }
    }
}
```

### B. SecureLoginController.cs (Secure Endpoint)

```csharp
using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace VulnerableECommerceMVC.Controllers
{
    [ApiController, RequireHttps]
    public class SecureLoginController : Controller
    {
        private readonly ILogger<SecureLoginController> _logger;
        public SecureLoginController(ILogger<SecureLoginController> logger) => _logger = logger;

        private const string PasswordHash =
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

        private static readonly Dictionary<string,string> _userHashes = new()
        {
            { "admin", PasswordHash }, { "john", PasswordHash }, { "jane", PasswordHash }
        };
        private static readonly Dictionary<string,string> _userRoles = new()
        {
            { "admin", "DatabaseOwner" }, { "john", "StandardUser" }, { "jane", "StandardUser" }
        };

        [HttpGet("/secure"), HttpGet("/securelogin")]
        public IActionResult Index()
        {
            var logs = new List<string> { "Received secure GET request" };
            _logger.LogInformation(logs.Last());

            var hdr = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(hdr) || !hdr.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return Challenge(hdr, logs);

            logs.Add($"Header: {hdr}"); _logger.LogInformation(logs.Last());

            string decoded;
            try
            {
                var payload = hdr.Substring("Basic ".Length).Trim();
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
                logs.Add($"Decoded: {decoded}"); _logger.LogInformation(logs.Last());
            }
            catch
            {
                return Challenge(hdr, logs);
            }

            var parts = decoded.Split(new[] { ':' }, 2);
            if (parts.Length != 2)
                return Challenge(hdr, logs);

            string user = parts[0], pass = parts[1];
            logs.Add($"Parsed user='{user}', pass='(redacted)'"); _logger.LogInformation(logs.Last());

            var hash = ComputeSha256(pass);
            logs.Add($"Hashed: {hash}"); _logger.LogInformation(logs.Last());

            if (!_userHashes.TryGetValue(user, out var stored) || stored != hash)
                return Challenge(hdr, logs);

            var role = _userRoles[user];
            logs.Add($"Role: {role}"); _logger.LogInformation(logs.Last());

            logs.Add("Authentication successful"); _logger.LogInformation(logs.Last());
            var body = new StringBuilder(); logs.ForEach(l => body.AppendLine(l));
            body.AppendLine(); body.AppendLine($"Welcome, {user}! Role: {role}");
            return Content(body.ToString(), "text/plain");
        }

        private IActionResult Challenge(string hdr, List<string> logs)
        {
            Response.Headers["WWW-Authenticate"] = "Basic realm=\"SecureVulnerableECommerce\"";
            Response.StatusCode = 401;
            var body = new StringBuilder(); logs.ForEach(l => body.AppendLine(l));
            return Content(body.ToString(), "text/plain");
        }

        private static string ComputeSha256(string input)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return string.Concat(bytes.Select(b => b.ToString("x2")));
        }
    }
}
```

### C. DataStore.cs (In-Memory User Store)

```csharp
using System.Collections.Generic;

namespace VulnerableECommerceMVC.Models
{
    public static class DataStore
    {
        public static List<User> Users { get; } = new()
        {
            new User { Username = "admin", Password = "password" },
            new User { Username = "john", Password = "password" },
            new User { Username = "jane", Password = "password" }
        };

        public static Dictionary<string,string> UserRoles { get; } = new()
        {
            { "admin", "DatabaseOwner" },
            { "john", "StandardUser" },
            { "jane", "StandardUser" }
        };
    }
}
```

### D. Program.cs (Application Startup)

```csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders(); builder.Logging.AddConsole();
builder.Services.AddControllersWithViews();

builder.WebHost.ConfigureKestrel(opts =>
{
    opts.ListenLocalhost(8080);
    opts.ListenLocalhost(8443, lo => lo.UseHttps());
});

var app = builder.Build();
app.UseHttpsRedirection(); app.UseStaticFiles(); app.UseRouting();
app.Use(async (ctx, next) => { app.Logger.LogInformation($"REQ {ctx.Request.Method} {ctx.Request.Path}"); await next(); });
app.UseEndpoints(endpoints => endpoints.MapControllers());
app.Run();
```

*Prepared by Paul — VulnerableECommerceMVC Security Lab*
