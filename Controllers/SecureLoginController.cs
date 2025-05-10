/*
 * File: Controllers/SecureLoginController.cs
 * Project: VulnerableECommerceMVC
 * Layer: MVC Controller (Secure Basic Authentication Endpoint)
 *
 * Purpose:
 *   Demonstrate a **secure** HTTP Basic Authentication flow on "/secure" and "/securelogin",
 *   with detailed logging and ASCII protocol diagrams—so you can compare step-by-step
 *   against the insecure demo in HomeController.
 *
 * Improvements over insecure version:
 *   • Enforces HTTPS ([RequireHttps]) so credentials are encrypted in transit
 *   • Stores only SHA-256 password hashes (no clear-text)
 *   • Supports multiple users (admin, john, jane) with role mapping
 *   • Logs every transition to the console and returns the trace in the response body
 *
 * HTTP Basic Auth Protocol (RFC 7617) & ASCII Flow:
 *
 *   1) Initial request (no Authorization header):
 *      ┌────────────┐
 *      │ Browser    │
 *      │ GET /secure│
 *      └──────┬─────┘
 *             │
 *             ▼
 *   ┌──────────────────────────────────┐
 *   │ SecureLoginController.Index     │
 *   │  • sees no header                │
 *   │  • logs "No header"              │
 *   │  • returns 401 + challenge       │
 *   └──────────────┬───────────────────┘
 *                  │
 *                  ▼
 *   ┌────────────┐
 *   │ Browser    │
 *   │ prompts    │
 *   │ for creds  │
 *   └────────────┘
 *
 *   2) Retry with Authorization header:
 *      ┌────────────┐
 *      │ Browser    │
 *      │ GET /secure│
 *      │ Auth: Basic│
 *      └──────┬─────┘
 *             │
 *             ▼
 *   ┌──────────────────────────────────┐
 *   │ SecureLoginController.Index     │
 *   │  • decodes Base64 → "user:pass"  │
 *   │  • logs "Decoded creds"          │
 *   │  • hashes password               │
 *   │  • logs "Hashed password"        │
 *   │  • validates against store       │
 *   │  • logs success/failure          │
 *   │  • returns 200 OK + welcome/role │
 *   └──────────────────────────────────┘
 *
 * Routes:
 *   [RequireHttps]
 *   [HttpGet("/secure"), HttpGet("/securelogin")]
 */

using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace VulnerableECommerceMVC.Controllers
{
    [ApiController]
    [RequireHttps]  // Only responds over HTTPS
    public class SecureLoginController : Controller
    {
        private readonly ILogger<SecureLoginController> _logger;

        public SecureLoginController(ILogger<SecureLoginController> logger)
        {
            _logger = logger;
        }

        // SHA-256 hash of "password"
        private const string PasswordHash = 
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

        // In-memory user→hash and user→role maps
        private static readonly Dictionary<string,string> _userHashes = new()
        {
            { "admin", PasswordHash },
            { "john",  PasswordHash },
            { "jane",  PasswordHash }
        };
        private static readonly Dictionary<string,string> _userRoles = new()
        {
            { "admin", "DatabaseOwner" },
            { "john",  "StandardUser"   },
            { "jane",  "StandardUser"   }
        };

        /// <summary>
        /// GET /secure and GET /securelogin
        /// Enforces Basic Auth over HTTPS with hashed passwords and role assignment.
        /// </summary>
        [HttpGet("/secure")]
        [HttpGet("/securelogin")]
        public IActionResult Index()
        {
            var logs = new List<string>();
            logs.Add("1️⃣ Received GET /secure or /securelogin over HTTPS");
            _logger.LogInformation(logs.Last());

            // 1) Check for Authorization header
            var authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || 
                !authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                logs.Add("2️⃣ No or invalid Authorization header – challenging client");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }
            logs.Add($"2️⃣ Found Authorization header: {authHeader}");
            _logger.LogInformation(logs.Last());

            // 2) Decode Base64 credentials
            var encoded = authHeader.Substring("Basic ".Length).Trim();
            logs.Add($"3️⃣ Extracted Base64 payload: {encoded}");
            _logger.LogInformation(logs.Last());

            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                logs.Add($"4️⃣ Decoded credentials: {decoded}");
                _logger.LogInformation(logs.Last());
            }
            catch (Exception ex)
            {
                logs.Add($"4️⃣ Base64 decode failed: {ex.Message}");
                _logger.LogError(ex, "Decode error");
                return ChallengeBasic(logs);
            }

            // 3) Split into username & password
            var parts = decoded.Split(new[] { ':' }, 2);
            if (parts.Length != 2)
            {
                logs.Add("5️⃣ Invalid credential format – missing ':'");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }
            var username = parts[0];
            var password = parts[1];
            logs.Add($"5️⃣ Parsed username='{username}', password='(redacted)'");
            _logger.LogInformation(logs.Last());

            // 4) Hash the provided password
            logs.Add("6️⃣ Hashing provided password with SHA-256");
            _logger.LogInformation(logs.Last());
            var hash = ComputeSha256(password);
            logs.Add($"6️⃣ Hashed password: {hash}");
            _logger.LogInformation(logs.Last());

            // 5) Validate credentials
            if (_userHashes.TryGetValue(username, out var storedHash) &&
                string.Equals(storedHash, hash, StringComparison.Ordinal))
            {
                logs.Add("7️⃣ Credentials valid – authentication successful");
                _logger.LogInformation(logs.Last());

                // 6) Lookup role
                var role = _userRoles.GetValueOrDefault(username, "StandardUser");
                logs.Add($"8️⃣ Assigned role: {role}");
                _logger.LogInformation(logs.Last());

                logs.Add("9️⃣ Returning 200 OK with logs + welcome message");
                _logger.LogInformation(logs.Last());

                // Build response
                var body = new StringBuilder();
                logs.ForEach(line => body.AppendLine(line));
                body.AppendLine();
                body.AppendLine($"👋 Welcome, {username}!");
                body.AppendLine($"🔑 Your role: {role}");

                return Content(body.ToString(), "text/plain");
            }
            else
            {
                logs.Add("7️⃣ Credentials invalid – challenging client");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }
        }

        /// <summary>
        /// Returns 401 Unauthorized + WWW-Authenticate header, 
        /// and echoes the log trace in the response body.
        /// </summary>
        private IActionResult ChallengeBasic(List<string> logs)
        {
            Response.Headers["WWW-Authenticate"] = "Basic realm=\"SecureVulnerableECommerce\"";
            Response.StatusCode = 401;
            var body = new StringBuilder();
            logs.ForEach(line => body.AppendLine(line));
            return Content(body.ToString(), "text/plain");
        }

        /// <summary>
        /// Computes SHA-256 hash of the input string and returns hex.
        /// </summary>
        private static string ComputeSha256(string input)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return string.Concat(bytes.Select(b => b.ToString("x2")));
        }
    }
}
