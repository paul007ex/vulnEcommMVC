/*
 * File: Controllers/HomeController.cs
 * Project: VulnerableECommerceMVC
 * Layer: MVC Controller (Basic Authentication Entry Point)
 *
 * Purpose:
 *   Demonstrate a **purposely insecure** HTTP Basic Authentication
 *   implementation in a single controller action for teaching:
 *     - How the Basic Auth protocol works end-to-end
 *     - Exactly where and why this approach is unsafe
 *
 * Insecurity Summary:
 *   • Credentials are only Base64-encoded, not encrypted—sent in clear text.
 *   • No HTTPS enforcement: sniffers can capture creds easily.
 *   • No session or cookie: every request must re-send creds.
 *   • Plain-text password store in static DataStore.Users.
 *   • No rate-limiting or brute-force protection.
 *   • Logic lives in controller—easy to forget or bypass.
 *
 * Basic Auth Protocol (RFC 7617):
 *   1) Client → GET / HTTP/1.1
 *        Host: vulnerableecommerce.com
 *   2) Server → 401 Unauthorized
 *        WWW-Authenticate: Basic realm="VulnerableECommerce"
 *   3) Browser prompts user for username/password.
 *   4) Client → GET / HTTP/1.1
 *        Authorization: Basic <Base64("username:password")>
 *   5) Server decodes, splits, validates:
 *        • Success → 200 OK + resource
 *        • Failure → 401 Unauthorized + repeat challenge
 *
 * ASCII Protocol Flow:
 *
 *   ┌────────────┐                      ┌──────────────────────────┐
 *   │ Browser    │ GET /                │ HomeController.Index     │
 *   │ (no auth)  │ ───────────────────► │ sees no Authorization    │
 *   └────────────┘                      │ header                   │
 *                                        └─────────┬────────────────┘
 *                                                  │ 401 + WWW-Authenticate
 *                                                  ▼
 *   ┌────────────┐                      ┌──────────────────────────┐
 *   │ Browser    │ challenge            │ ChallengeBasic()         │
 *   │ prompts    │ ◄─────────────────── │ returns 401 + header     │
 *   │ for creds  │                      └──────────────────────────┘
 *   └────────────┘
 *
 *   ┌────────────┐                      ┌──────────────────────────┐
 *   │ Browser    │ GET / + auth        │ HomeController.Index     │
 *   │ (with hdr) │ ───────────────────► │ decodes Base64           │
 *   └────────────┘                      │ splits "user:pass"       │
 *                                        └─────────┬────────────────┘
 *                                                  │ valid?
 *                        ┌─────────────────────────▼─────────────────┐
 *                        │ 200 OK + logs + welcome text             │
 *                        └────────────────────────────────────────────│
 *                                                  │ invalid
 *                        ┌─────────────────────────▼─────────────────┐
 *                        │ 401 Unauthorized + challenge              │
 *                        └────────────────────────────────────────────┘
 *
 * DataStore Lookup:
 *   - Static in-memory store: VulnerableECommerceMVC.Models.DataStore.Users
 *   - No DI required—just `DataStore.Users.Any(...)`
 *
 * Security Notes:
 *   - Always layer Basic Auth over HTTPS in production.
 *   - Use hashed & salted passwords in a real user store.
 *   - Move this logic into an AuthenticationHandler or Filter.
 */

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

        /// <summary>
        /// GET "/" and GET "/insecure"
        /// Insecure Basic-Auth demo with multiple users & roles.
        /// </summary>
        [HttpGet("/"), HttpGet("/insecure")]
        public IActionResult Index()
        {
            var logs = new List<string>
            {
                "1️⃣ Received GET request"
            };
            _logger.LogInformation(logs.Last());

            // 1) Check for Authorization header
            string auth = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(auth))
            {
                logs.Add("2️⃣ No Authorization header—sending 401 challenge");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }

            logs.Add($"2️⃣ Found Authorization header: {auth}");
            _logger.LogInformation(logs.Last());

            // 2) Ensure Basic scheme
            if (!auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                logs.Add("3️⃣ Header not Basic—sending 401 challenge");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }

            // 3) Decode Base64 payload
            string encoded = auth.Substring("Basic ".Length).Trim();
            logs.Add($"3️⃣ Extracted Base64 payload: {encoded}");
            _logger.LogInformation(logs.Last());

            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); // "user:pass"
                logs.Add($"4️⃣ Decoded credentials: {decoded}");
                _logger.LogInformation(logs.Last());
            }
            catch (Exception ex)
            {
                logs.Add($"4️⃣ Base64 decode failed: {ex.Message}");
                _logger.LogError(ex, "Decoding error");
                return ChallengeBasic(logs);
            }

            // 4) Split into username/password
            var parts = decoded.Split(new[] { ':' }, 2);
            if (parts.Length != 2)
            {
                logs.Add("5️⃣ Invalid format—missing ':' separator");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }
            string user = parts[0], pass = parts[1];
            logs.Add($"5️⃣ Parsed username='{user}', password='(redacted)'");
            _logger.LogInformation(logs.Last());

            // 5) Validate credentials
            logs.Add("6️⃣ Validating credentials against DataStore");
            _logger.LogInformation(logs.Last());
            bool valid = DataStore.Users.Any(u => u.Username == user && u.Password == pass);
            if (!valid)
            {
                logs.Add("7️⃣ Invalid credentials—sending 401 challenge");
                _logger.LogInformation(logs.Last());
                return ChallengeBasic(logs);
            }

            logs.Add("7️⃣ Credentials valid!");
            _logger.LogInformation(logs.Last());

            // 6) Lookup role
            DataStore.UserRoles.TryGetValue(user, out var role);
            logs.Add($"8️⃣ Assigned role: {role}");
            _logger.LogInformation(logs.Last());

            logs.Add("9️⃣ Returning 200 OK with logs & welcome text");
            _logger.LogInformation(logs.Last());

            var body = new StringBuilder();
            logs.ForEach(line => body.AppendLine(line));
            body.AppendLine();
            body.AppendLine($"👋 Welcome, {user}!");
            body.AppendLine($"🔑 Your role: {role}");

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