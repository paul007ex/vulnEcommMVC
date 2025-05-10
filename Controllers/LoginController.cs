/*
 * File: Controllers/LoginController.cs
 * Project: VulnerableECommerceMVC
 * Layer: MVC Controller (Authentication)
 *
 * Description:
 *   - Handles the user login flow via form submit.
 *   - Credentials posted in clear text (HTTP POST).
 *   - NO CSRF protection, NO HTTPS enforcement → insecure by design.
 *
 * Routes:
 *   • GET  /login          → Login form (Views/Login/Index.cshtml)
 *   • POST /login          → Process credentials
 *   • GET  /login/success  → Welcome page (Views/Login/Success.cshtml)
 *
 * How it works:
 *   1. `[HttpGet("login")]` → returns the form view.
 *   2. `[HttpPost("login")]` → reads `username` & `password` from form.
 *   3. Uses static DataStore.Users:
 *        using VulnerableECommerceMVC.Models;
 *        DataStore.Users.Any(u => u.Username == username && u.Password == password);
 *   4. On success → 302 redirect to /login/success?username={username}.
 *      On failure → re-render form with validation error.
 */

using System.Linq;
using Microsoft.AspNetCore.Mvc;
using VulnerableECommerceMVC.Models;

namespace VulnerableECommerceMVC.Controllers
{
    public class LoginController : Controller
    {
        /// <summary>
        /// GET /login
        /// Renders the login form.
        /// </summary>
        [HttpGet("login")]
        public IActionResult Index()
        {
            return View(); // Views/Login/Index.cshtml
        }

        /// <summary>
        /// POST /login
        /// Validates credentials against DataStore.Users.
        /// On success → redirect to /login/success?username=...
        /// On failure → re-display login form with error.
        /// </summary>
        [HttpPost("login")]
        public IActionResult Index(string username, string password)
        {
            bool valid = DataStore.Users
                .Any(u => u.Username == username && u.Password == password);

            if (valid)
            {
                return RedirectToAction("Success", new { username });
            }

            ModelState.AddModelError(string.Empty, "Invalid username or password");
            return View();
        }

        /// <summary>
        /// GET /login/success
        /// Shows a welcome message to the logged-in user.
        /// </summary>
        [HttpGet("login/success")]
        public IActionResult Success(string username)
        {
            return View(model: username);
        }
    }
}
