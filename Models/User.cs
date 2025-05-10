/*
 * File: Models/User.cs
 * Project: VulnerableECommerceMVC
 * Layer: Domain Model (Authentication)
 *
 * Description:
 *   A simple user record with plaintext credentials.
 *   Used by HomeController to validate HTTP Basic credentials.
 */

namespace VulnerableECommerceMVC.Models
{
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
