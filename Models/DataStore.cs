/*
 * File: Models/DataStore.cs
 * Project: VulnerableECommerceMVC
 * Layer: In-Memory Data Access (Authentication)
 *
 * Description:
 *   Static in-memory user store for the insecure Basic Auth demo.
 *   • Three users, all sharing the same clear-text password "password"
 *   • A simple role mapping (admin → DatabaseOwner; john/jane → StandardUser)
 *
 * Security Note:
 *   - Credentials and roles in clear text—no hashing, no encryption, no real ACL.
 */

using System.Collections.Generic;

namespace VulnerableECommerceMVC.Models
{
    public static class DataStore
    {
        // All share the insecure password "password"
        public static List<User> Users { get; } = new List<User>
        {
            new User { Username = "admin", Password = "password" },
            new User { Username = "john",  Password = "password" },
            new User { Username = "jane",  Password = "password" }
        };

        // Simple role map
        public static Dictionary<string, string> UserRoles { get; } = new Dictionary<string, string>
        {
            { "admin", "DatabaseOwner" },
            { "john",  "StandardUser"   },
            { "jane",  "StandardUser"   }
        };
    }
}
