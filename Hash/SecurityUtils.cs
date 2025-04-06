using System.Security.Cryptography;
using System.Text;

namespace App.Infra.Security
{
 /// <summary>
    /// Provides general security and cryptography utilities
    /// </summary>
    public static class SecurityUtils
    {
        /// <summary>
        /// Generates a random password of the specified length
        /// </summary>
        /// <param name="length">The length of the password to generate</param>
        /// <param name="includeSpecialChars">Whether to include special characters</param>
        /// <returns>A random password string</returns>
        public static string GenerateRandomPassword(int length = 12, bool includeSpecialChars = true)
        {
            const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
            const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string numberChars = "0123456789";
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";

            var charSet = lowerChars + upperChars + numberChars;
            if (includeSpecialChars) charSet += specialChars;

            // Use a cryptographically secure random number generator
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[length];
            rng.GetBytes(bytes);
            
            var result = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                // Use the random bytes to select characters from the charSet
                result.Append(charSet[bytes[i] % charSet.Length]);
            }

            return result.ToString();
        }

        /// <summary>
        /// Computes the SHA256 hash of a string
        /// </summary>
        /// <param name="input">The string to hash</param>
        /// <returns>The hexadecimal string representation of the hash</returns>
        public static string ComputeSha256Hash(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;

            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = sha256.ComputeHash(bytes);

            var builder = new StringBuilder();
            foreach (var b in hashBytes)
            {
                builder.Append(b.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}