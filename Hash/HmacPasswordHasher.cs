using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Provides password hashing functionality using HMAC SHA256
    /// </summary>
    public class HmacPasswordHasher : IPasswordHasher
    {
        private readonly byte[] _key;
        private const int SaltSize = 16; // 128 bits

        /// <summary>
        /// Initializes a new instance of the HmacPasswordHasher class
        /// </summary>
        /// <param name="key">The secret key to use for HMAC</param>
        public HmacPasswordHasher(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key));

            _key = Encoding.UTF8.GetBytes(key);
        }

        /// <summary>
        /// Creates a hash of a password with the given salt using HMAC SHA256
        /// </summary>
        public async Task<byte[]> HashAsync(string password, byte[] salt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            if (salt == null || salt.Length == 0)
                throw new ArgumentNullException(nameof(salt));

            return await Task.Run(() =>
            {
                // Combine password and salt
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var combined = new byte[passwordBytes.Length + salt.Length];

                Buffer.BlockCopy(passwordBytes, 0, combined, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, combined, passwordBytes.Length, salt.Length);

                // Compute HMAC
                using var hmac = new HMACSHA256(_key);
                return hmac.ComputeHash(combined);
            });
        }

        /// <summary>
        /// Creates a salted hash of a password
        /// </summary>
        public async Task<(string Hash, string Salt)> HashPasswordAsync(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            // Generate a random salt
            byte[] saltBytes = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }

            // Hash the password with the salt
            byte[] hashBytes = await HashAsync(password, saltBytes);

            // Convert to base64 strings
            string hash = Convert.ToBase64String(hashBytes);
            string salt = Convert.ToBase64String(saltBytes);

            return (hash, salt);
        }

        /// <summary>
        /// Verifies a password against a stored hash and salt
        /// </summary>
        public async Task<bool> VerifyPasswordAsync(string password, string storedHash, string storedSalt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            if (string.IsNullOrEmpty(storedHash))
                throw new ArgumentNullException(nameof(storedHash));

            if (string.IsNullOrEmpty(storedSalt))
                throw new ArgumentNullException(nameof(storedSalt));

            byte[] saltBytes = Convert.FromBase64String(storedSalt);
            byte[] hashBytes = await HashAsync(password, saltBytes);
            string hash = Convert.ToBase64String(hashBytes);

            return hash == storedHash;
        }

        /// <summary>
        /// Dispose method (no resources to dispose in this implementation)
        /// </summary>
        public void Dispose()
        {
            // No resources to dispose
            GC.SuppressFinalize(this);
        }
    }
}