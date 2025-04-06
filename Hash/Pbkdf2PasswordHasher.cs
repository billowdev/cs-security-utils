
namespace App.Infra.Security {


 /// <summary>
    /// Provides password hashing functionality using PBKDF2
    /// </summary>
    public class Pbkdf2PasswordHasher : IPasswordHasher
    {
        private const int Iterations = 10000;
        private const int HashSize = 32; // 256 bits
        private const int SaltSize = 16; // 128 bits
        
        /// <summary>
        /// Creates a hash of a password with the given salt using PBKDF2
        /// </summary>
        public async Task<byte[]> HashAsync(string password, byte[] salt)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));
                
            if (salt == null || salt.Length == 0)
                throw new ArgumentNullException(nameof(salt));
                
            return await Task.Run(() =>
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(
                    password, 
                    salt, 
                    Iterations, 
                    HashAlgorithmName.SHA256);
                    
                return pbkdf2.GetBytes(HashSize);
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
        /// Dispose method (no resources to dispose)
        /// </summary>
        public void Dispose()
        {
            // No resources to dispose
            GC.SuppressFinalize(this);
        }
    }
    