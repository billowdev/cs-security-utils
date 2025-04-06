```cs
using App.Infra.Security;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace App.Example
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Setup dependency injection
            var services = new ServiceCollection();
            
            // Register the PBKDF2 password hasher as the default implementation
            services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
            
            // You can also register the HMAC password hasher with a specific name if needed
            services.AddSingleton<HmacPasswordHasher>(provider => 
                new HmacPasswordHasher("your-secure-key-here"));
                
            var serviceProvider = services.BuildServiceProvider();
            
            // Get the default password hasher
            var passwordHasher = serviceProvider.GetRequiredService<IPasswordHasher>();
            
            // Example usage
            string password = SecurityUtils.GenerateRandomPassword(16, true);
            Console.WriteLine($"Generated password: {password}");
            
            // Hash the password
            var (hash, salt) = await passwordHasher.HashPasswordAsync(password);
            Console.WriteLine($"Hash: {hash}");
            Console.WriteLine($"Salt: {salt}");
            
            // Verify the password
            bool isValid = await passwordHasher.VerifyPasswordAsync(password, hash, salt);
            Console.WriteLine($"Password verification result: {isValid}");
            
            // Compute a simple SHA256 hash
            string input = "Hello, World!";
            string sha256Hash = SecurityUtils.ComputeSha256Hash(input);
            Console.WriteLine($"SHA256 hash of '{input}': {sha256Hash}");
            
            // Don't forget to dispose the password hasher when done
            passwordHasher.Dispose();
        }
    }
}
```