using System;
using System.Threading.Tasks;

namespace App.Sources.Infra.Security;

/// <summary>
/// Interface for password hashing operations
/// </summary>
public interface IPasswordHasher : IDisposable
{
    /// <summary>
    /// Creates a hash of a password with the given salt
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="salt">The salt to use in hashing</param>
    /// <returns>The hashed password as a byte array</returns>
    Task<byte[]> HashAsync(string password, byte[] salt);

    /// <summary>
    /// Creates a salted hash of a password
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <returns>A tuple containing the hash and salt as base64 strings</returns>
    Task<(string Hash, string Salt)> HashPasswordAsync(string password);

    /// <summary>
    /// Verifies a password against a stored hash and salt
    /// </summary>
    /// <param name="password">The password to verify</param>
    /// <param name="storedHash">The stored hash (base64 encoded)</param>
    /// <param name="storedSalt">The stored salt (base64 encoded)</param>
    /// <returns>True if the password matches, false otherwise</returns>
    Task<bool> VerifyPasswordAsync(string password, string storedHash, string storedSalt);
}