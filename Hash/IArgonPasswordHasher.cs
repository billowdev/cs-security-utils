using System;
using System.Threading.Tasks;

namespace App.Sources.Infra.Security.Hash;

/// <summary>
/// Interface for password hashing operations (Salt embedded in Hash)
/// </summary>
public interface IArgonPasswordHasher : IDisposable
{
    /// <summary>
    /// Creates a hash of a password with the given salt. This method is primarily for internal use.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <param name="salt">The salt to use in hashing.</param>
    /// <returns>The hashed password as a byte array.</returns>
    /// <remarks>This method should generally not be called directly. Use <see cref="HashPasswordAsync"/> instead.</remarks>
    Task<byte[]> HashAsync(string password, byte[] salt);

    /// <summary>
    /// Creates a salted hash of a password. The salt is embedded within the returned hash.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>A tuple containing the combined hash (Salt+Hash) and an empty salt string.  The salt is not returned separately as it is embedded within the hash.</returns>
    Task<(string Hash, string Salt)> HashPasswordAsync(string password);

    /// <summary>
    /// Verifies a password against a stored combined hash (Salt+Hash).
    /// </summary>
    /// <param name="password">The password to verify.</param>
    /// <param name="storedHash">The stored combined hash (Salt+Hash) as a base64 string.</param>
    /// <returns>True if the password matches the stored hash, false otherwise.</returns>
    Task<bool> VerifyPasswordAsync(string password, string storedHash);
}