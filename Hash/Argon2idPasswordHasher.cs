using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Konscious.Security.Cryptography;

namespace App.Sources.Infra.Security.Hash;

/// <summary>
/// Implementation of IArgonPasswordHasher using Argon2id, storing the salt with the hash.
/// Implements the modified IArgonPasswordHasher interface.
/// </summary>
public class Argon2idPasswordHasher : IArgonPasswordHasher
{
	private const int Parallelism = 4; // Adjust based on available cores
	private const int MemorySize = 65536; // Adjust based on available memory (64MB)
	private const int Iterations = 3; // Adjust for security level vs. performance
	private const int SaltSize = 16; // Recommended minimum salt size
	private const int HashSize = 32; // Recommended minimum hash size

	private const string SaltSeparator = "$argon2id$"; // Separator character for combining salt and hash. Choose a character that's unlikely to appear in base64.

	private bool _disposedValue;


	/// <inheritdoc />
	private async Task<byte[]> HashAsync(string password, byte[] salt)
	{
		if (string.IsNullOrEmpty(password))
		{
			throw new ArgumentNullException(nameof(password), "Password cannot be null or empty.");
		}

		if (salt == null || salt.Length < SaltSize)
		{
			throw new ArgumentException($"Salt must be at least {SaltSize} bytes.", nameof(salt));
		}

		using (var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password)))
		{
			argon2.Salt = salt;
			argon2.DegreeOfParallelism = Parallelism;
			argon2.MemorySize = MemorySize;
			argon2.Iterations = Iterations;

			return await Task.Run(() => argon2.GetBytes(HashSize));
		}
	}

	/// <inheritdoc />
	public async Task<(string Hash, string Salt)> HashPasswordAsync(string password)
	{
		byte[] salt = GenerateSalt();
		byte[] hash = await HashAsync(password, salt);

		string combinedHash = Convert.ToBase64String(salt) + SaltSeparator + Convert.ToBase64String(hash);

		return (combinedHash, string.Empty); //Salt is now empty
	}

	/// <inheritdoc />
	public async Task<bool> VerifyPasswordAsync(string password, string storedHash)
	{
		if (string.IsNullOrEmpty(password))
		{
			throw new ArgumentNullException(nameof(password), "Password cannot be null or empty.");
		}

		if (string.IsNullOrEmpty(storedHash))
		{
			throw new ArgumentNullException(nameof(storedHash), "Stored hash cannot be null or empty.");
		}

		try
		{
			string[] parts = storedHash.Split(new string[] { SaltSeparator }, StringSplitOptions.None);

			if (parts.Length != 2)
			{
				Console.Error.WriteLine("Invalid stored hash format: Missing salt/hash separator.");
				return false; // Invalid stored hash format
			}

			byte[] saltBytes = Convert.FromBase64String(parts[0]);
			byte[] hashBytes = Convert.FromBase64String(parts[1]);

			byte[] computedHash = await HashAsync(password, saltBytes);

			return CryptographicOperations.FixedTimeEquals(hashBytes, computedHash);
		}
		catch (FormatException)
		{
			Console.Error.WriteLine("Invalid base64 encoding in stored hash.");
			return false;
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"Error during password verification: {ex.Message}");
			return false;
		}
	}

	/// <summary>
	/// Generates a random salt.
	/// </summary>
	/// <returns>The generated salt.</returns>
	private byte[] GenerateSalt()
	{
		byte[] salt = new byte[SaltSize];
		using (var rng = RandomNumberGenerator.Create())
		{
			rng.GetBytes(salt);
		}
		return salt;
	}

	protected virtual void Dispose(bool disposing)
	{
		if (!_disposedValue)
		{
			if (disposing)
			{
				// Dispose managed resources here.  In this case, there aren't any
				// *currently*, but this is where you'd put them if you added any
				// managed resources that implement IDisposable.  Even though Argon2id
				// *is* disposable, it's created and disposed of within the HashAsync
				// method, so we don't need to worry about it here.
			}

			// Free unmanaged resources (if any).
			// There are typically no unmanaged resources in this type of class.

			_disposedValue = true;
		}
	}

	// // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
	// ~Argon2idPasswordHasher()
	// {
	//     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
	//     Dispose(disposing: false);
	// }

	public void Dispose()
	{
		// Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
		Dispose(disposing: true);
		GC.SuppressFinalize(this);
	}

	Task<byte[]> IArgonPasswordHasher.HashAsync(string password, byte[] salt)
	{
		return HashAsync(password, salt);
	}
}