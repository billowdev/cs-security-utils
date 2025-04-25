# Argon2idPasswordHasher

This repository provides an implementation of a secure password hashing utility using Argon2id, adhering to best practices for security and performance. It utilizes the `Konscious.Security.Cryptography` NuGet package.  The salt is embedded within the generated hash.

## Features

*   **Argon2id Hashing:** Uses the Argon2id algorithm, a modern key derivation function highly resistant to various attacks, including brute-force and side-channel attacks.
*   **Salt Embedding:**  The generated hash contains the randomly generated salt required for verification.
*   **Configurable Parameters:** Allows customization of Argon2id parameters such as parallelism, memory size, and iterations to balance security and performance.
*   **Secure Comparison:**  Employs `CryptographicOperations.FixedTimeEquals` for secure password comparison, preventing timing attacks.
*   **Asynchronous Operations:** Uses asynchronous operations for efficient use of resources, especially important in web applications.
*   **Clear Error Handling:** Includes detailed error handling and logging for potential issues during password hashing and verification.
*   **`IDisposable` Implementation:** Properly disposes of resources.

## Prerequisites

*   .NET 6.0 or later
*   `Konscious.Security.Cryptography` NuGet package.  Install it using:

    ```bash
    dotnet add package Konscious.Security.Cryptography
    ```

## Installation

1.  Clone the repository to your local machine.
2.  Add the `Argon2idPasswordHasher.cs` file and `IArgonPasswordHasher.cs` files to your project.
3.  Install the `Konscious.Security.Cryptography` NuGet package.

## Usage

Here's how to use the `Argon2idPasswordHasher` class for hashing and verifying passwords:

```csharp
using App.Sources.Infra.Security.Hash; // Adjust the namespace if necessary
using System.Threading.Tasks;

public class PasswordManager
{
    private readonly IArgonPasswordHasher _passwordHasher;

    public PasswordManager()
    {
        _passwordHasher = new Argon2idPasswordHasher();
    }

    public async Task<(string Hash, string Salt)> HashPasswordAsync(string password)
    {
        return await _passwordHasher.HashPasswordAsync(password);
    }

    public async Task<bool> VerifyPasswordAsync(string password, string storedHash)
    {
        return await _passwordHasher.VerifyPasswordAsync(password, storedHash);
    }
}

public class Example
{
    public static async Task Main(string[] args)
    {
        var passwordManager = new PasswordManager();

        string password = "MySuperSecretPassword123!";

        // Hash the password
        var (hash, _) = await passwordManager.HashPasswordAsync(password); // The Salt will be an empty string; it is embedded in the Hash.

        Console.WriteLine($"Hashed Password: {hash}");


        // Verify the password
        bool isValid = await passwordManager.VerifyPasswordAsync(password, hash);

        Console.WriteLine($"Password is valid: {isValid}"); // Output: Password is valid: True

        // Verify an incorrect password
        bool isInvalid = await passwordManager.VerifyPasswordAsync("WrongPassword", hash);

        Console.WriteLine($"Password is valid: {isInvalid}"); // Output: Password is valid: False

        // Remember to Dispose the hasher to release resources when you're done with it!
        ((IDisposable)passwordManager._passwordHasher).Dispose();

    }
}

```

**Explanation:**

1.  **`Argon2idPasswordHasher` instantiation:**  A new instance of `Argon2idPasswordHasher` is created.  This class implements `IDisposable`, so you'll want to ensure that it is disposed of to prevent resource leaks, particularly in long-running applications. Using `using` blocks or explicitly calling `Dispose()` are both acceptable methods of doing this.

2.  **`HashPasswordAsync`:** This method takes the plain text password and generates a secure hash with a randomly generated salt. The salt is then embedded within the returned hash. The salt property in the returning tuple will be an empty string because the salt is inside the Hash.

3.  **`VerifyPasswordAsync`:** This method takes the plain text password and the stored combined hash (Salt+Hash). It extracts the salt from the hash, hashes the provided password using the extracted salt, and compares the result with the stored hash.  It uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks.

## Configuration

The `Argon2idPasswordHasher` class allows you to configure the Argon2id parameters. You can adjust these parameters to balance security and performance.

```csharp
public class Argon2idPasswordHasher : IArgonPasswordHasher
{
    private const int Parallelism = 4; // Adjust based on available cores
    private const int MemorySize = 65536; // Adjust based on available memory (64MB)
    private const int Iterations = 3; // Adjust for security level vs. performance
    private const int SaltSize = 16; // Recommended minimum salt size
    private const int HashSize = 32; // Recommended minimum hash size

    // ...
}
```

*   **`Parallelism`:**  The degree of parallelism (number of threads).  Generally, this should match the number of available processor cores.
*   **`MemorySize`:**  The amount of memory to use in KB.  Increasing this makes the algorithm more resistant to brute-force attacks but also increases resource consumption.  64MB (65536) is a reasonable default.
*   **`Iterations`:** The number of iterations to perform.  Increasing this increases the computation cost and makes the algorithm more resistant to brute-force attacks.  Adjust this in relation to the MemorySize and Parallelism.
*   **`SaltSize`:**  The length of the salt in bytes.  16 bytes is the minimum recommended salt size.
*   **`HashSize`:** The desired length of the hash in bytes. 32 bytes (256 bits) is a good starting point.

**Security Considerations:**

*   The default values are a good starting point, but it is recommended to adjust them based on your specific security requirements and available resources.
*   Higher values for `MemorySize` and `Iterations` provide better security but also increase the computation cost, which can impact performance.
*   It is essential to regularly review and update these parameters to maintain a strong security posture.

## Error Handling

The `VerifyPasswordAsync` method includes error handling for the following scenarios:

*   Null or empty password.
*   Null or empty stored hash.
*   Invalid stored hash format (missing separator).
*   Invalid base64 encoding in the stored hash.
*   Other exceptions during password verification.

Error messages are logged to the console's error stream (`Console.Error`) to aid in debugging.  In a production environment, you should replace this with a more robust logging mechanism.

## Thread Safety

The `Argon2idPasswordHasher` is thread-safe for concurrent hashing and verification operations. The `Argon2id` class from `Konscious.Security.Cryptography` handles thread safety internally.

## Disposal

The `Argon2idPasswordHasher` implements the `IDisposable` interface.  It is important to dispose of the object when you are finished with it to release any resources. Use a `using` statement or explicitly call the `Dispose()` method.

```csharp
using (var passwordHasher = new Argon2idPasswordHasher())
{
    // Use the password hasher
} // Dispose() is called automatically at the end of the using block
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contributions

Contributions are welcome! Please feel free to submit pull requests or open issues to report bugs or suggest new features.

