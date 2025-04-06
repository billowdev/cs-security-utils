using System;
using Microsoft.IdentityModel.Tokens;

namespace App.Infra.Security;

public class JwtIssuerOptions
{
    public const string Schemes = "Bearer";

    /// <summary>
    /// "iss" (Issuer) Claim
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// "sub" (Subject) Claim
    /// </summary>
    public string? Subject { get; set; }

    /// <summary>
    /// "aud" (Audience) Claim
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// "nbf" (Not Before) Claim (default is UTC NOW)
    /// </summary>
    public DateTime NotBefore => DateTime.UtcNow;

    /// <summary>
    /// "iat" (Issued At) Claim (default is UTC NOW)
    /// </summary>
    public DateTime IssuedAt => DateTime.UtcNow;

    /// <summary>
    /// Set the timespan the token will be valid for (default is 5 min/300 seconds)
    /// </summary>
    public TimeSpan ValidFor { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// "exp" (Expiration Time) Claim (returns IssuedAt + ValidFor)
    /// </summary>
    public DateTime Expiration => IssuedAt.Add(ValidFor);

    /// <summary>
    /// "jti" (JWT ID) Claim (default ID is a GUID)
    /// </summary>
    public Func<string> JtiGenerator => () => Guid.NewGuid().ToString();

    /// <summary>
    /// The signing key to use when generating tokens.
    /// </summary>
    public SigningCredentials? SigningCredentials { get; set; }

    /// <summary>
    /// "role_permission" (Role Permission) Claim
    /// </summary>
    /// <remarks>
    /// This claim identifies the roles and their associated permissions.
    /// </remarks>
    public string? RolePermission { get; set; }

    /// <summary>
    /// "page_permission" (Page Permission) Claim
    /// </summary>
    /// <remarks>
    /// This claim identifies the permissions for specific pages.
    /// </remarks>
    public string? PagePermission { get; set; }
    /// <summary>
    /// "email" (Email) Claim
    /// </summary>
    /// <remarks>
    /// This claim represents the email address of the token owner.
    /// </remarks>
    public string? Email { get; set; }
}
