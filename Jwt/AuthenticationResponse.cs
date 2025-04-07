using System;
using System.Text.Json.Serialization;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Represents the response to a successful authentication
    /// </summary>
    public class AuthenticationResponse
    {
        /// <summary>
        /// Gets or sets the user ID
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Gets or sets the user's email
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's role
        /// </summary>
        public string Role { get; set; }

        /// <summary>
        /// Gets or sets the JWT access token
        /// </summary>
        public string AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the access token expiration time
        /// </summary>
        public DateTime AccessTokenExpires { get; set; }

        /// <summary>
        /// Gets or sets the refresh token
        /// </summary>
        public string RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token expiration time
        /// </summary>
        public DateTime RefreshTokenExpires { get; set; }

        /// <summary>
        /// Gets the refresh token expiration time in Unix timestamp format
        /// </summary>
        public long RefreshTokenExpiresUnix => new DateTimeOffset(RefreshTokenExpires).ToUnixTimeSeconds();

        /// <summary>
        /// Gets the access token expiration time in Unix timestamp format
        /// </summary>
        public long AccessTokenExpiresUnix => new DateTimeOffset(AccessTokenExpires).ToUnixTimeSeconds();
    }
}