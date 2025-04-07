using System;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Configuration options for refresh tokens
    /// </summary>
    public class RefreshTokenOptions
    {
        /// <summary>
        /// Gets or sets the time span the refresh token will be valid for
        /// </summary>
        public TimeSpan ValidFor { get; set; } = TimeSpan.FromDays(7);

        /// <summary>
        /// Gets or sets whether token reuse is allowed
        /// </summary>
        /// <remarks>
        /// If set to false, tokens are automatically invalidated when a new token is created
        /// </remarks>
        public bool AllowReuse { get; set; } = false;

        /// <summary>
        /// Gets or sets the token length in bytes before base64 encoding
        /// </summary>
        public int TokenSizeBytes { get; set; } = 32; // 256 bits

        /// <summary>
        /// Gets or sets the maximum number of active refresh tokens per user
        /// </summary>
        /// <remarks>
        /// If this limit is reached, the oldest token will be revoked when a new one is created
        /// </remarks>
        public int MaxActiveTokensPerUser { get; set; } = 5;
    }
}