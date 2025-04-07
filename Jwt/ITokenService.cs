using System;
using System.Threading.Tasks;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Service interface for JWT token operations including access and refresh tokens
    /// </summary>
    public interface ITokenService
    {
        /// <summary>
        /// Generates an authentication response containing access and refresh tokens
        /// </summary>
        /// <param name="claimsInfo">The claims information for the token</param>
        /// <param name="ipAddress">The IP address of the requestor</param>
        /// <returns>Authentication response with tokens</returns>
        Task<AuthenticationResponse> GenerateAuthTokensAsync(IClaimsInfo claimsInfo, string ipAddress);

        /// <summary>
        /// Refreshes an access token using a valid refresh token
        /// </summary>
        /// <param name="refreshToken">The refresh token</param>
        /// <param name="ipAddress">The IP address of the requestor</param>
        /// <returns>Authentication response with new tokens</returns>
        Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken, string ipAddress);

        /// <summary>
        /// Revokes a refresh token
        /// </summary>
        /// <param name="token">The token to revoke</param>
        /// <param name="ipAddress">The IP address of the requestor</param>
        /// <param name="reason">The reason for revocation</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task RevokeTokenAsync(string token, string ipAddress, string reason = "Revoked without reason");

        /// <summary>
        /// Validates an access token
        /// </summary>
        /// <param name="token">The token to validate</param>
        /// <returns>True if the token is valid, false otherwise</returns>
        Task<bool> ValidateAccessTokenAsync(string token);

        /// <summary>
        /// Gets the claims info from an access token
        /// </summary>
        /// <param name="token">The access token</param>
        /// <returns>The claims info or null if invalid</returns>
        Task<IClaimsInfo> GetClaimsFromTokenAsync(string token);
    }
}