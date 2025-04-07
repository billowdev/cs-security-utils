using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Implementation of the token service for JWT access and refresh token operations
    /// </summary>
    public class TokenService : ITokenService
    {
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly IOptions<JwtIssuerOptions> _jwtOptions;
        private readonly IOptions<RefreshTokenOptions> _refreshOptions;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly JwtSecurityTokenHandler _tokenHandler;

        /// <summary>
        /// Initializes a new instance of the TokenService class
        /// </summary>
        public TokenService(
            IJwtTokenGenerator jwtTokenGenerator,
            IOptions<JwtIssuerOptions> jwtOptions,
            IOptions<RefreshTokenOptions> refreshOptions,
            IRefreshTokenRepository refreshTokenRepository)
        {
            _jwtTokenGenerator = jwtTokenGenerator;
            _jwtOptions = jwtOptions;
            _refreshOptions = refreshOptions;
            _refreshTokenRepository = refreshTokenRepository;
            _tokenHandler = new JwtSecurityTokenHandler();
        }

        /// <summary>
        /// Generates an authentication response containing access and refresh tokens
        /// </summary>
        public async Task<AuthenticationResponse> GenerateAuthTokensAsync(IClaimsInfo claimsInfo, string ipAddress)
        {
            // Generate JWT access token
            string accessToken = _jwtTokenGenerator.CreateToken(claimsInfo);

            // Generate refresh token
            var refreshToken = await GenerateRefreshTokenAsync(claimsInfo.UserId, ipAddress);

            // Store refresh token
            await _refreshTokenRepository.AddAsync(refreshToken);

            // Enforce max active tokens limit
            await EnforceMaxActiveTokensLimitAsync(claimsInfo.UserId);

            // Create authentication response
            return new AuthenticationResponse
            {
                UserId = claimsInfo.UserId,
                Email = claimsInfo.Email,
                Role = claimsInfo.Role,
                AccessToken = accessToken,
                AccessTokenExpires = _jwtOptions.Value.Expiration,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpires = refreshToken.Expires
            };
        }

        /// <summary>
        /// Refreshes an access token using a valid refresh token
        /// </summary>
        public async Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken, string ipAddress)
        {
            // Get refresh token from repository
            var storedToken = await _refreshTokenRepository.GetByTokenAsync(refreshToken);

            if (storedToken == null)
                throw new SecurityException("Invalid refresh token");

            if (!storedToken.IsActive)
                throw new SecurityException("Inactive refresh token");

            // Get claims info from user associated with token
            var user = await _refreshTokenRepository.GetUserByIdAsync(storedToken.UserId);
            if (user == null)
                throw new SecurityException("User not found");

            // Create claims info for the new token
            var claimsInfo = new ClaimsInfo
            {
                UserId = user.Id,
                Email = user.Email,
                Role = user.Role,
                SubRole = user.SubRole,
                Permissions = user.Permissions
            };

            // If token reuse is not allowed, revoke the current token and replace it
            if (!_refreshOptions.Value.AllowReuse)
            {
                // Revoke current refresh token
                await RevokeTokenAsync(refreshToken, ipAddress, "Replaced by new token");

                // Create new refresh token
                return await GenerateAuthTokensAsync(claimsInfo, ipAddress);
            }

            // If token reuse is allowed, just create a new access token
            string accessToken = _jwtTokenGenerator.CreateToken(claimsInfo);

            return new AuthenticationResponse
            {
                UserId = claimsInfo.UserId,
                Email = claimsInfo.Email,
                Role = claimsInfo.Role,
                AccessToken = accessToken,
                AccessTokenExpires = _jwtOptions.Value.Expiration,
                RefreshToken = refreshToken,
                RefreshTokenExpires = storedToken.Expires
            };
        }

        /// <summary>
        /// Revokes a refresh token
        /// </summary>
        public async Task RevokeTokenAsync(string token, string ipAddress, string reason = "Revoked without reason")
        {
            var refreshToken = await _refreshTokenRepository.GetByTokenAsync(token);

            if (refreshToken == null)
                throw new SecurityException("Invalid token");

            if (!refreshToken.IsActive)
                throw new SecurityException("Token is already inactive");

            // Revoke token
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReasonRevoked = reason;

            // Save changes
            await _refreshTokenRepository.UpdateAsync(refreshToken);
        }

        /// <summary>
        /// Validates an access token
        /// </summary>
        public async Task<bool> ValidateAccessTokenAsync(string token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _jwtOptions.Value.SigningCredentials.Key,
                    ValidateIssuer = true,
                    ValidIssuer = _jwtOptions.Value.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtOptions.Value.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                // Validate token
                var principal = _tokenHandler.ValidateToken(token, tokenValidationParameters, out _);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the claims info from an access token
        /// </summary>
        public async Task<IClaimsInfo> GetClaimsFromTokenAsync(string token)
        {
            if (!await ValidateAccessTokenAsync(token))
                return null;

            var jwtToken = _tokenHandler.ReadJwtToken(token);
            var claims = jwtToken.Claims;

            var claimsInfo = new ClaimsInfo
            {
                UserId = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value,
                Email = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value,
                Role = claims.FirstOrDefault(c => c.Type == "role")?.Value,
                SubRole = claims.FirstOrDefault(c => c.Type == "subrole")?.Value
            };

            // Parse permissions from role_permission claim
            var permissionsStr = claims.FirstOrDefault(c => c.Type == "role_permission")?.Value;
            if (!string.IsNullOrEmpty(permissionsStr))
            {
                claimsInfo.Permissions = permissionsStr.Split(',').ToList();
            }

            return claimsInfo;
        }


        /// <summary>
        /// Generates a new refresh token
        /// </summary>
        private async Task<RefreshToken> GenerateRefreshTokenAsync(string userId, string ipAddress)
        {
            // Generate random token
            var randomBytes = new byte[_refreshOptions.Value.TokenSizeBytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            var token = Convert.ToBase64String(randomBytes);

            // Create refresh token object
            var refreshToken = new RefreshToken
            {
                Token = token,
                UserId = userId,
                Expires = DateTime.UtcNow.Add(_refreshOptions.Value.ValidFor),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };

            return refreshToken;
        }

        /// <summary>
        /// Enforces the maximum number of active tokens per user
        /// </summary>
        private async Task EnforceMaxActiveTokensLimitAsync(string userId)
        {
            var activeTokens = await _refreshTokenRepository.GetActiveTokensByUserIdAsync(userId);

            var maxTokensAllowed = _refreshOptions.Value.MaxActiveTokensPerUser;

            if (activeTokens.Count > maxTokensAllowed)
            {
                // Order by creation date (oldest first) and take tokens to remove
                var tokensToRemove = activeTokens
                    .OrderBy(t => t.Created)
                    .Take(activeTokens.Count - maxTokensAllowed);

                foreach (var token in tokensToRemove)
                {
                    token.Revoked = DateTime.UtcNow;
                    token.ReasonRevoked = "Exceeded max active tokens per user";
                    await _refreshTokenRepository.UpdateAsync(token);
                }
            }
        }

#endregion
    }

    /// <summary>
    /// Concrete implementation of IClaimsInfo
    /// </summary>
    public class ClaimsInfo : IClaimsInfo
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string SubRole { get; set; } = string.Empty;
        public IList<string> Permissions { get; set; } = new List<string>();
    }

    /// <summary>
    /// Custom security exception class
    /// </summary>
    public class SecurityException : Exception
    {
        public SecurityException(string message) : base(message) { }
    }
}