using System.Collections.Generic;
using System.Threading.Tasks;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Repository interface for refresh token operations
    /// </summary>
    public interface IRefreshTokenRepository
    {
        /// <summary>
        /// Adds a new refresh token to the repository
        /// </summary>
        /// <param name="token">The token to add</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task AddAsync(RefreshToken token);

        /// <summary>
        /// Updates an existing refresh token in the repository
        /// </summary>
        /// <param name="token">The token to update</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task UpdateAsync(RefreshToken token);

        /// <summary>
        /// Gets a refresh token by its token string
        /// </summary>
        /// <param name="token">The token string</param>
        /// <returns>The refresh token object or null if not found</returns>
        Task<RefreshToken> GetByTokenAsync(string token);

        /// <summary>
        /// Gets all active refresh tokens for a user
        /// </summary>
        /// <param name="userId">The user ID</param>
        /// <returns>A list of active refresh tokens</returns>
        Task<List<RefreshToken>> GetActiveTokensByUserIdAsync(string userId);

        /// <summary>
        /// Gets a user by their ID
        /// </summary>
        /// <param name="userId">The user ID</param>
        /// <returns>The user object or null if not found</returns>
        Task<UserInfo> GetUserByIdAsync(string userId);

        /// <summary>
        /// Removes expired tokens from the repository
        /// </summary>
        /// <returns>The number of tokens removed</returns>
        Task<int> CleanupExpiredTokensAsync();
    }

    /// <summary>
    /// Represents basic user information for token operations
    /// </summary>
    public class UserInfo
    {
        /// <summary>
        /// Gets or sets the user ID
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the user's email
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the user's role
        /// </summary>
        public string Role { get; set; }

        /// <summary>
        /// Gets or sets the user's sub-role
        /// </summary>
        public string SubRole { get; set; }

        /// <summary>
        /// Gets or sets the user's permissions
        /// </summary>
        public List<string> Permissions { get; set; } = new List<string>();
    }
}