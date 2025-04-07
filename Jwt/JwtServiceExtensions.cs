using System;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace App.Sources.Infra.Security
{
    /// <summary>
    /// Extension methods for setting up JWT authentication services
    /// </summary>
    public static class JwtServiceExtensions
    {
        /// <summary>
        /// Adds JWT authentication services to the specified IServiceCollection
        /// </summary>
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            // Get JWT configuration
            var jwtSection = configuration.GetSection("Jwt");
            services.Configure<JwtIssuerOptions>(jwtSection);

            // Get refresh token configuration
            var refreshSection = configuration.GetSection("RefreshToken");
            services.Configure<RefreshTokenOptions>(refreshSection);

            // Configure JWT authentication
            var jwtSettings = jwtSection.Get<JwtIssuerOptions>();
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.SigningCredentials.Key.ToString()));

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

            // Register JWT services
            services.AddSingleton<IJwtTokenGenerator, JwtTokenGenerator>();
            services.AddScoped<ITokenService, TokenService>();

            return services;
        }
    }
}