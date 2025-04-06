using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace App.Infra.Security;

public class JwtTokenGenerator(IOptions<JwtIssuerOptions> jwtOptions) : IJwtTokenGenerator
{
    private readonly JwtIssuerOptions _jwtOptions = jwtOptions.Value;

    public string CreateToken(IClaimsInfo claimsInfo)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, claimsInfo.UserId),
            new Claim(JwtRegisteredClaimNames.Jti, _jwtOptions.JtiGenerator()),
            new Claim(
                JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(_jwtOptions.IssuedAt).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64
            ),
            new Claim(JwtRegisteredClaimNames.Email, claimsInfo.Email, ClaimValueTypes.String),
            new Claim("role", claimsInfo.Role, ClaimValueTypes.String),
            new Claim("role_permission", string.Join(",", claimsInfo.Permissions), ClaimValueTypes.String),
        };
        var jwt = new JwtSecurityToken(
            _jwtOptions.Issuer,
            _jwtOptions.Audience,
            claims,
            _jwtOptions.NotBefore,
            _jwtOptions.Expiration,
            _jwtOptions.SigningCredentials
        );

        var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
        return encodedJwt;
    }
}