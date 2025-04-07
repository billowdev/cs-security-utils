namespace App.Sources.Infra.Security;

public interface IJwtTokenGenerator
{
    string CreateToken(IClaimsInfo claimsInfo);
}

public class IClaimsInfo
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string SubRole { get; set; } = string.Empty;
    public IList<string> Permissions { get; set; }

    public IClaimsInfo()
    {
        Permissions = new List<string>();
    }
}