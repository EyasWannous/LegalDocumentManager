using LegalDocumentManager.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LegalDocumentManager.Services;

public class TokenService
{
    private readonly IConfiguration _configuration;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string GenerateToken(ApplicationUser user)
    {
        //var claims = new List<Claim>
        //{
        //    new(ClaimTypes.Name, user.UserName!),
        //    // Add more claims as needed
        //};

        //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        //var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        //var token = new JwtSecurityToken(
        //    _configuration["Jwt:Issuer"],
        //    _configuration["Jwt:Audience"],
        //    claims,
        //    expires: DateTime.UtcNow.AddMinutes(30),
        //    signingCredentials: creds
        //);

        var tokenHandler = new JwtSecurityTokenHandler();

        var signingKey = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]!);

        List<Claim> claims =
        [
            new("Id", user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.GivenName, user.UserName!),
            new(JwtRegisteredClaimNames.Sub, user.Email!), // unique id
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // used by refresh token
        ];

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(30),
            Audience = _configuration["Jwt:Issuer"],
            Issuer = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials
            (
                new SymmetricSecurityKey(signingKey),
                SecurityAlgorithms.HmacSha256Signature
            ),
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        //var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

        var jwtToken = tokenHandler.WriteToken(token);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}