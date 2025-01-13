using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Identity;

namespace LegalDocumentManager.Services.PasswordHashers;

public class PasswordHasher : IPasswordHasher<ApplicationUser>
{
    const char Delimiter = ';';
    public string HashPassword(ApplicationUser user, string password)
    {
        var hasedPassword = PasswordHashingSalting.HashPasword(password, out byte[] salt);

        return string.Join(Delimiter, Convert.ToHexString(salt), hasedPassword);
    }

    public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
    {
        var elements = hashedPassword.Split(Delimiter);
        var salt = Convert.FromHexString(elements[0]);
        var hash = elements[1];

        return PasswordHashingSalting.VerifyPassword(providedPassword, hash, salt)
            ? PasswordVerificationResult.Success
            : PasswordVerificationResult.Failed;
    }
}