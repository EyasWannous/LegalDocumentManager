using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Identity;

namespace LegalDocumentManager.Extensions;

public static class ApplicationDbInitializer
{
    public static async Task SeedUsersAndRolesAsync(IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var defaultUser = new ApplicationUser
        {
            Id = Guid.Empty.ToString(),
            UserName = "01010255577",
            Email = "01010255577",
            FullName = "Default User",
            PhoneNumber = "123456789",

        };

        if (await userManager.FindByEmailAsync(defaultUser.Email) == null)
        {
            await userManager.CreateAsync(defaultUser, "123qwe");
        }

        var defaultGovernment = new GovernmentAccount
        {
            UserName = "govuser",
            Email = "govuser@example.com",
            FullName = "Government User",
            PhoneNumber = "987654321"
        };

        if (await userManager.FindByEmailAsync(defaultGovernment.Email) == null)
        {
            await userManager.CreateAsync(defaultGovernment, "123qwe");
        }
    }
}
