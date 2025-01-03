using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Identity;

namespace LegalDocumentManager.Extensions;

public static class ApplicationDbInitializer
{
    public static async Task SeedUsersAndRolesAsync(IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        //var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        //// Ensure roles exist
        //var roles = new[] { "User", "Government" };
        //foreach (var role in roles)
        //{
        //    if (!await roleManager.RoleExistsAsync(role))
        //    {
        //        await roleManager.CreateAsync(new IdentityRole(role));
        //    }
        //}

        // Seed a default user
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
            var result = await userManager.CreateAsync(defaultUser, "123qwe");
            //if (result.Succeeded)
            //{
            //    await userManager.AddToRoleAsync(defaultUser, "User");
            //}
        }

        // Seed a government user
        var defaultGovernment = new GovernmentAccount
        {
            UserName = "govuser",
            Email = "govuser@example.com",
            FullName = "Government User",
            PhoneNumber = "987654321"
        };

        if (await userManager.FindByEmailAsync(defaultGovernment.Email) == null)
        {
            var result = await userManager.CreateAsync(defaultGovernment, "123qwe");
            //if (result.Succeeded)
            //{
            //    await userManager.AddToRoleAsync(defaultGovernment, "Government");
            //}
        }
    }
}
