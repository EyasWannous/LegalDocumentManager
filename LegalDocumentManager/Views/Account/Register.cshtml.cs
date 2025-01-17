using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using LegalDocumentManager.Models;
using Shared.Encryptions;

namespace LegalDocumentManager.Views.Account;

public class RegisterModel : PageModel
{
    [BindProperty]
    public RegisterViewModel Input { get; set; } = new();

    public IActionResult OnGet()
    {
        // Generate RSA Key Pair
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        ViewData["PublicKey"] = publicKey;
        TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Call the Register logic in AccountController
        var controller = new Controllers.AccountController(/* inject required services */);
        var result = await controller.Register(Input);

        if (result is RedirectToActionResult)
        {
            return RedirectToPage("/Index"); // Adjust to your home page
        }

        TempData["Error"] = "Registration failed.";
        return Page();
    }
}
