using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using LegalDocumentManager.Models;
using Shared.Encryptions;

namespace LegalDocumentManager.Views.Account;

public class LoginModel : PageModel
{
    [BindProperty]
    public LoginViewModel Input { get; set; }

    public IActionResult OnGet()
    {
        // Generate RSA Key Pair
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        ViewData["PublicKey"] = publicKey;
        TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

        return Page();
    }

    //public async Task<IActionResult> OnPostAsync()
    //{
    //    if (!ModelState.IsValid)
    //    {
    //        return Page();
    //    }

    //    // Call the Login logic in AccountController
    //    var controller = new Controllers.AccountController(/* inject required services */);
    //    var result = await controller.Login(Input);

    //    if (result is RedirectToActionResult)
    //    {
    //        return RedirectToPage("/Index"); // Adjust to your home page
    //    }

    //    TempData["Error"] = "Login failed.";
    //    return Page();
    //}
}
