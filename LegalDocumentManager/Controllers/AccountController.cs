using LegalDocumentManager.Data;
using LegalDocumentManager.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Shared.Encryptions;

namespace LegalDocumentManager.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpGet]
    public IActionResult Login()
    {
        // Generate RSA Key Pair
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        // Pass the Public Key to the View
        ViewData["PublicKey"] = publicKey;

        TempData["Key"] = AsymmetricEncryptionService.Encrypt(Constant.key, publicKey);

        // The Private Key should not be stored server-side. It will be stored in the client's localStorage.
        TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            TempData["Error"] = "Invalid form submission.";
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.NationalNumber);
        if (user is null)
        {
            TempData["Error"] = "User Not Found.";
            return View(model);
        }

        var result = await _signInManager.PasswordSignInAsync(user.UserName!, model.Password, model.RememberMe, false);
        if (!result.Succeeded)
        {
            TempData["Error"] = "National Number or password are incorrect";
            return View(model);
        }

        if (!string.IsNullOrEmpty(model.PublicKey))
        {
            user.ClientPublicKey = model.PublicKey;
            await _userManager.UpdateAsync(user);
        }

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            await _signInManager.CreateUserPrincipalAsync(user)
        );

        return RedirectToAction("Index", "Home");
    }


    [HttpGet]
    public IActionResult Register()
    {
        // Generate RSA Key Pair
        var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

        // Pass the Public Key to the View
        ViewData["PublicKey"] = publicKey;

        TempData["Key"] = AsymmetricEncryptionService.Encrypt(Constant.key, publicKey);

        // The Private Key should not be stored server-side. It will be stored in the client's localStorage.
        TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            TempData["Error"] = "Invalid form submission.";
            return View(model);
        }

        ApplicationUser user = model.IsGovernmentAccount
            ? new GovernmentAccount
            {
                UserName = model.NationalNumber,
                Email = model.NationalNumber,
                PhoneNumber = model.PhoneNumber,
                FullName = model.FullName,
            }
            : new ApplicationUser
            {
                UserName = model.NationalNumber,
                Email = model.NationalNumber,
                PhoneNumber = model.PhoneNumber,
                FullName = model.FullName,
            };

        if (!string.IsNullOrEmpty(model.PublicKey))
        {
            user.ClientPublicKey = model.PublicKey;
        }

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            TempData["Error"] = result.Errors.Select(x => x.Description).ToList();
            return View(model);
        }

        await _signInManager.SignInAsync(user, isPersistent: false);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            await _signInManager.CreateUserPrincipalAsync(user)
        );

        return RedirectToAction("Index", "Home");
    }


    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Index", "Home");
    }
}