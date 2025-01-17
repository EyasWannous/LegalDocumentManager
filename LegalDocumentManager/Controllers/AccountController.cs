using LegalDocumentManager.Data;
using LegalDocumentManager.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace LegalDocumentManager.Controllers;

[ApiController]
[Route("[Controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    //[HttpGet]
    //public IActionResult Login()
    //{
    //    // Generate RSA Key Pair
    //    var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

    //    // Pass the Public Key to the View
    //    ViewData["PublicKey"] = publicKey;

    //    TempData["Key"] = AsymmetricEncryptionService.Encrypt(Constant.AESKey, publicKey);

    //    // The Private Key should not be stored server-side. It will be stored in the client's localStorage.
    //    TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

    //    return View();
    //}

    [HttpPost("Login")]
    public async Task<IActionResult> Login([FromBody] LoginViewModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.NationalNumber);
        if (user is null)
            return BadRequest("User Not Found");

        var result = await _signInManager.PasswordSignInAsync(user.UserName!, model.Password, model.RememberMe, false);
        if (!result.Succeeded)
            return BadRequest("National Number or password are incorrect");

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


    //[HttpGet]
    //public IActionResult Register()
    //{
    //    // Generate RSA Key Pair
    //    var (publicKey, privateKey) = RSAKeyGenerator.GenerateKeys();

    //    // Pass the Public Key to the View
    //    ViewData["PublicKey"] = publicKey;

    //    TempData["Key"] = AsymmetricEncryptionService.Encrypt(Constant.AESKey, publicKey);

    //    // The Private Key should not be stored server-side. It will be stored in the client's localStorage.
    //    TempData["PrivateKey"] = privateKey; // Optional for debugging; avoid in production.

    //    return View();
    //}

    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
    {
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
            user.ClientPublicKey = model.PublicKey;

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors.Select(x => x.Description).ToList());

        await _signInManager.SignInAsync(user, isPersistent: false);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            await _signInManager.CreateUserPrincipalAsync(user)
        );

        return RedirectToAction("Index", "Home");
    }


    [HttpGet("Logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpGet("PublicKey")]
    public Task<IActionResult> GetPublicKey()
    {
        return Task.FromResult<IActionResult>(Ok(Constant.ASymmetricKeys.Values.First()));
    }
}