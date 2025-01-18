﻿using LegalDocumentManager.Data;
using LegalDocumentManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using LegalDocumentManager.Services;

namespace LegalDocumentManager.Controllers;

[ApiController]
[Route("[Controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly TokenService _tokenService;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        TokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

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

        var token = _tokenService.GenerateToken(user);
        return Ok(new { token });
    }

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

        //await _signInManager.SignInAsync(user, isPersistent: false);

        var token = _tokenService.GenerateToken(user);
        return Ok(new { token });
    }

    [Authorize]
    [HttpGet("Logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return RedirectToAction("Index", "Home");
    }

    [Authorize]
    [HttpGet("PublicKey")]
    public async Task<IActionResult> GetPublicKey()
    {
        var publicKey = await _keyService.GetPublicKeyAsync();
        return Ok(publicKey);
    }
}