using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class KeyController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;

    public KeyController(KeyManagementService keyManagementService)
    {
        _keyManagementService = keyManagementService;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        try
        {
            using RSA rsa = await _keyManagementService.GetPublicKeyAsync();

            string publicKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            return Ok(new { PublicKey = publicKeyBase64 });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = "Failed to retrieve public key.", ex.Message });
        }
    }
}
