using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;
using Shared.Encryptions;
using System.ComponentModel.DataAnnotations;
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
    public async Task<IActionResult> GetPublicKey()
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

    [HttpPost]
    public async Task<IActionResult> SendHashedSymmetricKey([FromBody] HashedSymmetricKey input)
    {
        using RSA rsa = await _keyManagementService.GetPrivateKeyAsync();

        string privateKeyBase64 = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

        var symmetricKey = AsymmetricEncryptionService.Decrypt(input.HashedKey, privateKeyBase64);


    }
}

class HashedSymmetricKey
{
    [Required]
    public string HashedKey { get; set; } = string.Empty;
}