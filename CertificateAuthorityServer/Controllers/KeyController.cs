using CertificateAuthorityServer.Data;
using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Shared.Encryptions;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class KeyController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;
    private readonly ApplicationDbContext _context;

    public KeyController(KeyManagementService keyManagementService, ApplicationDbContext context)
    {
        _keyManagementService = keyManagementService;
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> GetPublicKey([FromQuery] string publicKey)
    {
        try
        {
            await _context.ServerCertificates.AddAsync(
                new ServerCertificate
                {
                    Host = HttpContext.Request.Host.Value,
                    PublicKey = publicKey,
                }
            );

            await _context.SaveChangesAsync();

            using RSA rsa = await _keyManagementService.GetPublicKeyAsync();

            string publicKeyBase64 = Convert.ToBase64String(rsa.ExportRSAPublicKey());

            return Ok(publicKeyBase64);
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = "Failed to retrieve public key.", ex.Message });
        }
    }

    [HttpPost]
    public async Task<IActionResult> SendHashedSymmetricKey([FromBody] HashedSymmetricKey input)
    {
        var serverCert = await _context.ServerCertificates.FirstOrDefaultAsync(x => x.Host == HttpContext.Request.Host.Value);

        if (serverCert is null)
            return BadRequest();

        using RSA rsa = await _keyManagementService.GetPrivateKeyAsync();

        string privateKeyBase64 = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

        var symmetricKey = AsymmetricEncryptionService.Decrypt(input.HashedKey, privateKeyBase64);

        serverCert.Key = symmetricKey;

        await _context.SaveChangesAsync();

        return Ok();
    }

    [HttpGet("generate-Keys")]
    public async Task<IActionResult> GenerateKeys()
    {
        await _keyManagementService.GenerateKeyPairAsync();

        return Ok();
    }
}

public class HashedSymmetricKey
{
    [Required]
    public string HashedKey { get; set; } = string.Empty;
}