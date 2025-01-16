using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PublicKeyController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;

    public PublicKeyController(KeyManagementService keyManagementService)
    {
        _keyManagementService = keyManagementService;
    }

    [HttpGet]
    public IActionResult Get()
    {
        try
        {
            using (RSA rsa = _keyManagementService.GetPublicKey())
            {
                string publicKeyBase64 = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
                return Ok(new { PublicKey = publicKeyBase64 });
            }
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = "Failed to retrieve public key.", Message = ex.Message });
        }
    }
}
