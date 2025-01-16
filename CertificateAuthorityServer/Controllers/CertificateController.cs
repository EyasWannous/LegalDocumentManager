using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;

    public CertificateController(KeyManagementService keyManagementService)
    {
        _keyManagementService = keyManagementService;
    }

    [HttpPost("sign")]
    public IActionResult Sign([FromBody] string data)
    {
        if (string.IsNullOrEmpty(data))
            return BadRequest("Data to sign cannot be empty.");

        var signature = _keyManagementService.SignData(data);
        return Ok(new { Signature = Convert.ToBase64String(signature) });
    }

    [HttpPost("verify")]
    public IActionResult Verify([FromBody] VerifyRequest request)
    {
        if (string.IsNullOrEmpty(request.OriginalData) || string.IsNullOrEmpty(request.Signature))
            return BadRequest("Original data and signature cannot be empty.");

        byte[] signatureBytes = Convert.FromBase64String(request.Signature);
        bool isValid = _keyManagementService.VerifySignature(request.OriginalData, signatureBytes);
        return Ok(new { IsValid = isValid });
    }

    [HttpPost("generate-certificate")]
    public IActionResult GenerateCertificate([FromBody] CertificateRequest request)
    {
        if (request == null || string.IsNullOrEmpty(request.ClientPublicKey))
        {
            return BadRequest("Invalid request. A client public key is required.");
        }

        try
        {
            var certificate = _keyManagementService.GenerateCertificate(request);
            return Ok(certificate);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("validate-certificate")]
    public IActionResult ValidateCertificate([FromBody] Certificate certificate)
    {
        if (certificate == null || string.IsNullOrEmpty(certificate.Signature))
        {
            return BadRequest("Invalid certificate. A valid signature is required.");
        }

        try
        {
            bool isValid = _keyManagementService.ValidateCertificate(certificate);
            return Ok(new { IsValid = isValid });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { Error = ex.Message });
        }
    }
}

public class VerifyRequest
{
    public string OriginalData { get; set; }
    public string Signature { get; set; }
}

public class CertificateRequest
{
    public string IssuedTo { get; set; }
    public DateTime Expiry { get; set; }
    public string ClientPublicKey { get; set; } // Base64-encoded client public key
}

public class Certificate
{
    public string IssuedTo { get; set; }
    public string IssuedFrom { get; set; }
    public DateTime IssuedAt { get; set; }
    public DateTime Expiry { get; set; }
    public string ClientPublicKey { get; set; }
    public string Signature { get; set; } // CA's signature for the certificate
}