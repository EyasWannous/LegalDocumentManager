using System.ComponentModel.DataAnnotations;
using System.Text.Json;
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
    public async Task<IActionResult> Sign([FromBody] string data)
    {
        if (string.IsNullOrEmpty(data))
            return BadRequest("Data to sign cannot be empty.");

        var signature = await _keyManagementService.SignDataAsync(data);
        return Ok(new { Signature = Convert.ToBase64String(signature) });
    }

    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest request)
    {
        if (string.IsNullOrEmpty(request.OriginalData) || string.IsNullOrEmpty(request.Signature))
            return BadRequest("Original data and signature cannot be empty.");

        byte[] signatureBytes = Convert.FromBase64String(request.Signature);
        bool isValid = await _keyManagementService.VerifySignatureAsync(request.OriginalData, signatureBytes);
        
        return Ok(new { IsValid = isValid });
    }

    [HttpPost("generate-certificate")]
    public async Task<IActionResult> GenerateCertificate([FromBody] CertificateRequest request)
    {
        if (request == null || string.IsNullOrEmpty(request.ClientPublicKey))
            return BadRequest("Invalid request. A client public key is required.");

        try
        {
            var certificate = await _keyManagementService.GenerateCertificateAsync(request);
            return Ok(certificate);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("validate-certificate")]
    public async Task<IActionResult> ValidateCertificate([FromBody] Certificate certificate)
    {
        if (certificate == null || string.IsNullOrEmpty(certificate.Signature))
            return BadRequest("Invalid certificate. A valid signature is required.");

        try
        {
            bool isValid = await _keyManagementService.ValidateCertificateAsync(certificate);
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
    [Required]
    public string OriginalData { get; set; } = string.Empty;

    [Required]
    public string Signature { get; set; } = string.Empty;
}

public class CertificateRequest
{
    [Required]
    public string IssuedTo { get; set; } = string.Empty;

    [Required]
    public DateTime Expiry { get; set; }

    [Required]
    public string ClientPublicKey { get; set; } = string.Empty; // Base64-encoded client public key
}

public class Certificate
{
    [Required]
    public string IssuedTo { get; set; } = string.Empty;

    [Required]
    public string IssuedFrom { get; set; } = string.Empty;

    [Required]
    public DateTime IssuedAt { get; set; }

    [Required]
    public DateTime Expiry { get; set; }

    [Required]
    public string ClientPublicKey { get; set; } = string.Empty;

    [Required]
    public string Signature { get; set; } = string.Empty; // CA's signature for the certificate

    public override string ToString()
    {
        return JsonSerializer.Serialize(this);
    }

    public static Certificate? FromString(string str)
    {
        return JsonSerializer.Deserialize<Certificate>(str);
    }
}