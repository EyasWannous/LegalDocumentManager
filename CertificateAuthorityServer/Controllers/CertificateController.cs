using CertificateAuthorityServer.Controllers.Dtos;
using CertificateAuthorityServer.Data;
using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;
    private readonly ApplicationDbContext _context;

    public CertificateController(KeyManagementService keyManagementService, ApplicationDbContext context)
    {
        _keyManagementService = keyManagementService;
        _context = context;
    }

    //[HttpPost("sign")]
    //public async Task<IActionResult> Sign([FromBody] string data)
    //{
    //    if (string.IsNullOrEmpty(data))
    //        return BadRequest("Data to sign cannot be empty.");

    //    var signature = await _keyManagementService.SignDataAsync(data);
    //    return Ok(new { Signature = Convert.ToBase64String(signature) });
    //}

    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyRequest request)
    {
        if (string.IsNullOrEmpty(request.OriginalData) || string.IsNullOrEmpty(request.Signature))
            return BadRequest("Original data and signature cannot be empty.");

        var serverCert = await _context.ServerCertificates.FirstOrDefaultAsync(x => x.Host == request.Host);

        if (serverCert is null  || serverCert.PublicKey is null)
            return NotFound();

        byte[] signatureBytes = Convert.FromBase64String(request.Signature);

        bool isValid = await _keyManagementService.VerifySignatureAsync(request.OriginalData, signatureBytes, serverCert.PublicKey);
        
        return Ok(new { IsValid = isValid });
    }

    [HttpPost("generate-certificate")]
    public async Task<IActionResult> GenerateCertificate([FromBody] CertificateRequest request)
    {
        if (request is null || string.IsNullOrEmpty(request.ClientPublicKey))
            return BadRequest("Invalid request. A client public key is required.");

        var serverCert = await _context.ServerCertificates.FirstOrDefaultAsync(x => x.Host == HttpContext.Request.Host.Value);

        if (serverCert is null)
            return BadRequest();

        try
        {
            serverCert.Certificate = await _keyManagementService.GenerateCertificateAsync(request);

            await _context.SaveChangesAsync();
             
            return Ok(serverCert.Certificate);
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

    [HttpGet]
    public async Task<IActionResult> GetHostCertificate(string host)
    {
        var certificate = await _context.ServerCertificates.FirstOrDefaultAsync(x => x.Host == host);
        
        if (certificate is null || certificate.Certificate is null)
            return BadRequest("No certificate exists.");

        try
        {
            return Ok(new { certificate.Certificate });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { Error = ex.Message });
        }
    }
}
