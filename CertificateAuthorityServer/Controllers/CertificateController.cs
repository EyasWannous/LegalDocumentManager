using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private static X509Certificate2 _caCertificate;

    static CertificateController()
    {
        // Create or load a self-signed root CA certificate for the server
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=MyCertificateAuthority", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddYears(10);

        _caCertificate = request.CreateSelfSigned(notBefore, notAfter);
    }

    [HttpPost("sign-document")]
    public IActionResult SignDocument([FromBody] string document)
    {
        if (string.IsNullOrEmpty(document))
        {
            return BadRequest("Document cannot be null or empty.");
        }

        var documentBytes = Encoding.UTF8.GetBytes(document);

        using var rsa = _caCertificate.GetRSAPrivateKey();
        var signedBytes = rsa.SignData(documentBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var signedBase64 = Convert.ToBase64String(signedBytes);

        return Ok(new { SignedDocument = signedBase64 });
    }

    [HttpPost("verify-document")]
    public IActionResult VerifyDocument([FromBody] VerificationRequest request)
    {
        if (string.IsNullOrEmpty(request.Document) || string.IsNullOrEmpty(request.SignedDocument))
        {
            return BadRequest("Invalid request.");
        }

        var documentBytes = Encoding.UTF8.GetBytes(request.Document);
        var signedBytes = Convert.FromBase64String(request.SignedDocument);

        using var rsa = _caCertificate.GetRSAPublicKey();
        var isValid = rsa.VerifyData(documentBytes, signedBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return Ok(new { IsValid = isValid });
    }

    public class VerificationRequest
    {
        public string Document { get; set; }
        public string SignedDocument { get; set; }
    }
}
