using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Mvc;

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
            "CN=MyCertificateAuthority", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1
        );

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true)
        );

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)
        );

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
        if (rsa is null)
            return BadRequest("Invalid request.");

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
        byte[] signedBytes;
        try
        {
            signedBytes = Convert.FromBase64String(request.SignedDocument);
        }
        catch (Exception)
        {
            return BadRequest("Invalid request.");
        }

        using var rsa = _caCertificate.GetRSAPublicKey();
        if (rsa is null)
            return BadRequest("Invalid request.");

        var isValid = rsa.VerifyData(documentBytes, signedBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return Ok(new { IsValid = isValid });
    }

    public async Task Test()
    {
        using RSA parent = RSA.Create(4096);
        using RSA rsa = RSA.Create(2048);
        
        var parentReq = new CertificateRequest(
            "CN=Experimental Issuing Authority",
            parent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        parentReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true)
        );

        parentReq.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false)
        );

        using X509Certificate2 parentCert = parentReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-45),
            DateTimeOffset.UtcNow.AddDays(365)
        );
        
        var req = new CertificateRequest(
            "CN=Valid-Looking Timestamp Authority",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                false
            )
        );

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [
                    new Oid("1.3.6.1.5.5.7.3.8")
                ],
                true
            )
        );

        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, false)
        );

        using X509Certificate2 cert = req.Create(
            parentCert,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90),
            [1, 2, 3, 4]
        );

        // Do something with these certs, like export them to PFX,
        // or add them to an X509Store, or whatever.

        var store = new X509Store();
    }

    public class VerificationRequest
    {
        public string Document { get; set; } = string.Empty;
        public string SignedDocument { get; set; } = string.Empty;
    }
}
