using System.ComponentModel.DataAnnotations;

namespace CertificateAuthorityServer.Controllers.Dtos;

public class CertificateRequest
{
    [Required]
    public string IssuedTo { get; set; } = string.Empty;

    [Required]
    public DateTime Expiry { get; set; }

    [Required]
    public string ClientPublicKey { get; set; } = string.Empty; // Base64-encoded client public key
}
