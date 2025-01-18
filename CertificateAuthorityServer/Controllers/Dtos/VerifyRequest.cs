using System.ComponentModel.DataAnnotations;

namespace CertificateAuthorityServer.Controllers.Dtos;

public class VerifyRequest
{
    [Required]
    public string OriginalData { get; set; } = string.Empty;

    [Required]
    public string Signature { get; set; } = string.Empty;

    [Required]
    public string Host { get; set; } = string.Empty;
}
