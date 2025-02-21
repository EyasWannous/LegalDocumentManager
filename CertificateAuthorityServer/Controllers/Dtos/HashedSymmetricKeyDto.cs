using System.ComponentModel.DataAnnotations;

namespace CertificateAuthorityServer.Controllers.Dtos;

public class HashedSymmetricKeyDto
{
    [Required]
    public string HashedKey { get; set; } = string.Empty;
}