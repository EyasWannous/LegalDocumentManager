using System.ComponentModel.DataAnnotations;

namespace CertificateAuthorityServer.Data;

public class ServerCertificate
{
    public int Id { get; set; }

    [Required]
    public string Host { get; set; }
    public string? Key { get; set; }
    public string PublicKey { get; set; }
    public Certificate? Certificate { get; set; }
}
