using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace CertificateAuthorityServer.Data;

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