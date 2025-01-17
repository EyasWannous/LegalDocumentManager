using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LegalDocumentManager.Data;

public class Certificate
{
    public int Id { get; set; }
    
    [JsonPropertyName("issuedTo")]
    public required string IssuedTo { get; set; }

    [JsonPropertyName("issuedFrom")]
    public required string IssuedFrom { get; set; }

    [JsonPropertyName("issuedAt")]
    public required DateTime IssuedAt { get; set; }

    [JsonPropertyName("expiry")]
    public required DateTime Expiry { get; set; }

    [JsonPropertyName("clientPublicKey")]
    public required string ClientPublicKey { get; set; }

    [JsonPropertyName("signature")]
    public required string Signature { get; set; }
}