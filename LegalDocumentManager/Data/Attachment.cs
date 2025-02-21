using System.Text.Json.Serialization;

namespace LegalDocumentManager.Data;

public class Attachment
{
    public int Id { get; set; }
    public required string FilePath { get; set; }
    public required string FileName { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;

    [JsonIgnore]
    public required ApplicationUser User { get; set; }
}
