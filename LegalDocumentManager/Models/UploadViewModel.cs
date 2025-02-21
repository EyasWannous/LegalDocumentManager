using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace LegalDocumentManager.Models;

public class UploadViewModel
{
    [Required]
    [JsonPropertyName("encryptedFile")]
    public string EncryptedFile { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("fileName")]
    public string FileName { get; set; } = string.Empty;
}