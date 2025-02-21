using System.Text.Json.Serialization;

namespace WebClient.Models;

public class DownloadViewModel
{
    [JsonPropertyName("encryptedFile")]
    public string? EncryptedFile { get; set; }

    [JsonPropertyName("fileName")]
    public string? FileName { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    public void CheckProperties()
    {
        if (EncryptedFile is null)
            throw new ArgumentNullException(nameof(EncryptedFile));

        if (FileName is null)
            throw new ArgumentNullException(nameof(FileName));

        if (Signature is null)
            throw new ArgumentNullException(nameof(Signature));
    }
}