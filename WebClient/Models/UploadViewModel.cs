using System.Text.Json.Serialization;

namespace WebClient.Models;
public class UploadViewModel
{
    [JsonPropertyName("encryptedFile")]
    public string? EncryptedFile { get; set; }

    [JsonPropertyName("fileName")]
    public string? FileName { get; set; }

    public void CheckProperties()
    {
        if (EncryptedFile is null)
            throw new ArgumentNullException(nameof(EncryptedFile));

        if (FileName is null)
            throw new ArgumentNullException(nameof(FileName));
    }
}
