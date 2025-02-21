namespace WebClient.Models;

public class Attachment
{
    public int Id { get; set; }
    public required string FilePath { get; set; }
    public required string FileName { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
}
