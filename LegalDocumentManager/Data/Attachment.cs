﻿using System.Text.Json.Serialization;

namespace LegalDocumentManager.Data;

public class Attachment
{
    public int Id { get; set; }
    public required string FilePath { get; set; }
    public required string FileName { get; set; }
    public string UserId { get; set; }
    public string Signature { get; set; }

    [JsonIgnore]
    public ApplicationUser User { get; set; }
}
