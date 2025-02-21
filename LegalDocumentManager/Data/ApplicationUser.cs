using Microsoft.AspNetCore.Identity;

namespace LegalDocumentManager.Data;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
    public ICollection<Attachment> Attachments { get; set; } = [];
}
