using Microsoft.AspNetCore.Identity;

namespace LegalDocumentManager.Data;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; }
    public ICollection<Attachment> Attachments { get; set; }
    public string ClientPublicKey { get; set; }
}
