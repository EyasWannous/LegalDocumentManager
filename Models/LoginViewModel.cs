using System.ComponentModel.DataAnnotations;

namespace LegalDocumentManager.Models;

public class LoginViewModel
{
    [Required]
    [StringLength(100)]
    public required string NationalNumber { get; set; }
    
    [Required]
    [DataType(DataType.Password)]
    public required string Password { get; set; }

    public bool RememberMe { get; set; }
}
