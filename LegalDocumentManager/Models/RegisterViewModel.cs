using System.ComponentModel.DataAnnotations;

namespace LegalDocumentManager.Models;

public class RegisterViewModel
{
    [Required]
    [StringLength(100)]
    public required string FullName { get; set; }

    [Required]
    [StringLength(100)]
    public required string NationalNumber { get; set; }

    [Required]
    [StringLength(100)]
    public required string PhoneNumber { get; set; }

    [Required]
    public DateOnly Birthday { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public required string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public required string ConfirmPassword { get; set; }

    public bool IsGovernmentAccount { get; set; }
}
