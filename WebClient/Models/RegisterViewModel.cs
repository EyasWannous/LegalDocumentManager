using System.ComponentModel.DataAnnotations;

namespace WebClient.Models;

public class RegisterViewModel
{
    public string FullName { get; set; }
    public string NationalNumber { get; set; }
    public string PhoneNumber { get; set; }
    public DateOnly Birthday { get; set; }
    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
    public bool IsGovernmentAccount { get; set; }

}
