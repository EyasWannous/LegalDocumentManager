using System.ComponentModel.DataAnnotations;

namespace WebClient.Models;

public class LoginViewModel
{
    public string NationalNumber { get; set; }
    public string Password { get; set; }
    public bool RememberMe { get; set; }
}
