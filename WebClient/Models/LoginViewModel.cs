using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebClient.Models;

public class LoginViewModel
{
    [JsonPropertyName("nationalNumber")]
    public string NationalNumber { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }
    
    [JsonPropertyName("rememberMe")]
    public bool RememberMe { get; set; }
}
