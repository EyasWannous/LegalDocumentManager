using System.Text.Json.Serialization;

namespace WebClient.Models;

public class LoginViewModel
{
    [JsonPropertyName("nationalNumber")]
    public string NationalNumber { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("rememberMe")]
    public bool RememberMe { get; set; }
}
