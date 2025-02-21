using System.Text.Json.Serialization;

namespace WebClient.Models;

public class RegisterViewModel
{
    [JsonPropertyName("fullName")]
    public string FullName { get; set; } = string.Empty;

    [JsonPropertyName("nationalNumber")]
    public string NationalNumber { get; set; } = string.Empty;

    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; set; } = string.Empty;

    [JsonPropertyName("birthday")]
    public DateOnly Birthday { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("confirmPassword")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [JsonPropertyName("isGovernmentAccount")]
    public bool IsGovernmentAccount { get; set; }
}
