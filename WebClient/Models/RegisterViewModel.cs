using System.Text.Json.Serialization;

namespace WebClient.Models;

public class RegisterViewModel
{
    [JsonPropertyName("fullName")]
    public string FullName { get; set; }

    [JsonPropertyName("nationalNumber")]
    public string NationalNumber { get; set; }

    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; set; }

    [JsonPropertyName("birthday")]
    public DateOnly Birthday { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }

    [JsonPropertyName("confirmPassword")]
    public string ConfirmPassword { get; set; }

    [JsonPropertyName("isGovernmentAccount")]
    public bool IsGovernmentAccount { get; set; }
}
