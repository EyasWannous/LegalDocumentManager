using System.Text.Json.Serialization;

namespace WebClient;

public class CertificateService
{
    private readonly HttpClient _httpClient;
    public static Certificate? Certificate;

    public CertificateService(HttpClient httpClient)
    {
        _httpClient = httpClient;

        _httpClient.BaseAddress = new Uri("https://localhost:7011/api/");
    }

    public async Task GetCertificateAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("certificate");

            response.EnsureSuccessStatusCode();

            var certificate = await response.Content.ReadFromJsonAsync<Certificate>();
            if (certificate is null)
                throw new ArgumentNullException();

            Certificate = certificate;
        }
        catch (HttpRequestException ex)
        {
            throw new Exception(ex.Message);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }
}

public class Certificate
{
    public int Id { get; set; }

    [JsonPropertyName("issuedTo")]
    public required string IssuedTo { get; set; }

    [JsonPropertyName("issuedFrom")]
    public required string IssuedFrom { get; set; }

    [JsonPropertyName("issuedAt")]
    public required DateTime IssuedAt { get; set; }

    [JsonPropertyName("expiry")]
    public required DateTime Expiry { get; set; }

    [JsonPropertyName("clientPublicKey")]
    public required string ClientPublicKey { get; set; }

    [JsonPropertyName("signature")]
    public required string Signature { get; set; }
}
