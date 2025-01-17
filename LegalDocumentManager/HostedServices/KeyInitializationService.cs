using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LegalDocumentManager.Data;
using Shared.Encryptions;

namespace LegalDocumentManager.HostedServices;

public class KeyInitializationService : IHostedService
{
    private readonly HttpClient _httpClient;

    public KeyInitializationService(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.BaseAddress = new Uri("https://localhost:7154/");
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var publicKeyResponse = await _httpClient.GetAsync("api/Key", cancellationToken);
        if (!publicKeyResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't get public key from CA");

        var publicKeyResult = await publicKeyResponse.Content.ReadAsStringAsync(cancellationToken);
        Console.WriteLine($"Public Key: {publicKeyResult}");

        string symmetricKey = Constant.AESKey;
        string encryptedSymmetricKey = AsymmetricEncryptionService.Encrypt(symmetricKey, publicKeyResult);

        var hashedKey = new {
            hashedKey = encryptedSymmetricKey 
        };
        var content = new StringContent(
            JsonSerializer.Serialize(hashedKey),
            Encoding.UTF8,
            "application/json"
        );

        var sendKeyResponse = await _httpClient.PostAsync("api/Key", content, cancellationToken);

        if (!sendKeyResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't send key to CA");
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // Cleanup logic (if needed)
        return Task.CompletedTask;
    }
}
