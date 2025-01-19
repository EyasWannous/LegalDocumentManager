using LegalDocumentManager.Data;
using LegalDocumentManager.Services;
using Shared.Encryptions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LegalDocumentManager.HostedServices;

public class KeyInitializationService : IHostedService
{
    private readonly HttpClient _httpClient;
    private readonly IServiceProvider _serviceProvider;

    public KeyInitializationService(IHttpClientFactory httpClientFactory, IServiceProvider serviceProvider)
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.BaseAddress = new Uri("https://localhost:7154/api/");

        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var keyService = scope.ServiceProvider.GetRequiredService<KeyManagementService>();

        RSA myKey = await keyService.GetPublicKeyAsync();

        var myPublicKeyBytes = myKey.ExportRSAPublicKey();
        var myPublicKey = Convert.ToBase64String(myPublicKeyBytes);

        var publicKeyResponse = await _httpClient.GetAsync($"Key?publicKey={myPublicKey}", cancellationToken);

        if (!publicKeyResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't get public key from CA");

        var publicKeyResult = await publicKeyResponse.Content.ReadAsStringAsync(cancellationToken);

        string symmetricKey = KeyManagementService.AESKey;
        string encryptedSymmetricKey = AsymmetricEncryptionService.Encrypt(symmetricKey, publicKeyResult);

        var hashedKey = new
        {
            hashedKey = encryptedSymmetricKey
        };

        var content = new StringContent(
            JsonSerializer.Serialize(hashedKey),
            Encoding.UTF8,
            "application/json"
        );

        var sendKeyResponse = await _httpClient.PostAsync("Key", content, cancellationToken);

        if (!sendKeyResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't send key to CA");

        var certificateRequest = new
        {
            issuedTo = "Syria.org.sy",
            expiry = DateTime.Now.AddYears(10),
            clientPublicKey = myPublicKey,
        };

        var certificateRequestContent = new StringContent(
            JsonSerializer.Serialize(certificateRequest),
            Encoding.UTF8,
            "application/json"
        );

        var certificateResponse = await _httpClient.PostAsync("Certificate/generate-certificate", certificateRequestContent, cancellationToken);
        if (!certificateResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't get certificate from CA");

        var certificateResult = await certificateResponse.Content.ReadAsStringAsync(cancellationToken);

        var certificate = JsonSerializer.Deserialize<Certificate>(certificateResult);
        if (certificate is null)
            throw new Exception("Couldn't deserialize certificate");

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await context.Certificates.AddAsync(certificate, cancellationToken);
        await context.SaveChangesAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // Cleanup logic (if needed)
        return Task.CompletedTask;
    }
}
