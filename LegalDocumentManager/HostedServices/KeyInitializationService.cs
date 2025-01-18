using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json;
using LegalDocumentManager.Data;
using LegalDocumentManager.Services;
using Shared.Encryptions;

namespace LegalDocumentManager.HostedServices;

public class KeyInitializationService : IHostedService
{
    private readonly HttpClient _httpClient;
    private readonly IServiceProvider _serviceProvider;
    private readonly KeyManagementService _keyService;

    public KeyInitializationService(IHttpClientFactory httpClientFactory, IServiceProvider serviceProvider, KeyManagementService keyService)
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.BaseAddress = new Uri("https://localhost:7154/api/");

        _serviceProvider = serviceProvider;
        _keyService = keyService;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var myPublicKey = await _keyService.GetPublicKeyAsync();

        var publicKeyResponse = await _httpClient.GetAsync($"Key?publicKey={myPublicKey}", cancellationToken);
        if (!publicKeyResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't get public key from CA");

        var publicKeyResult = await publicKeyResponse.Content.ReadAsStringAsync(cancellationToken);

        string symmetricKey = KeyManagementService.AESKey;
        string encryptedSymmetricKey = AsymmetricEncryptionService.Encrypt(symmetricKey, publicKeyResult);

        var hashedKey = new {
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
        
        var certificateRequest = new {
            issuedTo = "Syria.org.sy", 
            expiry = DateTime.Now.AddYears(10),
            clientPublicKey = myPublicKey,
        };

        content = new StringContent(
            JsonSerializer.Serialize(certificateRequest),
            Encoding.UTF8,
            "application/json"
        );

        var certificateResponse = await _httpClient.PostAsync("Certificate/generate-certificate", content, cancellationToken);
        if (!certificateResponse.IsSuccessStatusCode)
            throw new Exception("Couldn't get certificate from CA");

        var certificateResult = await certificateResponse.Content.ReadAsStringAsync(cancellationToken);

        var certificate = JsonSerializer.Deserialize<Certificate>(certificateResult);
        if (certificate is null)
            throw new Exception("Couldn't deserialize certificate");

        using (var scope = _serviceProvider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
         
            await context.Certificates.AddAsync(certificate, cancellationToken);
            await context.SaveChangesAsync(cancellationToken);
        }

    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        // Cleanup logic (if needed)
        return Task.CompletedTask;
    }
}
