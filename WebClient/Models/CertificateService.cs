namespace WebClient.Models;

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
                throw new ArgumentNullException(nameof(certificate));

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
