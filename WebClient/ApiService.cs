using WebClient.Models;

namespace WebClient;

public class ApiService
{
    private readonly HttpClient _httpClient;

    public ApiService(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.BaseAddress = new Uri("https://localhost:7011/api/");
    }

    public async Task<string> LoginAsync(LoginViewModel model)
    {
        var response = await _httpClient.PostAsJsonAsync("Account/Login", model);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<LoginResult>();
        if (result is null)
            throw new ArgumentNullException("Login Failed");

        return result.Token;
    }

    public async Task<string> RegisterAsync(RegisterViewModel model)
    {
        var response = await _httpClient.PostAsJsonAsync("Account/Register", model);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<LoginResult>();
        if (result is null)
            throw new ArgumentNullException("Register Failed");

        return result.Token;
    }

    public async Task LogoutAsync()
    {
        await _httpClient.GetAsync("Account/Logout");
    }
}
