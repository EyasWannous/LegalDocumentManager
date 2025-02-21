using WebClient.Models;

namespace WebClient.Components.Pages;

public partial class Register
{
    private RegisterViewModel registerModel = new RegisterViewModel();
    private string ErrorMessage = string.Empty;

    private async Task HandleRegister()
    {
        ErrorMessage = string.Empty; // Clear previous errors

        try
        {
            var token = await ApiService.RegisterAsync(registerModel);

            var userSession = new UserSession { UserName = registerModel.NationalNumber, Email = registerModel.NationalNumber, Token = token };
            await ((CustomAuthenticationStateProvider)AuthenticationStateProvider).MarkUserAsAuthenticated(userSession);

            Navigation.NavigateTo("/");
        }
        catch (HttpRequestException ex)
        {
            ErrorMessage = $"Registration failed: {ex.Message}";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"An error occurred: {ex.Message}";
        }
    }

}
