using WebClient.Models;

namespace WebClient.Components.Pages;

public partial class Login
{
    private LoginViewModel loginModel = new LoginViewModel();
    private string ErrorMessage = string.Empty; // To store error messages

    private async Task HandleLogin()
    {
        ErrorMessage = string.Empty; // Clear previous error messages

        try
        {
            // Call the API to log in
            var token = await ApiService.LoginAsync(loginModel);

            // Create a user session
            var userSession = new UserSession
            {
                UserName = loginModel.NationalNumber,
                Email = loginModel.NationalNumber,
                Token = token
            };

            // Mark the user as authenticated
            await ((CustomAuthenticationStateProvider)AuthenticationStateProvider).MarkUserAsAuthenticated(userSession);

            // Navigate to the home page
            Navigation.NavigateTo("/");
        }
        catch (HttpRequestException ex)
        {
            // Handle API errors (e.g., 400 Bad Request, 500 Internal Server Error)
            ErrorMessage = $"Login failed: {ex.Message}";
        }
        catch (Exception ex)
        {
            // Handle other exceptions (e.g., network errors)
            ErrorMessage = $"An error occurred: {ex.Message}";
        }
    }
}
