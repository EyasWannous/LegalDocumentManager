namespace WebClient.Components.Layout;

public partial class MainLayout
{
    private async Task Logout()
    {
        await ((CustomAuthenticationStateProvider)AuthenticationStateProvider).MarkUserAsLoggedOut();
        Navigation.NavigateTo("/login");
    }

}
