namespace WebClient.Components.Layout;

public partial class NavMenu
{
    private bool collapseNavMenu = false; // Ensure the menu is open by default

    private string? NavMenuCssClass => collapseNavMenu ? "show" : "collapse";

    private void ToggleNavMenu()
    {
        collapseNavMenu = !collapseNavMenu;
    }

}
