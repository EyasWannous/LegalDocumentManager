using WebClient;
using WebClient.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddScoped<KeyManagementService>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var keyManagementService = scope.ServiceProvider.GetRequiredService<KeyManagementService>();
    await keyManagementService.GenerateKeyPairAsync();
    await keyManagementService.GetServerPublicKeyAsync();
    await keyManagementService.FetchSymmetricKeyAsync();
    Console.WriteLine($"PublicKey: {KeyManagementService.SymmetricKey}");
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
