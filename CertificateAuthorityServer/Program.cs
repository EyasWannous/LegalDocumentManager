using CertificateAuthorityServer.Data;
using CertificateAuthorityServer.Utilities;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<KeyManagementService>();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("CADB")
);


var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var keyManagementService = scope.ServiceProvider.GetRequiredService<KeyManagementService>();
    await keyManagementService.GenerateKeyPairAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
