using Microsoft.EntityFrameworkCore;

namespace CertificateAuthorityServer.Data;

public class ApplicationDbContext(DbContextOptions options) : DbContext(options)
{
    public DbSet<ServerCertificate> ServerCertificates { get; set; }
}
