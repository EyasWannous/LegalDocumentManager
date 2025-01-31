using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace CertificateAuthorityServer.Data;

public class ApplicationDbContext(DbContextOptions options) : DbContext(options)
{
    public DbSet<ServerCertificate> ServerCertificates { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ServerCertificate>(model =>
        {
            model.HasKey(x => x.Id);

            model.Property(x => x.Certificate)
                .HasConversion(
                    certificate => certificate == null ? string.Empty : certificate.ToString(),
                    str => str == string.Empty ? null : Certificate.FromString(str)
                )
                .IsRequired(false);
        });
    }
}
