using CertificateAuthorityServer.Data;

namespace CertificateAuthorityServer.Utilities;

public class ServerService
{
    private readonly ApplicationDbContext _context;

    public ServerService(ApplicationDbContext context)
    {
        _context = context;
    }

    public bool SaveServerInfo()
}
