using CertificateAuthorityServer.Controllers;

namespace CertificateAuthorityServer.Data;

public class ServerCertificate
{
    public int Id { get; set; }
    public string Key { get; set; }
    public Certificate? Certificate { get; set; }
}
