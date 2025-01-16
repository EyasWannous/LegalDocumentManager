using CertificateAuthorityServer.Utilities;
using Microsoft.AspNetCore.Mvc;

namespace CertificateAuthorityServer.Controllers;

[ApiController]
[Route("[controller]/api")]
public class PublicKeyController : ControllerBase
{
    private readonly KeyManagementService _keyManagementService;

    public PublicKeyController(KeyManagementService keyManagementService)
    {
        _keyManagementService = keyManagementService;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return Ok(_keyManagementService.GetPublicKey());
    }
}
