using LegalDocumentManager.Services;
using Microsoft.AspNetCore.Mvc;
using Shared.Encryptions;

namespace LegalDocumentManager.Controllers;

[ApiController]
[Route("api/[Controller]")]
public class KeysController : ControllerBase
{
    private readonly KeyManagementService _keyService;

    public KeysController(KeyManagementService keyManagementService)
    {
        _keyService = keyManagementService;
    }

    [HttpGet("public")]
    public async Task<IActionResult> GetPublicKey(string publickey)
    {
        KeyManagementService.ClientPublicKeyString64 = publickey;
        var publicKey = await _keyService.GetPublicKeyAsync();
        var publicKeyString = Convert.ToBase64String(publicKey.ExportRSAPublicKey());
        return Ok(publicKeyString);
    }

    [HttpGet("symmetric")]
    public async Task<IActionResult> GetSymmetricKey()
    {
        string symmetricKey = KeyManagementService.AESKey;

        var hashedKey = AsymmetricEncryptionService.Encrypt(symmetricKey, KeyManagementService.ClientPublicKeyString64);

        return Ok(hashedKey);
    }
}
