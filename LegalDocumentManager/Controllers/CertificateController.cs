using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LegalDocumentManager.Controllers;

[ApiController]
[Route("api/[Controller]")]
public class CertificateController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public CertificateController(ApplicationDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> GetCertificate()
    {
        return Ok(await _context.Certificates.FirstOrDefaultAsync());
    }
}
