using LegalDocumentManager.Data;
using LegalDocumentManager.Models;
using LegalDocumentManager.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using Attachment = LegalDocumentManager.Data.Attachment;

namespace LegalDocumentManager.Controllers;

[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[ApiController]
[Route("api/[controller]")]
public class AttachmentController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly KeyManagementService _keyService;

    public AttachmentController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, KeyManagementService keyService)
    {
        _context = context;
        _userManager = userManager;
        _keyService = keyService;
    }

    [HttpPost("Upload")]
    public async Task<IActionResult> Upload([FromBody] string input)
    {
        try
        {
            var upload = JsonSerializer.Deserialize<UploadViewModel>(await KeyManagementService.DecryptSymmetricAsync(input));

            var user = await _userManager.GetUserAsync(User);

            if (user is null)
                return Unauthorized();

            if (string.IsNullOrWhiteSpace(upload?.EncryptedFile) || string.IsNullOrWhiteSpace(upload.FileName))
                return BadRequest();

            var decryptedFile = Convert.FromBase64String(upload.EncryptedFile);

            var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            if (!Directory.Exists(uploadsPath))
                Directory.CreateDirectory(uploadsPath);

            var fileNameToStore = Path.GetFileNameWithoutExtension(upload.FileName) + Guid.NewGuid().ToString() + Path.GetExtension(upload.FileName);
            var filePath = Path.Combine(uploadsPath, fileNameToStore);

            await System.IO.File.WriteAllBytesAsync(filePath, decryptedFile);

            if (!await ScanService.ScanFileWithWindowsDefenderAsync(Path.GetFullPath(filePath)))
                System.IO.File.Delete(filePath);

            var signature = await _keyService.SignDataAsync(upload.EncryptedFile);

            var attachment = new Attachment
            {
                FilePath = $"/uploads/{fileNameToStore}",
                FileName = upload.FileName,
                UserId = user.Id,
                Signature = Convert.ToBase64String(signature),
                User = user
            };

            _context.Attachments.Add(attachment);
            await _context.SaveChangesAsync();

            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest($"An error occurred: {ex.Message}");
        }
    }

    [HttpGet("List")]
    public async Task<IActionResult> List([FromQuery] string? searchNationalNumber)
    {
        var user = await _userManager.GetUserAsync(User);

        if (user is null)
            return Unauthorized();

        IQueryable<Attachment> attachmentsQuery;

        if (user is GovernmentAccount)
        {
            attachmentsQuery = _context.Attachments.Include(a => a.User);

            if (!string.IsNullOrWhiteSpace(searchNationalNumber))
                attachmentsQuery = attachmentsQuery.Where(a => a.User.Email!.Contains(searchNationalNumber));

            var attachments = await attachmentsQuery.ToListAsync();

            var encAttachments = await KeyManagementService.EncryptSymmetricAsync(JsonSerializer.Serialize(attachments));

            return Ok(encAttachments);
        }

        var userAttachments = await _context.Attachments
            .Where(a => a.UserId == user!.Id)
            .ToListAsync();

        var userEncAttachments = await KeyManagementService.EncryptSymmetricAsync(JsonSerializer.Serialize(userAttachments));

        return Ok(userEncAttachments);
    }

    [HttpGet("Download/{id:int}")]
    public async Task<IActionResult> Download([FromRoute] int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot/{attachment.FilePath}");
        var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);

        var result = new
        {
            FileName = attachment.FileName,
            EncryptedFile = await KeyManagementService.EncryptSymmetricAsync(Convert.ToBase64String(fileBytes)),
            Signature = attachment.Signature
        };

        return Ok(result);
    }

    [HttpGet("GetSignature/{id:int}")]
    public async Task<IActionResult> GetSignature([FromRoute] int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        return Ok(attachment.Signature);
    }

    [HttpPost("Delete/{id:int}")]
    public async Task<IActionResult> Delete([FromRoute] int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot/{attachment.FilePath}");
        System.IO.File.Delete(filePath);

        _context.Attachments.Remove(attachment);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}
