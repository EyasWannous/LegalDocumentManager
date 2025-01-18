﻿using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using LegalDocumentManager.Data;
using LegalDocumentManager.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Shared.Encryptions;
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
    public async Task<IActionResult> Upload([FromBody] UploadViewModel input)
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);

            if (user is null)
            {
                return BadRequest("");
            }

            if (string.IsNullOrWhiteSpace(input.EncryptedFile) || string.IsNullOrWhiteSpace(input.FileName))
            {
                return BadRequest("");
            }

            var encryptionService = new EncryptionAES(KeyManagementService.AESKey);
            var decryptedFileString = await encryptionService.DecryptWithCatchAsync(input.EncryptedFile);
            var decryptedFile = Convert.FromBase64String(decryptedFileString);

            var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            if (!Directory.Exists(uploadsPath))
            {
                Directory.CreateDirectory(uploadsPath);
            }

            var fileNameToStore = Path.GetFileNameWithoutExtension(input.FileName) + Guid.NewGuid().ToString() + Path.GetExtension(input.FileName);
            var filePath = Path.Combine(uploadsPath, fileNameToStore);

            await System.IO.File.WriteAllBytesAsync(filePath, decryptedFile);

            var signature = await _keyService.SignDataAsync(decryptedFileString);

            var attachment = new Attachment
            {
                FilePath = $"/uploads/{input.FileName}",
                FileName = fileNameToStore,
                UserId = user.Id,
                Signature = Convert.ToBase64String(signature)
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
        {
            return Unauthorized();
        }

        IQueryable<Attachment> attachmentsQuery;

        if (user is GovernmentAccount)
        {
            // Allow government accounts to search all users
            attachmentsQuery = _context.Attachments.Include(a => a.User);

            if (!string.IsNullOrWhiteSpace(searchNationalNumber))
            {
                attachmentsQuery = attachmentsQuery.Where(a => a.User.Email!.Contains(searchNationalNumber));
            }
            var attachments = await attachmentsQuery.ToListAsync();

            var encAttachments = _keyService.EncryptSymmetricAsync(JsonSerializer.Serialize(attachments));

            return Ok(attachments);
        }

        var userAttachments = await _context.Attachments
            .Where(a => a.UserId == user!.Id)
            .ToListAsync();

        return Ok(userAttachments);
    }

    [HttpGet("Download")]
    public async Task<IActionResult> Download([FromRoute] int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot/{attachment.FilePath}");
        var fileName = Path.GetFileName(filePath);
        var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);

        return File(fileBytes, "application/octet-stream", fileName);
    }

    [HttpGet("GetSignature")]
    public async Task<IActionResult> GetSignature([FromRoute] int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        return Ok(attachment.Signature);
    }

    [HttpPost("Delete")]
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

public class UploadViewModel
{
    [Required]
    public string EncryptedFile { get; set; }
    
    [Required]
    public string FileName { get; set; }
}