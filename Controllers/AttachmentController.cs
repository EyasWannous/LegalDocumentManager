using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Attachment = LegalDocumentManager.Data.Attachment;

namespace LegalDocumentManager.Controllers;

[Authorize]
public class AttachmentController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public AttachmentController(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    [HttpGet]
    public async Task<IActionResult> Upload()
    {
        return await Task.FromResult(View());
    }

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);

            if (user is null)
            {
                TempData["Error"] = "You must be logged in to upload files.";
                return RedirectToAction(nameof(AccountController.Login), "Account");
            }

            if (file is null || file.Length == 0)
            {
                TempData["Error"] = "Please select a valid file.";
                return View();
            }

            var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            if (!Directory.Exists(uploadsPath))
            {
                Directory.CreateDirectory(uploadsPath);
            }

            var fileName = file.FileName.Split('.').First() 
                + Guid.NewGuid().ToString() 
                + '.' 
                + file.FileName.Split('.').Last();
            
            var filePath = Path.Combine(uploadsPath, fileName);
            
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            var attachment = new Attachment
            {
                FilePath = $"/uploads/{fileName}",
                FileName = file.FileName,
                UserId = user.Id
            };

            _context.Attachments.Add(attachment);
            await _context.SaveChangesAsync();

            TempData["Success"] = "File uploaded successfully.";
            return RedirectToAction(nameof(List));
        }
        catch (Exception ex)
        {
            TempData["Error"] = $"An error occurred: {ex.Message}";
            return View();
        }
    }

    [HttpGet]
    public async Task<IActionResult> List(string searchNationalNumber)
    {
        var user = await _userManager.GetUserAsync(User);

        if (user is null)
        {
            TempData["Error"] = "You must be logged in to view attachments.";
            return RedirectToAction(nameof(AccountController.Login), "Account");
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

            // Pass search query back to the view for user feedback
            ViewData["SearchQuery"] = searchNationalNumber;

            return View(attachments);
        }
        var userAttachments = await _context.Attachments.Where(a => a.UserId == user!.Id).ToListAsync();

        return View(userAttachments);
    }

    public async Task<IActionResult> Download(int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot/{attachment.FilePath}");
        //var filePath = attachment.FilePath;
        var fileName = Path.GetFileName(filePath);
        var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);

        return File(fileBytes, "application/octet-stream", fileName);
    }


    [HttpPost]
    public async Task<IActionResult> Delete(int id)
    {
        var attachment = await _context.Attachments.FindAsync(id);
        if (attachment is null)
            return NotFound();

        var filePath = Path.Combine(Directory.GetCurrentDirectory(), $"wwwroot/{attachment.FilePath}");
        System.IO.File.Delete(filePath);

        _context.Attachments.Remove(attachment);
        await _context.SaveChangesAsync();

        TempData["Success"] = "File deleted successfully.";
        return RedirectToAction(nameof(List));
    }

}
