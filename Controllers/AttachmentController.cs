using LegalDocumentManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
        {
            TempData["Error"] = "Please select a valid file.";
            return View();
        }

        var user = await _userManager.GetUserAsync(User);
        var filePath = Path.Combine("wwwroot/uploads", file.FileName);

        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        var attachment = new Attachment
        {
            FilePath = $"/uploads/{file.FileName}",
            FileName = file.FileName,
            UserId = user!.Id
        };

        _context.Attachments.Add(attachment);
        await _context.SaveChangesAsync();

        TempData["Success"] = "File uploaded successfully.";
        return RedirectToAction("List");
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user is GovernmentAccount)
        {
            var attachments = await _context.Attachments.Include(a => a.User).ToListAsync();
            return View(attachments);
        }
        else
        {
            var attachments = await _context.Attachments.Where(a => a.UserId == user!.Id).ToListAsync();
            return View(attachments);
        }
    }
}
