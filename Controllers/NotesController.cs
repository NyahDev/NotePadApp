using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NotePadApp.Data;
using NotePadApp.Models;
using System.Security.Claims;

namespace NotePadApp.Controllers
{
    public class NotesController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly NotePadDbContext _context;

        public NotesController(UserManager<User> userManager, NotePadDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }
        // Display the editable page (Home/Index)
        public IActionResult Index()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var note = _context.Notes.FirstOrDefault(n => n.UserId == userId);

            if (note == null)
            {
                // If no note exists, create a new one
                note = new Note
                {
                    UserId = userId
                };

                _context.Notes.Add(note);
                _context.SaveChanges();
            }

            return View(note);
        }


        // Handle the saving of a note
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(int id, string content)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var note = _context.Notes.FirstOrDefault(n => n.Id == id && n.UserId == userId);

            if (note == null)
            {
                return NotFound();
            }

            note.Content = content;

            _context.Notes.Update(note);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index");
        }

        // Your other controller actions for viewing, saving to local drive, etc.

        // Add these actions for viewing and saving notes to local drive
    }
}