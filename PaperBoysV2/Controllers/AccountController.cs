using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using PaperBoysV2.Models;
using PaperBoysV2.ViewModels;

namespace PaperBoysV2.Controllers
{
    public class AccountController : Controller
    {
        private readonly PaperBoysDbContext _context;

        public AccountController(PaperBoysDbContext context)
        {
            _context = context;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(UserRegistrationViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Check Unique Email
                var existingUser = _context.Users.FirstOrDefault(u => u.Email == model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError(string.Empty, "Email is already registered.");
                    return View(model);
                }

                // passwordHash
                string hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password);

                //new User entity
                var newUser = new User
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    Password = hashedPassword,
                    Role = false
                };

                // Add the new user to the database
                _context.Users.Add(newUser);
                _context.SaveChanges();


                TempData["SuccessMessage"] = "Registration successful! You can now log in.";

                // Redirect to login page and begin session
                return RedirectToAction("Login");
            }

            return View(model);
        }

    }
}
