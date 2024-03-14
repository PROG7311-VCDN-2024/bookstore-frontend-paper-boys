using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using PaperBoysV2.Models;
using PaperBoysV2.ViewModels;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace PaperBoysV2.Controllers
{
    public class AccountController(PaperBoysDbContext context, ILogger<AccountController> logger) : Controller
    {
        private readonly PaperBoysDbContext _context = context;
        private readonly ILogger<AccountController> _logger = logger;

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
                };

                // Add the user to the database
                _context.Users.Add(newUser);
                _context.SaveChanges();


                TempData["SuccessMessage"] = "Registration successful! You can now log in.";

                // Redirect to login page
                return RedirectToAction("Login");
            }

            return View(model);
        }


        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    // Find the user by email
                    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == model.Email);

                    // If the user is found and the password matches
                    if (user != null && BCrypt.Net.BCrypt.Verify(model.Password, user.Password))
                    {
                        // Retrieve the user's role from the database
                        var userRole = user.UserRole;

                        // Create claims for the user, including the role
                        var claims = new List<Claim>
                {
                    new(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                    new(ClaimTypes.Email, user.Email),
                    new(ClaimTypes.Role, userRole)
                };

                        // Create claims identity
                        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                        // Sign in the user
                        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                        // Log successful login attempt
                        _logger.LogInformation($"User {model.Email} logged in successfully.");

                        // Redirect the user to the home page
                        return RedirectToAction("Index", "Home");
                    }

                    // Failed login attempt
                    _logger.LogWarning($"Failed login attempt for user {model.Email}.");

                    // User not found or wrong password
                    ModelState.AddModelError(string.Empty, "Invalid email or password.");
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError(string.Empty, "An error occurred while processing your request. Please try again later.");
                    _logger.LogError(ex, "An error occurred while processing login request.");
                }
            }

            return View(model);
        }
    }
}
