using System.ComponentModel.DataAnnotations;

namespace PaperBoysV2.ViewModels
{
    public class UserRegistrationViewModel
    {
            [Required]
            [Display(Name = "User Name")]
            public required string UserName { get; set; }

            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public required string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public required string Password { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm Password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public required string ConfirmPassword { get; set; }
        
    }
}
