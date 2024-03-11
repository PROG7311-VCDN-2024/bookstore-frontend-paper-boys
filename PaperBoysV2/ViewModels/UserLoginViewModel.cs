using System.ComponentModel.DataAnnotations;

namespace PaperBoysV2.ViewModels
{
    public class UserLoginViewModel
    {
        [Required(ErrorMessage = "Please enter your email.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Please enter your password.")]
        [DataType(DataType.Password)]
        public required string Password { get; set; }
    }
}
