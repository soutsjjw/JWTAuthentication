using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Models.DataTransferObjects
{
    public class UserForRegistrationDto
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        [Required(ErrorMessage = "UserName 是必須的")] public string UserName { get; set; }
        [Required(ErrorMessage = "Password 是必須的")] public string Password { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public ICollection<string> Roles { get; set; }
    }
}
