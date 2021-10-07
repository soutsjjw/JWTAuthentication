using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Models.DataTransferObjects
{
    public class UserForAuthenticationDto
    {
        [Required(ErrorMessage = "UserName 是必須的")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Password 是必須的")]
        public string Password { get; set; }
    }
}
