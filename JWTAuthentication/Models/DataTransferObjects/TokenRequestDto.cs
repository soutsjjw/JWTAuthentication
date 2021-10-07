using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Models.DataTransferObjects
{
    public class TokenRequestDto
    {
        /// <summary>
        /// 原 Token
        /// </summary>
        [Required]
        public string Token { get; set; }
        /// <summary>
        /// Refresh Token
        /// </summary>
        [Required]
        public string RefreshToken { get; set; }
    }
}
