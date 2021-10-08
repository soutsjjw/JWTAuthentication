using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Models.DataTransferObjects
{
    public class TokenRequestDto
    {
        /// <summary>
        /// 原令牌
        /// </summary>
        [Required]
        public string Token { get; set; }

        /// <summary>
        /// 刷新令牌
        /// </summary>
        [Required]
        public string RefreshToken { get; set; }
    }
}
