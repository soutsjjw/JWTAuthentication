using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuthentication.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string UserId { get; set; } // 連接到 ASP.Net Identity User Id
        public string Token { get; set; }  // Refresh Token
        public string JwtId { get; set; } // 使用 JwtId 映射到對應的 token
        public bool IsUsed { get; set; } // 如果已經使用過它，我們不想使用相同的 refresh token 生成新的 JWT token
        public bool IsRevorked { get; set; } // 是否出於安全原因已將其撤銷
        public DateTime AddedDate { get; set; }
        public DateTime ExpiryDate { get; set; } // refresh token 的生命周期很長，可以持續數月

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }
    }
}
