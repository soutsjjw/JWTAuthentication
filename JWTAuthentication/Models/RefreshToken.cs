using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace JWTAuthentication.Models
{
    public class RefreshToken
    {
        /// <summary>
        /// 電腦編號
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// 使用者 Id
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// 刷新 Token
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// 使用 JwtId 映射到對應的 token
        /// </summary>
        public string JwtId { get; set; }

        /// <summary>
        /// 是否已使用
        /// </summary>
        public bool IsUsed { get; set; }

        /// <summary>
        /// 是否已撤銷
        /// </summary>
        public bool IsRevorked { get; set; }

        /// <summary>
        /// 建立日期
        /// </summary>
        public DateTime AddedDate { get; set; }

        /// <summary>
        /// 到期日期期
        /// </summary>
        public DateTime ExpiryDate { get; set; }

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }
    }
}
