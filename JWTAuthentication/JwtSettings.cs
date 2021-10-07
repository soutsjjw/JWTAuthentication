using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication
{
    public class JwtSettings
    {
        /// <summary>
        /// 發行者
        /// </summary>
        public string Issuer { get; set; }
        /// <summary>
        /// 受眾
        /// </summary>
        public string Audience { get; set; }
        /// <summary>
        /// 密鑰
        /// </summary>
        public string SecretKey { get; set; }
        /// <summary>
        /// 過期時間
        /// </summary>
        public int AccessExpiration { get; set; }
    }
}
