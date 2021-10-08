using JWTAuthentication.Models;
using JWTAuthentication.Models.DataTransferObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Contracts
{
    public interface IAuthenticationManager
    {
        /// <summary>
        /// 驗證登入資料
        /// </summary>
        /// <param name="userForAuth"></param>
        /// <returns></returns>
        Task<bool> ValidateUser(UserForAuthenticationDto userForAuth);

        Task<AuthResult> CreateToken(ApplicationUser dbUser = null);

        Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto tokenRequest);
    }
}
