using JWTAuthentication.Contracts;
using JWTAuthentication.Models;
using JWTAuthentication.Models.DataTransferObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication
{
    public class AuthenticationManager : IAuthenticationManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _dbContext;
        private readonly TokenValidationParameters _tokenValidationParams;

        private ApplicationUser _user;
        private JwtSettings jwtSettings;

        public AuthenticationManager(UserManager<ApplicationUser> userManager, IConfiguration configuration, ApplicationDbContext dbContex, TokenValidationParameters tokenValidationParams)
        {
            _userManager = userManager;
            _configuration = configuration;
            _dbContext = dbContex;
            _tokenValidationParams = tokenValidationParams;

            jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>();
        }

        public async Task<bool> ValidateUser(UserForAuthenticationDto userForAuth)
        {
            _user = await _userManager.FindByNameAsync(userForAuth.UserName);

            return (_user != null && await _userManager.CheckPasswordAsync(_user, userForAuth.Password));
        }

        public async Task<AuthResult> CreateToken(ApplicationUser dbUser = null)
        {
            if (_user == null && dbUser != null)
                _user = dbUser;

            var signingCredentials = GetSigningCredentials();
            var claims = await GetClaims();
            var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtTokenHandler.WriteToken(tokenOptions);

            var refreshToken = new RefreshToken()
            {
                JwtId = tokenOptions.Id,
                IsUsed = false,
                IsRevorked = false,
                UserId = _user.Id,
                AddedDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddMinutes(6),
                Token = RandomString(35) + Guid.NewGuid()
            };

            var entities = _dbContext.RefreshTokens.Where(x => x.UserId == _user.Id && x.IsRevorked == false).AsNoTracking();
            if (entities.Any())
            {
                var userId = new Microsoft.Data.SqlClient.SqlParameter("UserId", _user.Id);
                _dbContext.Database.ExecuteSqlRaw("UPDATE [RefreshTokens] SET IsRevorked = 1 WHERE UserId = @userId; ", userId);
            }

            await _dbContext.RefreshTokens.AddAsync(refreshToken);
            await _dbContext.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        private SigningCredentials GetSigningCredentials()
        {
            //var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"));
            var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
            var secret = new SymmetricSecurityKey(key);

            return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
        }

        private async Task<List<Claim>> GetClaims()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, _user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var roles = await _userManager.GetRolesAsync(_user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            var tokenOptions = new JwtSecurityToken
            (
                issuer: jwtSettings.Issuer,
                audience: jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(jwtSettings.AccessExpiration),
                signingCredentials: signingCredentials
            );

            return tokenOptions;
        }

        private string RandomString(int length)
        {
            var random = System.Security.Cryptography.RandomNumberGenerator.Create();
            byte[] number = new byte[length];
            random.GetBytes(number);
            return BitConverter.ToString(number).Replace("-", "");
        }

        public async Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                // Validation 1 - Validation JWT token format
                // 此驗證功能將確保 Token 滿足驗證參數，並且它是一個真正的 token 而不僅僅是隨機字符串
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validatedToken);

                // Validation 2 - Validate encryption alg
                // 檢查 token 是否有有效的安全算法
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (result == false)
                    {
                        return null;
                    }
                }

                // Validation 3 - validate expiry date
                // 驗證原 token 的過期時間，得到 unix 時間戳
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.Now)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "令牌尚未過期"
                        }
                    };
                }

                // validation 4 - validate existence of the token
                // 驗證 refresh token 是否存在，是否是保存在數據庫的 refresh token
                var storedRefreshToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedRefreshToken == null)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "刷新令牌不存在"
                        }
                    };
                }

                // Validation 5 - 檢查存儲的 RefreshToken 是否已過期
                // Check the date of the saved refresh token if it has expired
                if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
                {
                    return new AuthResult()
                    {
                        Errors = new List<string>() { "刷新令牌已過期，使用者需要重新登入" },
                        Success = false
                    };
                }

                // Validation 6 - validate if used
                // 驗證 refresh token 是否已使用
                if (storedRefreshToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "刷新令牌已被使用"
                        }
                    };
                }

                // Validation 7 - validate if revoked
                // 檢查 refresh token 是否被撤銷
                if (storedRefreshToken.IsRevorked)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "刷新令牌已被撤銷"
                        }
                    };
                }

                // Validation 8 - validate the id
                // 這裡獲得原 JWT token Id
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                // 根據數據庫中保存的 Id 驗證收到的 token 的 Id
                if (storedRefreshToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "令牌與保存的令牌不匹配"
                        }
                    };
                }

                // update current token 
                // 將該 refresh token 設置為已使用
                storedRefreshToken.IsUsed = true;
                _dbContext.RefreshTokens.Update(storedRefreshToken);
                await _dbContext.SaveChangesAsync();

                // 生成一個新的 token
                var dbUser = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
                return await CreateToken(dbUser);
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("Lifetime validation failed. The token is expired."))
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "令牌已過期請重新登入"
                        }
                    };
                }
                else
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "出現其他問題"
                        }
                    };
                }
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTimeVal;
        }
    }
}
