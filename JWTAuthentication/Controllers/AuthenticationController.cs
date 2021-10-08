using AutoMapper;
using JWTAuthentication.Contracts;
using JWTAuthentication.Models;
using JWTAuthentication.Models.DataTransferObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly ILoggerManager _logger;
        private readonly IMapper _mapper;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuthenticationManager _authManager;

        public AuthenticationController(ILoggerManager logger, IMapper mapper, UserManager<ApplicationUser> userManager,
            IAuthenticationManager authManager)
        {
            _logger = logger;
            _mapper = mapper;
            _userManager = userManager;
            _authManager = authManager;
        }

        /// <summary>
        /// 建立使用者
        /// </summary>
        /// <param name="userForRegistration"></param>
        /// <returns></returns>
        [HttpPost]
        public async Task<IActionResult> RegisterUser([FromBody] UserForRegistrationDto userForRegistration)
        {
            var user = _mapper.Map<ApplicationUser>(userForRegistration);

            var result = await _userManager.CreateAsync(user, userForRegistration.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }

                return BadRequest(ModelState);
            }

            await _userManager.AddToRolesAsync(user, userForRegistration.Roles);

            return StatusCode(201);
        }

        /// <summary>
        /// 登入
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> Authenticate([FromBody] UserForAuthenticationDto user)
        {
            if (!await _authManager.ValidateUser(user))
            {
                _logger.LogWarn($"{nameof(Authenticate)}: 驗證失敗。 錯誤的用戶名或密碼。");
                return Unauthorized();
            }

            return Ok(await _authManager.CreateToken());
        }

        [HttpPost("refreshtoken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestDto tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await _authManager.VerifyAndGenerateToken(tokenRequest);

                if (result == null)
                {
                    _logger.LogWarn($"{nameof(RefreshToken)}: 無效的令牌。");

                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>()
                        {
                            "無效的令牌"
                        },
                        Success = false
                    });
                }

                return Ok(result);
            }

            _logger.LogWarn($"{nameof(RefreshToken)}: 無效的參數。");

            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>()
                {
                    "無效的參數"
                },
                Success = false
            });
        }
    }
}
