# JWT 認證實作

## 設置資料庫

建立 User 類別
```CSharp
public class User : IdentityUser
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
}
```

添加套件
```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore
```

建立 DbContext
```CSharp
public class ApplicationDbContext : IdentityDbContext<User>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
    }
}
```

設置連線字串
```xml
"ConnectionStrings": {
    "sqlConnection": "server=.\\MSSQL2017;database=JWTAuthentication; Uid=sa;Password=P@ssw0rd"
}
```

添加套件
```bash
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
```

建立服務擴充類別

建立 Extensions 資料夾後，接著建立 ServiceExtensions.cs
```CSharp
public static class ServiceExtensions
{ }
```

註冊資料庫服務

```CSharp
public static void ConfigureSqlContext(this IServiceCollection services, IConfiguration configuration) =>
    services.AddDbContext<ApplicationDbContext>(
        opts => opts.UseSqlServer(configuration.GetConnectionString("sqlConnection"),
        b => b.MigrationsAssembly("JWTAuthentication")
    ));
```

Startup.cs
```CSharp
public void ConfigureServices(IServiceCollection services)
{
    services.ConfigureSqlContext(Configuration);

    ...
}
```

## 設置 Identity 服務

在 Extensions\ServiceExtensions.cs 加入下面程式碼：

```CSharp
public static void ConfigureIdentity(this IServiceCollection services)
{
    var builder = services.AddIdentityCore<ApplicationUser>(o =>
    {
        o.Password.RequireDigit = true;
        o.Password.RequireLowercase = false;
        o.Password.RequireUppercase = false;
        o.Password.RequireNonAlphanumeric = false;
        o.Password.RequiredLength = 10;
        o.User.RequireUniqueEmail = true;
    });

    builder = new IdentityBuilder(builder.UserType, typeof(IdentityRole), builder.Services);
    builder.AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
}
```

在 Startup.cs 中

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddAuthentication();
    services.ConfigureIdentity();
}
```

```CSharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    ...

    app.UseAuthentication();    // 增加這一行
    app.UseAuthorization();

    ...
}
```

## 更新至資料庫

引用套件

```bash
dotnet add package Microsoft.EntityFrameworkCore.Design
```

建立 Migrations，

使用套件管理器主控台
```bash
PM> Add-Migration CreatingIdentityTables
```

使用 .net Core CLI
```bash
dotnet ef migrations add CreatingIdentityTables
```

更新至資料庫

使用套件管理器主控台
```bash
PM> Update-Database
```

使用 .net Core CLI
```bash
dotnet ef database update
```

## 增加角色

建立 Configuration 資料夾，加入 RoleConfiguration.cs

```CSharp
public class RoleConfiguration : IEntityTypeConfiguration<IdentityRole>
{
    public void Configure(EntityTypeBuilder<IdentityRole> builder)
    {
        builder.HasData(
            new IdentityRole
            {
                Name = "Manager",
                NormalizedName = "MANAGER"
            },
            new IdentityRole
            {
                Name = "Administrator",
                NormalizedName = "ADMINISTRATOR"
            }
        );
    }
}
```

使用套件管理器主控台

```bash
PM> Add-Migration AddedRolesToDb
PM> Update-Database
```

使用 .net Core CLI

```bash
dotnet ef migrations add AddedRolesToDb
dotnet ef database update
```

檢視 AspNetRoles 資料表可以看到有兩筆資料

## 使用 AutoMapper

引用套件

```bash
dotnet add package AutoMapper.Extensions.Microsoft.DependencyInjection
```

Startup.cs

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddAutoMapper(typeof(Startup));
}
```

## 使用 NLog

引用套件

```bash
dotnet add package NLog.Extensions.Logging
```

建立 Contracts 資料夾，加入 ILoggerManager 介面

```CSharp
public interface ILoggerManager
{
	void LogInfo(string message);
	void LogWarn(string message);
	void LogDebug(string message);
	void LogError(string message);
}
```

建立 LoggerManager

```CSharp
public class LoggerManager : ILoggerManager
{
	private static ILogger logger = LogManager.GetCurrentClassLogger();

	public LoggerManager()
	{
	}

	public void LogDebug(string message)
	{
		logger.Debug(message);
	}

	public void LogError(string message)
	{
		logger.Error(message);
	}

	public void LogInfo(string message)
	{
		logger.Info(message);
	}

	public void LogWarn(string message)
	{
		logger.Warn(message);
	}
}
```

註冊服務

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddScoped<ILoggerManager, LoggerManager>();
}
```

## 建立使用者

建立一個新的控制器，名為 AuthenticationController

```CSharp
[ApiController]
[Route("[controller]")]
public class AuthenticationController : Controller
{
    private readonly ILoggerManager _logger;
    private readonly IMapper _mapper;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthenticationController(ILoggerManager logger, IMapper mapper, UserManager<ApplicationUser> userManager)
    {
        _logger = logger;
        _mapper = mapper;
        _userManager = userManager;
    }
}
```

在 Models 資料夾中再建立一個 DataTransferObjects 資料夾並加入 UserForRegistrationDto

```CSharp
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
```

在 MappingProfile 中加入

```CSharp
CreateMap<UserForRegistrationDto, ApplicationUser>();
```

在 AuthenticationController 中加入 

```CSharp
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
```

## 設置 JWT 服務

加入套件

```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

在 appsettings.json 中加入 JWT 設定

```
"JWTSetting": {
    "Issuer": "cba",
    "Audience": "cba",
    "SecretKey": "123456789abcdefghi",
    "AccessExpiration": 60,
    "RefreshExpiration": 80
},
```

建立 JwtSettings 類別

```CSharp
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
    /// <summary>
    /// 刷新時間
    /// </summary>
    public int RefreshExpiration { get; set; }
}
```

在 Startup.cs 增加下列內容

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    var jwtSettings = Configuration.GetSection("JwtSettings").Get<JwtSettings>();
    // var secretKey = Environment.GetEnvironmentVariable("SECRET");
    var tokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwtSettings.Issuer,
        ValidAudience = jwtSettings.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(jwtSettings.SecretKey)),
        // IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
    };
    services.AddSingleton(tokenValidationParameters);

    ...
}
```

在 Extensions\ServiceExtensions.cs 加入下面程式碼：

```CSharp
public static void ConfigureJWT(this IServiceCollection services, IConfiguration configuration, TokenValidationParameters tokenValidationParameters)
{
    services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));
    var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
    // var secretKey = Environment.GetEnvironmentVariable("SECRET");

    services.AddAuthentication(opt =>
    {
        opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.TokenValidationParameters = tokenValidationParameters;
    });
}
```

密鑰明碼儲存在 JwtSettings 中，有另一種更為安全的設置方式，執行下列指令：

```bash
setx SECRET "你要設置的內容" /M
```

https://zh.wikipedia.org/wiki/Setx

讀取設置的密鑰

```CSharp
var secretKey = Environment.GetEnvironmentVariable("SECRET");
new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
```

在 Startup.cs 中

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.ConfigureIdentity();
    services.ConfigureJWT(Configuration, tokenValidationParameters);
}
```

## 設置權限檢查

在 WeatherForecastController 的 Get 中加上 Authorize

```CSharp
[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    ...

    [HttpGet, Authorize]
    public IEnumerable<WeatherForecast> Get()
    {
        ...
    }
}
```

現在讀取 https://localhost:5001/WeatherForecast 會得到 401 Unauthorized

## 使用者驗證

在 Models/DataTransferObjects 資料夾中加入

```CSharp
public class UserForAuthenticationDto
{
    [Required(ErrorMessage = "UserName 是必須的")]
    public string UserName { get; set; }
    [Required(ErrorMessage = "Password 是必須的")]
    public string Password { get; set; }
}
```

在 Contracts 資料夾中加入

```CSharp
public interface IAuthenticationManager
{
    Task<bool> ValidateUser(UserForAuthenticationDto userForAuth);
    Task<string> CreateToken();
}
```

建立 AuthenticationManager

```CSharp
public class AuthenticationManager : IAuthenticationManager
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    private ApplicationUser _user;

    public AuthenticationManager(UserManager<ApplicationUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    public async Task<bool> ValidateUser(UserForAuthenticationDto userForAuth)
    {
        _user = await _userManager.FindByNameAsync(userForAuth.UserName);

        return (_user != null && await _userManager.CheckPasswordAsync(_user, userForAuth.Password));
    }

    public async Task<string> CreateToken()
    {
        var signingCredentials = GetSigningCredentials();
        var claims = await GetClaims();
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

        return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
    }

    private SigningCredentials GetSigningCredentials()
    {
        //var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("SECRET"));
        var jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>();
        var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
        var secret = new SymmetricSecurityKey(key);

        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    private async Task<List<Claim>> GetClaims()
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, _user.UserName)
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
        var jwtSettings = _configuration.GetSection("JwtSettings").Get<JwtSettings>();

        var tokenOptions = new JwtSecurityToken
        (
            issuer: jwtSettings.Issuer,
            audience: jwtSettings.Audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings.AccessExpiration)),
            signingCredentials: signingCredentials
        );

        return tokenOptions;
    }
}
```

在 Startup.cs 中註冊服務

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...
    services.AddScoped<IAuthenticationManager, AuthenticationManager>();
}
```

修改 AuthenticationController

```CSharp
private readonly IAuthenticationManager _authManager;

public AuthenticationController(ILoggerManager logger, IMapper mapper, UserManager<ApplicationUser> userManager, IAuthenticationManager authManager)
{
    _logger = logger;
    _mapper = mapper;
    _userManager = userManager;
    _authManager = authManager;
}
```

並增加

```CSharp
[HttpPost("login")]
public async Task<IActionResult> Authenticate([FromBody] UserForAuthenticationDto user)
{
    if (!await _authManager.ValidateUser(user))
    {
        _logger.LogWarn($"{nameof(Authenticate)}: 驗證失敗。 錯誤的用戶名或密碼。");
        return Unauthorized();
    }

    return Ok(new { Token = await _authManager.CreateToken() });
}
```

## SWagger 介面

### 增加驗證項目

```CSharp
public void ConfigureServices(IServiceCollection services)
{
    ...

    services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWTAuthentication", Version = "v1" });

        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Description = "加入帶有 Bearer 的 JWT",
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer"
        });

        c.AddSecurityRequirement(new OpenApiSecurityRequirement()
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    },
                    Name = "Bearer",
                },
                new List<string>()
            }
        });
    });

    ...
}
```

### 增加說明

先至【專案】-> 【屬性】->【建置】->【輸出】，勾選【XML 文件檔案】

在 Startup.cs 中設置

```
public void ConfigureServices(IServiceCollection services)
{
    ... 

    services.AddSwaggerGen(c =>
    {
        ...

        var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        if (File.Exists(xmlPath))
            c.IncludeXmlComments(xmlPath);

        ...
    }
}
```

## JWT Token 刷新 

### 建立 Token 刷新資料表

在 Models 資料夾建立 RefreshToken 類別

```CSharp
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
```

將 RefreshToken 類別加入至 ApplicationDbContext 中

```CSharp
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    ...

    public virtual DbSet<RefreshToken> RefreshTokens { get; set; }

    ...
}
```

建立 Migrations 並更新至資料庫

使用套件管理器主控台
```bash
PM> Add-Migration AddedRefreshTokensTable
PM> Update-Database
```

使用 .net Core CLI
```bash
dotnet ef migrations add AddedRefreshTokensTable
dotnet ef database update
```

### 調整回傳物件

在 Models 資料夾中建立 AuthResult 類別

```
public class AuthResult
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public bool Success { get; set; }
    public List<string> Errors { get; set; }
}
```

### 調整 Token 建立功能

修改 AuthenticationManager 的 CreateToken 函數

```CSharp
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

private string RandomString(int length)
{
    var random = System.Security.Cryptography.RandomNumberGenerator.Create();
    byte[] number = new byte[length];
    random.GetBytes(number);
    return BitConverter.ToString(number).Replace("-", "");
}
```

將 AuthenticationController 中的 Authenticate Action 調整如下：

```CSharp
[HttpPost("login")]
public async Task<IActionResult> Authenticate([FromBody] UserForAuthenticationDto user)
{
    ...

    return Ok(await _authManager.CreateToken());
}
```

### 驗證並重新產生令牌

在 Models/DataTransferObjects 資料夾中增加 TokenRequestDto 類別

```CSharp
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
```

在 AuthenticationManager 中增加 VerifyAndGenerateToken 函數

```CSharp
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
```

### 增加刷新令牌 Action

在 Models/DataTransferObjects 資料夾中增加 TokenRequestDto 類別

```CSharp
public class RegistrationResponse : AuthResult
{ }
```

```CSharp
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
```

## 參考

1. [Ultimate ASP.NET Core Web API - Code Maze](https://code-maze.com/ultimate-aspnet-core-web-api/)

2. [Refresh JWT with Refresh Tokens in Asp Net Core 5 Rest API Step by Step](https://dev.to/moe23/refresh-jwt-with-refresh-tokens-in-asp-net-core-5-rest-api-step-by-step-3en5)

3. [Asp.Net Core 5 REST API 使用 RefreshToken 刷新 JWT - Step by Step](https://www.cnblogs.com/ittranslator/p/refresh-jwt-with-refresh-tokens-in-asp-net-core-5-rest-api-step-by-step.html)

4. [JWT.IO](https://jwt.io/)