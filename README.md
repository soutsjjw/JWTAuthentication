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
{
}
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

在 Extensions\ServiceExtensions.cs 加入下面程式碼：

```CSharp
public static void ConfigureJWT(this IServiceCollection services, IConfiguration configuration)
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
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.SecretKey)),
            // IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
        };
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
    services.ConfigureJWT(Configuration);
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

## SWagger 介面增加驗證

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
            Name = "授權",
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