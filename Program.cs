using AuthorizationService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
// using AuthorizationService.Data;
// using AuthorizationService.Models;

var builder = WebApplication.CreateBuilder(args);

// ---------- ĐỌC CHUỖI KẾT NỐI ----------
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

// ---------- DATABASE & IDENTITY ----------
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    options.UseOpenIddict(); // EF Core integration cho OpenIddict
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredUniqueChars = 1;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ---------- OPENIDDICT CONFIGURATION ----------
// builder.Services.AddOpenIddict()
//     .AddCore(options =>
//     {
//         options.UseEntityFrameworkCore()
//                .UseDbContext<ApplicationDbContext>();
//     })
//     .AddServer(options =>
//     {

//         options.AddEphemeralEncryptionKey();

//         // ✅ Dùng khóa ký JWT
//         options.AddDevelopmentSigningCertificate();
//         options.DisableAccessTokenEncryption();
//         options.SetTokenEndpointUris("/connect/token");
//         options.AllowPasswordFlow();
//         options.AllowRefreshTokenFlow();
//         options.AcceptAnonymousClients();

//         options.UseAspNetCore()
//                .EnableTokenEndpointPassthrough();
//     })
//     .AddValidation(options =>
//     {
//         options.UseLocalServer();
//         options.UseAspNetCore();
//     });





// --------------------- Cho phép HTTP (chỉ dùng khi phát triển) ---------------------
builder.Services.Configure<OpenIddictServerAspNetCoreOptions>(options =>
{
    // Tắt bắt buộc HTTPS để dễ test local (KHÔNG dùng trong production)
    options.DisableTransportSecurityRequirement = true;
});

// --------------------- Cấu hình OpenIddict ---------------------
builder.Services.AddOpenIddict()

    // ---------- Core Layer: sử dụng Entity Framework để lưu trữ ứng dụng, token, v.v. ----------
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })

    // ---------- Server Layer: nơi phát hành token và xử lý xác thực ----------
    .AddServer(options =>
    {
        // Cấu hình các endpoint được hỗ trợ
        options.SetTokenEndpointUris("/connect/token");
        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetUserInfoEndpointUris("/connect/userinfo");

        // Cho phép các flow phổ biến (đăng nhập, client credentials, refresh token)
        options.AllowPasswordFlow()
               .AllowRefreshTokenFlow()
               .AllowClientCredentialsFlow();

        // Chấp nhận ứng dụng không có client_id (anonymous client - không an toàn với prod)
        options.AcceptAnonymousClients();

        // Không mã hóa access token (JWT ở dạng plain)
        options.DisableAccessTokenEncryption();

        // Dùng chứng chỉ tạm thời để ký và mã hóa token (chỉ dùng khi dev)
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Kích hoạt tích hợp với ASP.NET Core cho các endpoint
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();
    })

    // ---------- Validation Layer: xác thực access token gửi từ client ----------
    .AddValidation(options =>
    {
        // Token phải chứa audience này (tuỳ chỉnh theo hệ thống của bạn)
        options.AddAudiences("audiences");

        // Token phải phát hành từ issuer này
        options.SetIssuer("https://localhost:5048");

        // options.UseSystemNetHttp(); // Tuỳ chọn dùng HttpClient chuẩn (nếu cần)

        // Xác thực token bằng chính server local này
        options.UseLocalServer();

        // Dùng tích hợp sẵn với ASP.NET Core
        options.UseAspNetCore();
    });

// --------------------- Cấu hình xác thực (Authentication) ---------------------
builder.Services.AddAuthentication(options =>
{
    // Sử dụng validation scheme mặc định của OpenIddict
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// --------------------- Cấu hình phân quyền (Authorization) ---------------------
builder.Services.AddAuthorization();

builder.Services.AddAuthorization(options =>
{
    // Mặc định: người dùng phải được xác thực để truy cập mọi endpoint
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();
});

// --------------------- Tùy chỉnh phản hồi khi bị từ chối hoặc chưa đăng nhập (401/403) ---------------------
builder.Services.ConfigureApplicationCookie(options =>
{
    // Trả về 401 thay vì redirect khi chưa đăng nhập (API friendly)
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };

    // Trả về 403 khi bị từ chối truy cập
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});


var emailSettings = builder.Configuration
    .GetSection("EmailSettings")
    .Get<EmailSettings>();

builder.Services.AddSingleton(emailSettings);
builder.Services.AddScoped<EmailService>();

// ---------- AUTHENTICATION ----------
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// ---------- AUTHORIZATION ----------
builder.Services.AddAuthorization();

// ---------- CONTROLLERS / SWAGGER ----------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
// ---------- APPLY MIGRATIONS + TẠO ROLE MẶC ĐỊNH ----------
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.Migrate();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roles = { "User", "Admin" };

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}

// ---------- MIDDLEWARE PIPELINE ----------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection(); - http


app.MapControllers();


app.Run();