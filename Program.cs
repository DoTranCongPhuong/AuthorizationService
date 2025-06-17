using AuthorizationService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using Grpc.AspNetCore;
using Microsoft.AspNetCore.Server.Kestrel.Core;

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
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(opt =>
    {

        opt.SetTokenEndpointUris("/connect/token");
        opt.SetAuthorizationEndpointUris("/connect/authorize");
        opt.SetUserInfoEndpointUris("/connect/userinfo");

        opt.AllowPasswordFlow().AllowRefreshTokenFlow();

        opt.AllowClientCredentialsFlow();

        opt.AcceptAnonymousClients();

        opt.DisableAccessTokenEncryption();

        opt.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();

        opt.UseAspNetCore().EnableTokenEndpointPassthrough().EnableAuthorizationEndpointPassthrough().EnableUserInfoEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.AddAudiences("audiences");
        options.SetIssuer("https://localhost:5048");
        //options.UseSystemNetHttp();
        options.UseLocalServer();
        options.UseAspNetCore();
    });


    // --------------------- Cho phép HTTP (chỉ dùng khi phát triển) ---------------------
builder.Services.Configure<OpenIddictServerAspNetCoreOptions>(options =>
{
    // Tắt bắt buộc HTTPS để dễ test local (KHÔNG dùng trong production)
    options.DisableTransportSecurityRequirement = true;
});

// ---------- AUTHENTICATION ----------
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

// ---------- AUTHORIZATION ----------
builder.Services.AddAuthorization();

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };
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

builder.WebHost.ConfigureKestrel(options =>
{
    // Cổng cho HTTP API
    options.ListenLocalhost(5048, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
    });
    options.ListenLocalhost(5049, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

// ---------- CONTROLLERS / SWAGGER ----------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddGrpc();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
// ---------- APPLY MIGRATIONS + TẠO ROLE MẶC ĐỊNH ----------
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.Migrate();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roles = {"User"};

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

app.MapGrpcService<AccountGrpcService>();

app.MapControllers();

app.Run();