using AuthorizationService;
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
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>(); // Kết nối EF Core
    })
    .AddServer(options =>
    {
        // Bạn cần cả khóa mã hóa và khóa ký.
        options.AddDevelopmentEncryptionCertificate();  // Khóa mã hóa (UNCOMMENT THIS LINE)
        options.AddDevelopmentSigningCertificate();     // Khóa ký

        // Endpoint & luồng xác thực
        options.SetTokenEndpointUris("/connect/token");
        options.AllowPasswordFlow();
        options.AllowRefreshTokenFlow();
        options.AcceptAnonymousClients();

        // Cho phép dùng controller tùy chỉnh
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });



// ✅ Set cứng: Cho phép HTTP mà không cần kiểm tra môi trường
builder.Services.Configure<OpenIddictServerAspNetCoreOptions>(options =>
{
    options.DisableTransportSecurityRequirement = true;
}
);




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

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


app.Run();