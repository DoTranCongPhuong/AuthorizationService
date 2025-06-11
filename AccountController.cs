using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Net;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOpenIddictTokenManager _tokenManager;

    private readonly EmailService _emailService;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOpenIddictTokenManager tokenManager,
        EmailService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenManager = tokenManager;
        _emailService = emailService;

    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest model)
    {
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
            // return BadRequest(result.Errors);

            // Gán role mặc định
        await _userManager.AddToRoleAsync(user, "User");

        // ✅ Tạo token xác thực email
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        Console.WriteLine("before " + token);

        // ✅ Encode token chuẩn để nhúng vào URL
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        // ✅ Tạo link xác nhận
        var confirmationLink = $"http://localhost:5048/api/account/confirm-email?userName={Uri.EscapeDataString(user.UserName)}&token={encodedToken}";

        var emailBody = $@"
                <h1>Chào mừng!</h1>
                <p>Bạn đã đăng ký thành công. Vui lòng xác nhận tài khoản của bạn bằng cách nhấp vào nút dưới đây:</p>
                <a href='{confirmationLink}' style='
                    display:inline-block;
                    padding:10px 20px;
                    background-color:#007bff;
                    color:white;
                    text-decoration:none;
                    border-radius:5px;
                    font-weight:bold;'>Xác nhận tài khoản</a>";

        await _emailService.SendEmailAsync(user.Email, "Xác nhận tài khoản", emailBody);

        return Ok("Đăng ký thành công. Vui lòng kiểm tra email để xác nhận tài khoản.");
    }

    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string userName, string token)
    {
        var user = await _userManager.FindByNameAsync(userName);
        Console.WriteLine($"User found: {user.Email}, EmailConfirmed: {user.EmailConfirmed}");

        if (user == null)
            return NotFound("Người dùng không tồn tại.");


        // ✅ Giải mã từ Base64Url về chuỗi token gốc
        var tokenBytes = WebEncoders.Base64UrlDecode(token);

        var decodedToken = Encoding.UTF8.GetString(tokenBytes);
        Console.WriteLine("after " + decodedToken);
        var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description);
            return BadRequest(new
            {
                Message = "Xác nhận email thất bại.",
                Errors = errors
            });
        }

        return Ok("Xác nhận email thành công. Bạn có thể đăng nhập.");
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            return Unauthorized("Invalid email or password");

        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
        identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id);
        identity.AddClaim(OpenIddictConstants.Claims.Email, user.Email);
        identity.AddClaim(OpenIddictConstants.Claims.Name, user.UserName);

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
            identity.AddClaim(OpenIddictConstants.Claims.Role, role);

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Roles);

        // 👇 Đây là cách OpenIddict tạo và trả token
        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }


    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return Unauthorized();

        var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok("Password changed successfully.");
    }
}
