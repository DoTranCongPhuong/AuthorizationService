using System.Text;
using Authorization.Grpc;
using Grpc.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

public class AccountGrpcService : AccountGrpc.AccountGrpcBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly EmailService _emailService;

    public AccountGrpcService(UserManager<ApplicationUser> userManager,
    EmailService emailService)
    {
        _userManager = userManager;
        _emailService = emailService;
    }

    public override async Task<CreateUserResponse> CreateUser(CreateUserRequest request, ServerCallContext context)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
        };

        string Password = Guid.NewGuid().ToString("N").Substring(0, 6).ToUpper();


        var result = await _userManager.CreateAsync(user, Password);

        user = await _userManager.FindByEmailAsync(request.Email);

        // Gán role mặc định
        await _userManager.AddToRoleAsync(user, "User");

        // ✅ Tạo token xác thực email
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        // ✅ Encode token chuẩn để nhúng vào URL
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        // ✅ Tạo link xác nhận
        var confirmationLink = $"http://localhost:5048/api/account/confirm-email?userName={Uri.EscapeDataString(user.UserName)}&token={encodedToken}";

        var emailBody = $@"
                <h1>Chào mừng!</h1>
                <div>
                Password: <span style='background-color: black; color: black;'>{Password}</span>
                </div>               
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

        return new CreateUserResponse
        {
            UserId = user.Id,
            Message = result.Succeeded ? "User created" : string.Join(", ", result.Errors.Select(e => e.Description))
        };
    }
}
