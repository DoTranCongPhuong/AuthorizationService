public class RegisterRequest
{
    public string Email { get; set; }
    public string Password { get; set; }
}
public class LoginRequest
{
    public string Email { get; set; }
    public string Password { get; set; }
}
public class ChangePasswordRequest
{
    public string CurrentPassword { get; set; }
    public string NewPassword { get; set; }
}