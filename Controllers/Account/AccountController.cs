using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NotePadApp.Data;
using NotePadApp.Models;
using NotePadApp.ViewModels.Dto;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;

namespace NotePadApp.Controllers.Account
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly SmtpSettings _smtpSettings;
        private readonly NotePadDbContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly IServiceProvider _serviceProvider;
        private readonly ICompositeViewEngine _razorViewEngine;
        private readonly ITempDataProvider _tempDataProvider;

        public AccountController(UserManager<User> userManager, 
            SignInManager<User> signInManager, IOptions<SmtpSettings> smtpSettings, NotePadDbContext dbContext, 
            IConfiguration configuration, IServiceProvider serviceProvider, ICompositeViewEngine razorViewEngine, 
            ITempDataProvider tempDataProvider)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _smtpSettings = smtpSettings.Value;
            _dbContext = dbContext;
            _configuration = configuration;
            _serviceProvider = serviceProvider;
            _razorViewEngine = razorViewEngine;
            _tempDataProvider = tempDataProvider;
        }

        [HttpGet("verify")]
        public IActionResult Verify()
        {
            var response = new VerificationDto();
            return View (response);
        }

        [HttpGet("EmailNot")]
        public IActionResult EmailNot()
        {
            return View("EmailNot");
        }

        public IActionResult Register()
        {
            var response = new UserRegistrationDto();
            return View(response);
        }

        public IActionResult RPassword()
        {
            var response = new PasswordRestDto();
            return View(response);
        }

        public IActionResult ConfirmPass()
        {
            var response = new ConfirmPasswordDto();
            return View(response);
        }
        //public IActionResult Index()
        //{
        //    return View();
        //}

        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            // Sign out the user
            await _signInManager.SignOutAsync();

            // Optionally, you can clear the user's session and cookies
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Redirect to the home page or another desired page
            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        public async Task<IActionResult> Register(UserRegistrationDto userRegDto)
        {
            try
            {
                string otp = GenerateAnOTP();

                //Check if password and Comfirmation of it matches
                if (userRegDto.Password != userRegDto.ConfirmPassword)
                {
                    ModelState.AddModelError("Confirm Password", "The password and confirmation password does not match.");
                    return View(userRegDto); //Returns the view with the validation errors
                }

                //Create new user with email, password, and
                var user = new User
                {
                    UserName = userRegDto.UserName,
                    PasswordHash = userRegDto.Password,
                    Email = userRegDto.Email.ToLowerInvariant(),
                    Occupation = userRegDto.Occupation,
                    VerificationCode = otp,
                    VerficationCodeExpiration = DateTime.UtcNow.AddMinutes(20),
                    EmailNot = userRegDto.Email
                };

                //Now we check if email exists already
                var userexists = await _userManager.FindByEmailAsync(user.Email);
                if (userexists != null)
                {
                    ModelState.AddModelError("Email", "Email Exists");
                    return View(userRegDto); //Return again with validation errors
                }

                //Create user with password
                var result = await _userManager.CreateAsync(user, userRegDto.Password);

                if (result.Succeeded)
                {
                    bool otpSent = false;
                    otpSent = SendOTPViaEmail(user.Email, otp);
                    if (!otpSent)
                    {
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send otp");
                    }
                    var token = GenerateJWTToken(user);

                    // Store the token in TempData for later retrieval
                    TempData["JWTToken"] = token;
                    //Redirect to the "Index" page after succesfull registration
                    return RedirectToAction("Verify", "Account");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Registraion failed. Please check information provided.");
                    return View(userRegDto);
                }

            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.InternalServerError, ex.Message);
            }
        }
        public IActionResult Login()
        {
            var log = new LoginDto();
            return View(log);
        }
        [HttpPost("Account/Login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDto loginDto, bool rememberMe)
        {
            try
            {
                // It tries to look for the user by Email
                var user = await _userManager.FindByEmailAsync(loginDto.Email.ToLowerInvariant());

                if (user == null)
                {
                    TempData["Error"] = "Invalid Email";
                    return RedirectToAction("Login", "Account");
                }

                if (!await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    TempData["Error"] = "Incorrect Password";
                    return RedirectToAction("Login", "Account");
                }

                //Checks to see if user is verified ***(customize this logic based on your app)
                if (!user.IsVerified)
                {
                    // If the User is not verified then send a new verification code to their email
                    string otp = GenerateAnOTP();

                    // Update the user's verification code and expiration time
                    user.VerificationCode = otp;
                    user.VerficationCodeExpiration = DateTime.UtcNow.AddMinutes(8);
                    await _userManager.UpdateAsync(user);

                    bool otpSent = false;
                    otpSent = SendOTPViaEmail(user.Email, otp);
                    if (!otpSent)
                    {
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send otp");
                    }


                    TempData["Error"] = "Your account is not verified. We've sent a new verification code to your email.";

                    // Return the "verify" view
                    //var verificationDto = new VerificationDto
                    {
                        // Pass any necessary data to the view
                    };

                    return View("Verify");
                }

                // User has been verified now generate a JWT token
                var token = GenerateJWTToken(user);

                // Store user info in TempData for the view (customize as needed)
                TempData["UserId"] = user.Id;
                TempData["UserName"] = user.UserName;
                TempData["UserEmail"] = user.Email;

                // If rememberMe is true, set the authentication cookie to be persistent
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = rememberMe,
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
        {
            // Add any other claims neededd for the user
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            // Add more claims as required
        }, CookieAuthenticationDefaults.AuthenticationScheme)), authProperties);

                return RedirectToAction("Index", "Home"); // Redirects back to dashboard or page desired 
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Internal server error: {ex.Message}";
                return RedirectToAction("Login"); // Redirects back to login view with error message
            }
        }

        // Helper method to render a view to string
        //private async Task<string> RenderViewToStringAsync(string viewName, object model)
        //{
        //    var httpContext = new DefaultHttpContext { RequestServices = _serviceProvider };
        //    var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

        //    using (var sw = new StringWriter())
        //    {
        //        var viewResult = _razorViewEngine.FindView(actionContext, viewName, false);

        //        if (viewResult.View == null)
        //        {
        //            throw new ArgumentNullException($"{viewName} does not match any available view");
        //        }

        //        var viewData = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
        //        {
        //            Model = model
        //        };
        //        var viewContext = new ViewContext(
        //            actionContext,
        //            viewResult.View,
        //            viewData,
        //            new TempDataDictionary(actionContext.HttpContext, _tempDataProvider),
        //            sw,
        //            new HtmlHelperOptions()
        //        );

        //        await viewResult.View.RenderAsync(viewContext);
        //        return sw.ToString();
        //    }
        //}

        [HttpPost]
        public async Task<IActionResult> VerifyOTP(VerificationDto verification)
        {
            // Retrieve the user from the UserManager using the logged-in user's identity
            //var token = TempData["JWTToken"]?.ToString();
            var token = Request.Form["jwtToken"];

            if (string.IsNullOrEmpty(token))
            {
                return RedirectToAction("Login", "Account"); // Redirect to login page if token is not found
            }

            // Parse the token to get the NameIdentifier claim
            var claim = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
            var userId = claim?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            if (userId == null)
            {
                return RedirectToAction("Login", "Account"); // Redirect to login page if claim is not found
            }

            // Retrieve the user using the NameIdentifier claim
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return RedirectToAction("Login", "Account"); // Redirect to login page if user is not found
            }

            if (string.IsNullOrEmpty(verification.otp) || verification.otp.Length != 6 || !verification.otp.All(char.IsDigit))
            {
                TempData["Error"] = "Invalid OTP format";
                return RedirectToAction("Verify", "Account"); // Redirect to verification page with error message
            }

            if (user.VerificationCode != verification.otp || DateTime.UtcNow > user.VerficationCodeExpiration)
            {
                TempData["Error"] = "Invalid OTP";
                return RedirectToAction("Verify", "Account"); // Redirect to verification page with error message
            }

            // OTP is valid, update user's verification status
            user.IsVerified = true;
            await _userManager.UpdateAsync(user);

            // Redirect to the login page
            return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        public async Task<IActionResult> ResetPasswordRequest(ResetPasswordRequestDto resetPasswordRequestDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordRequestDto.Email);

            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Handle case where user doesn't exist or email is not confirmed
                TempData["Error"] = "Invalid email address.";
                return RedirectToAction("RPassword", "Account");
            }

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));

            var callbackUrl = Url.Action("RPassword", "Account", new { userId = user.Id, token = encodedToken }, protocol: HttpContext.Request.Scheme);
            var emailSent = SendResetPasswordEmail(user.Email, callbackUrl);

            if (!emailSent)
            {
                return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send reset link.");
            }

            return RedirectToAction("ConfirmPass", "Account");
        }

        [HttpPost("resetpassword/confirm")]
        public async Task<IActionResult> ResetPasswordConfirm([FromBody] ConfirmPasswordDto confirmPassword)
        {
            // Ensure both UserId and Token are provided
            if (string.IsNullOrEmpty(confirmPassword.UserId) || string.IsNullOrEmpty(confirmPassword.Token))
            {
                return BadRequest("Invalid reset link.");
            }

            // Decode the token
            //var decodedToken = WebEncoders.Base64UrlDecode(Encoding.UTF8.GetBytes(confirmPassword.Token));
            //var resetToken = Encoding.UTF8.GetString(decodedToken);
            //if (confirmPassword.Token == null)
            //{
            //    return BadRequest("Invalid reset link.");
            //}

            //var decodedToken = WebEncoders.Base64UrlDecode(Encoding.UTF8.GetBytes(confirmPassword.Token));
            //var resetToken = Encoding.UTF8.GetString(decodedToken);

            string resetToken = null;

            if (confirmPassword.Token != null)
            {
                byte[] decodedBytes = WebEncoders.Base64UrlDecode(confirmPassword.Token);
                resetToken = Encoding.UTF8.GetString(decodedBytes);
            }

            if (resetToken == null)
            {
                return BadRequest("Invalid reset link.");
            }


            // Verify the reset token (Add your own logic to check token validity)
            var user = await _userManager.FindByIdAsync(confirmPassword.UserId);

            if (user == null || !await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", resetToken))
            {
                return BadRequest("Invalid reset link.");
            }

            // Verify the new password and confirm password
            if (confirmPassword.NewPassword != confirmPassword.ConfirmPassword)
            {
                return BadRequest("New password and confirm password do not match.");
            }

            var result = await _userManager.ResetPasswordAsync(user, resetToken, confirmPassword.NewPassword);

            if (result.Succeeded)
            {
                return RedirectToAction("Login", "Account");
            }

            return BadRequest("Password reset failed. Please try again.");
        }



        private string GenerateJWTToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>{
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            };
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(48), // Token expiration time (adjust as needed)
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        private string GenerateAnOTP()
        {
            Random random = new Random();
            int otpValue = random.Next(100000, 999999);
            return otpValue.ToString();
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);


                return addr.Address == email && email.Contains(".") && email.Contains("@");
            }
            catch
            {
                return false;
            }
        }
        //private bool SendEmail(string email, string subject, string body)
        //{
        //    try
        //    {
        //        MailMessage mail = new MailMessage();
        //        SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
        //        smtpClient.UseDefaultCredentials = false;
        //        smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
        //        smtpClient.EnableSsl = true;

        //        mail.From = new MailAddress("Jerry@Notepad.com");
        //        mail.To.Add(email);
        //        mail.Subject = subject;
        //        mail.Body = body;

        //        smtpClient.Send(mail);

        //        return true;
        //    }
        //    catch (Exception ex)
        //    {
        //        // Handle the exception
        //        return false;
        //    }
        //}
        //medium.com for publishing

        private bool SendOTPViaEmail(string email, string otp)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress("Jerry@TheBoss.com");
                mail.To.Add(email);
                mail.Subject = "OTP Verification From Jerry";
                mail.Body = $"David send me this OTP: {otp}";

                smtpClient.Send(mail);

                //Set the Verification code expiration time to 5 minutes from when sent
                TimeSpan expirationTimeOfCode = TimeSpan.FromMinutes(10);

                var user = _dbContext.Users.SingleOrDefault(u => u.Email == email);

                return true;
            }
            catch (Exception ex)
            {
                //Handle the exception
                return false;
            }
        }


        //private bool SendResetPasswordEmail(string email, string userId, string resetToken)
        //{
        //    try
        //    {
        //        // Construct the reset password URL
        //        var callbackUrl = Url.Action("ResetPasswordConfirm", "Account",
        //            new { userId, token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken)) },
        //            protocol: HttpContext.Request.Scheme);

        //        // Construct the email body with the reset password link
        //        string body = $"Click the link below to reset your password:\n\n{callbackUrl}";

        //        MailMessage mail = new MailMessage();
        //        SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
        //        // ... (rest of your email setup)

        //        mail.From = new MailAddress("Jerry@TheBoss.com");
        //        mail.To.Add(email);
        //        mail.Subject = "Reset Password Request";
        //        mail.Body = body;

        //        smtpClient.Send(mail);

        //        return true;
        //    }
        //    catch (Exception ex)
        //    {
        //        // Handle the exception (log, notify, etc.)
        //        return false;
        //    }
        //}


        private bool SendResetPasswordEmail(string email, string resetLink)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;
                mail.From = new MailAddress("Jerry@TheBoss.com");
                mail.To.Add(email);
                mail.Subject = "Reset Password Request";
                mail.Body = $"Click the link below to reset your password:\n\n{resetLink}";

                smtpClient.Send(mail);

                return true;
            }
            catch (Exception ex)
            {
                // Handle the exception (log, notify, etc.)
                return false;
            }
        }

        //private bool SendResetPasswordEmail(string email, string userId, string resetToken)
        //{
        //    try
        //    {
        //        var callbackUrl = Url.Action("RPassword", "Account",
        //            new { userId, token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken)) },
        //            protocol: HttpContext.Request.Scheme);

        //        // Construct the email body with the reset password link
        //        string body = $"Click the link below to reset your password:\n\n{callbackUrl}";

        //        return SendEmail(email, "Reset Password Request", body);
        //    }
        //    catch (Exception ex)
        //    {
        //        // Handle the exception (log, notify, etc.)
        //        return false;
        //    }
        //}

        //private bool SendEmail(string email, string subject, string body)
        //{
        //    try
        //    {
        //        MailMessage mail = new MailMessage();
        //        SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
        //        smtpClient.UseDefaultCredentials = false;
        //        smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
        //        smtpClient.EnableSsl = true;

        //        mail.From = new MailAddress("Jerry@TheBoss.com");
        //        mail.To.Add(email);
        //        mail.Subject = subject;
        //        mail.Body = body;

        //        smtpClient.Send(mail);

        //        return true;
        //    }
        //    catch (Exception ex)
        //    {
        //        // Handle the exception (log, notify, etc.)
        //        return false;
        //    }
        //}

    }
}
