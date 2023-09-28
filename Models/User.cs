using Microsoft.AspNetCore.Identity;

namespace NotePadApp.Models
{
    public class User : IdentityUser<int>
    {
        public string Occupation { get; set; }
        public string VerificationCode { get; set; }
        public bool IsVerified { get; set; } = false;
        public DateTime VerficationCodeExpiration { get; set; }
        public string EmailNot { get; set; }
    }
}
