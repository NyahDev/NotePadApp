namespace NotePadApp.ViewModels.Dto
{
    public class ConfirmPasswordDto
    {
        public string UserId { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set;}
    }
}
