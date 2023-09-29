namespace NotePadApp.Models
{
    using System;
    using System.ComponentModel.DataAnnotations;
    public class PasswordResetTokens
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int UserId { get; set; }  // Reference to the user for whom the token is issued

        [Required]
        public string Token { get; set; }  // The reset token

        [Required]
        public DateTime ExpirationDate { get; set; }  // When the token expires

        public bool IsUsed { get; set; }  // Whether the token has been used

        // Add any other relevant fields you might need
    }
}
