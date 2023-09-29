using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NotePadApp.Models;

namespace NotePadApp.Data
{
    public class NotePadDbContext: IdentityDbContext<User , IdentityRole<int>, int>
    {
        public NotePadDbContext(DbContextOptions options): base(options) 
        { }
       
        public DbSet<Note> Notes { get; set; }
        public DbSet<User> users { get; set; }
        public DbSet<PasswordResetTokens> PasswordResetTokens { get; set; }
    }
}
