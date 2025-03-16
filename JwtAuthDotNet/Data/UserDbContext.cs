using JwtAuthDotNet.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDotNet.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
