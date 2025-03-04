using Microsoft.EntityFrameworkCore;
using PocketCookTest.Models;

namespace PocketCookTest.Data 
{
    // Declare the class AppDbContext and extend from DbContext
    public class AppDbContext : DbContext
    {
        // constructor, will take DbContextOptions<AppDbContext> and pass it to DbContext
        // This allows the AppDbContext to be configured with options such as the connection string, database provider
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }  // This will create a Users table
    }
}

