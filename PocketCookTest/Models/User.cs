using System.ComponentModel.DataAnnotations;

namespace PocketCookTest.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string FullName { get; set; }

        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string PasswordHash { get; set; }  // Store hashed password
    }
}
