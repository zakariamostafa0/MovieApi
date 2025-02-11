using Microsoft.AspNetCore.Identity;

namespace MoviesApi.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(50)]
        public string FirstName { get; set; }
        [Required]
        [MaxLength(50)]
        public string LasName { get; set; }
        public string? Address { get; set; }
    }
}
