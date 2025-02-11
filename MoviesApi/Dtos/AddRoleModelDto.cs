namespace MoviesApi.Dtos
{
    public class AddRoleModelDto
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
