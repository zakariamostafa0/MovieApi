namespace MoviesApi.Dtos
{
    public class TokenRequestModelDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
