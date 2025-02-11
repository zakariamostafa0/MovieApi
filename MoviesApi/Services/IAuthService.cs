namespace MoviesApi.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModelDto model);
        Task<AuthModel> GetTokenAsync(TokenRequestModelDto model);
        Task<string> AddRoleAsync(AddRoleModelDto model);
    }
}
