namespace MoviesApi.Services.Abstract
{
    public interface IAuthService
    {
        // generate token in registreation
        Task<AuthModel> RegisterAsync(RegisterModelDto model);

        // generate token in login
        Task<AuthModel> GetTokenAsync(TokenRequestModelDto model);

        Task<string> AddRoleAsync(AddRoleModelDto model);

        //To Generate refresh token and new Jwt token
        Task<AuthModel> RefreshTokenAsync(string token);

        //
        Task<bool> RevokeTokenAsync(string token);
    }
}
