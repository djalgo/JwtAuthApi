using JwtAuthDotNet.Entities;
using JwtAuthDotNet.Models;

namespace JwtAuthDotNet.Services
{
    public interface IAuthService
    {
        Task<User> RegisterAsync(UserDtos request);
        Task<TokenResponseDto> LoginAsync(UserDtos request);

        Task<TokenResponseDto> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}
