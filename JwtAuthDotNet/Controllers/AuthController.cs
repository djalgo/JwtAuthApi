using JwtAuthDotNet.Entities;
using JwtAuthDotNet.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Unicode;
using JwtAuthDotNet.Services;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuthDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService authService;

        public AuthController(IAuthService authService)
        {
            this.authService = authService;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User?>> Register(UserDtos request)
        {
            var user = await authService.RegisterAsync(request);
            if (user == null)
            {
                return BadRequest("Username already Exists");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDtos request)
        {
            var result = await authService.LoginAsync(request);

            if (result is null)
            {
                return BadRequest("Invalid username or password.");
            }
          
            return Ok(result);
        }

        [Authorize]
        [HttpGet("IsAuthenticated")]
        public IActionResult IsAuthenticated()
        {
            return Ok(true);
        }

        [Authorize(Roles ="Admin")]
        [HttpGet("IsAdminAuthenticatedOnly")]
        public IActionResult IsAdminAuthenticatedOnly()
        {
            return Ok(true);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokensAsync(request);

            if(result is null ||
                result.RefreshToken is null ||
                result.AccessToken is null)
            {
                return Unauthorized("Invalid refresh token");
            }

            return Ok(result);
        }
    }
}
