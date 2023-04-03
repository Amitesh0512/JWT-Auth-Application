using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTApplicationTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {

        public static User user = new User();

        private readonly IConfiguration _configuration;

        public ValuesController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTo request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTo request)
        {
            if(user.UserName != request.UserName)
            {
                return BadRequest("User Not Found");
            }

            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password is Incorrect");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private void CreatePasswordHash(string Password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
            }
        }

        private bool VerifyPasswordHash(string Password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateToken(User user)
        {

            List<Claim> Claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("DhftOS5uphK3vmCJQrexST1RsyjZBjXWRgJMFPU4"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: Claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
