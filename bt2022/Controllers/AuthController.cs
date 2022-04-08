using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace bt2022.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password");

            }
   
            string token = CreateToken( user);

            return Ok(token);
        }

        //[HttpPost("Post")]
        //[Authorize(Roles = "Admin")]
        //public string Post()
        //{
        //    var identity = HttpContext.User.Identity as ClaimsIdentity;
        //    IList<Claim> claims = identity.Claims.ToList();
        //    var username = claims[0].Value;
        //    return "Welcome TO" + username;
        //}

        //[Authorize(Roles = "Member")]
        //[HttpGet("Getvalue")]
        //public ActionResult<IEnumerable<string>> Get()
        //{
        //    return new string[] { "Member", "is", "here" };
        //}

        private string CreateToken(User user)   
        {
            List<Claim> claims = new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.Name, user.Username)
                    //,

                    //new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                    //new Claim(ClaimTypes.Role,user.isAdmin)


                };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passworSalt)
        {
            using (var hmac = new HMACSHA512(passworSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
