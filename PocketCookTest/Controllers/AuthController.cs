using Microsoft.AspNetCore.Mvc;
using PocketCookTest.Models;
using PocketCookTest.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Google.Apis.Auth;
using System.Threading.Tasks;

namespace PocketCookTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, IConfiguration configuration)  // Inject the database context
        {
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// Register Endpoint
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterModel model)
        {
            // Check if the user already exists
            if (_context.Users.Any(u => u.FullName == model.FullName))
            {
                return BadRequest("Email is already registered.");
            }

            // Hash password
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);

            // Create a new User and add it to the list
            var user = new User
            {
                FullName = model.FullName,
                Email = model.Email,
                PasswordHash = passwordHash
            };

            // Save user to the database
            _context.Users.Add(user);
            _context.SaveChanges();  // Save to database

            return Ok(new { message = "User registered successfully!" });
        } // End of Register Endpoint

        /// <summary>
        /// Login Enpoint
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            var user = _context.Users.SingleOrDefault(u => u.Email == model.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                return Unauthorized("Invalid email or password.");
            }

            // Generate JWT Token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Email)
                }),
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"]
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString });
        } // End of Login Enpoint

        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request)
        {
            try
            {
                var settings = new GoogleJsonWebSignature.ValidationSettings
                {
                    Audience = new[] { "866934536387-udvlu0vv09mlggdbr4kotn2t39ggmv8k.apps.googleusercontent.com" } // Replace with your Google Client ID
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(request.Token, settings);

                // Check if user exists
                var existingUser = _context.Users.FirstOrDefault(u => u.Email == payload.Email);
                if (existingUser == null)
                {
                    // Create new user if not found
                    var newUser = new User
                    {
                        FullName = payload.Name,
                        Email = payload.Email,
                        PasswordHash = "GOOGLE_AUTH_USER"
                    };

                    _context.Users.Add(newUser);
                    _context.SaveChanges();
                    existingUser = newUser;
                }

                // Generate JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, existingUser.Email) }),
                    Expires = DateTime.UtcNow.AddHours(2),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { token = tokenString, user = existingUser });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Invalid Google token", details = ex.Message });
            }
        }


    }
}

