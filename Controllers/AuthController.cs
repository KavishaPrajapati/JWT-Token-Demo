using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Token_Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {    
            IConfiguration configuration;
            public AuthController(IConfiguration configuration)
            {
                this.configuration = configuration;
            }

            [AllowAnonymous]
            [HttpPost]
            public IActionResult Auth([FromBody] Class user)
            {
                IActionResult response = Unauthorized();
                if (user != null)
                {
                    if (user.Username.Equals("sanukavisha@gmail.com") && user.Password.Equals("287"))
                    {
                        var issuer = configuration["Jwt:Issuer"];
                        var audience = configuration["Jwt:Audience"];
                        var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"]);
                        var signingcredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature);


                        var subject = new ClaimsIdentity(new[]
                        {

                    new Claim(JwtRegisteredClaimNames.Sub as string,user.Username),
                    new Claim(JwtRegisteredClaimNames.Email as string,user.Username)


                });
                        var expires = DateTime.Now.AddMinutes(10);
                        var TokenDescriptor = new SecurityTokenDescriptor
                        {
                            Subject = subject,
                            Expires = expires,
                            Issuer = issuer,
                            Audience = audience,
                            SigningCredentials = signingcredentials
                        };
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var token = tokenHandler.CreateToken(TokenDescriptor);
                        var jwttoken = tokenHandler.WriteToken(token);
                        return Ok(jwttoken);
                    }
                }
                return response;
            }
        }
}
