using GerKiss.Exceptions;
using GerKiss.Models;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using GerKiss.Services.Interfaces;
using GerKiss.Data;


namespace GerKiss.Services
{
    public class UsuarioService : IUsuarioService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly BancoContext _bancoContext;

        public UsuarioService(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            BancoContext bancoContext
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _bancoContext = bancoContext;
        }

        public async Task<ValidationResultModel> Register(UsuarioSignupModel usuario)
        {
            var user = new IdentityUser
            {
                UserName = usuario.Email,
                Email = usuario.Email
            };

            var result = await _userManager.CreateAsync(user, usuario.Senha);

            if (!result.Succeeded)
            {
                var errors = new List<ValidationError>();
                foreach (var error in result.Errors)
                {
                    errors.Add(new ValidationError(error.Description));
                }

                return new ValidationResultModel(400, errors);
            }

            await _userManager.AddToRoleAsync(user, usuario.Perfil.ToString());
            await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Name, usuario.Nome));
            await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.DateOfBirth, usuario.DataNascimento.ToString()));

            return new ValidationResultModel(200, [new("Usuário Cadastrado com Sucesso.")]);
        }

        public void Adicionar(UsuarioSignupModel usuario)
        {
            var user = new UsuarioModel
            {
                Nome = usuario.Nome,
                DataNascimento = usuario.DataNascimento,
                Cpf = usuario.Cpf,
                Email = usuario.Email,
                Senha = usuario.Senha,
                Perfil = usuario.Perfil,
                DataCadastro = DateTime.Now
            };

            _bancoContext.Usuarios.Add(user);
            _bancoContext.SaveChanges();
        }

        public async Task<UsuarioSigninRespModel> Signin(UsuarioSigninModel usuario)
        {
            var user = await _userManager.FindByEmailAsync(usuario.Email) ?? throw new DomainException("Email inválido.");

            var result = await _signInManager.PasswordSignInAsync(usuario.Email, usuario.Senha, false, false);

            if (!result.Succeeded)
            {
                return null;
            }

            var token = GenerateToken(user);
            var claims = await _userManager.GetClaimsAsync(user);
            var nomeClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var nome= nomeClaim?.Value;

            return new UsuarioSigninRespModel
            {
                id = user.Id,
                token = token,
                nome = nome,
                email = user.Email
            };
        }

        public async Task<UsuarioSigninRespModel> validateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["TokenConfigurations:SecretKey"]);

           tokenHandler.ValidateToken(token, new TokenValidationParameters
           {
               ValidateIssuerSigningKey = true,
               IssuerSigningKey = new SymmetricSecurityKey(key),
               ValidateIssuer = false,
               ValidateAudience = false,
               ValidateLifetime = true
           }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var email = jwtToken.Claims.First(x => x.Type == ClaimTypes.Email).Value;
            var user = await _userManager.FindByEmailAsync(email);

            var claims = await _userManager.GetClaimsAsync(user);
            var nomeClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var nome = nomeClaim?.Value;

            return new UsuarioSigninRespModel
            {
                id = user.Id,
                token = token,
                nome = nome,
                email = user.Email
            };
        }

        private string GenerateToken(IdentityUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["TokenConfigurations:SecretKey"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                    new Claim[]
                    {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Email, user.Email)
                    }
                ),
                Expires = DateTime.UtcNow.AddDays(2),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature
                )
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
