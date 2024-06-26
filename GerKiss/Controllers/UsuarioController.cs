using GerKiss.Exceptions;
using GerKiss.Models;
using GerKiss.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace GerKiss.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsuarioController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IUsuarioService _usuarioService;

        public UsuarioController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            IUsuarioService usuarioService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _usuarioService = usuarioService;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody] UsuarioSignupModel usuario)
        {
            if (!ModelState.IsValid)
            {
                var errors = new List<ValidationError>();
                foreach (var modelState in ModelState.Values)
                    foreach (var error in modelState.Errors)
                        errors.Add(new ValidationError(error.ErrorMessage));

                return BadRequest(new ValidationResultModel(400, errors));
            }

            try
            {
                var result = await _usuarioService.Register(usuario);

                if (result.Status == 200)
                {
                    _usuarioService.Adicionar(usuario);
                    return Ok(usuario);
                }

                return BadRequest(result);
            }
            catch (Exception ex)
            {
                var errors = new List<ValidationError> { new(ex.Message) };
                return BadRequest(new ValidationResultModel(400, errors));
            }
        }

        [HttpPost("signin")]
        public async Task<IActionResult> Signin([FromBody] UsuarioSigninModel usuario)
        {
            if (!ModelState.IsValid)
            {
                var errors = new List<ValidationError>();
                foreach (var modelState in ModelState.Values)
                    foreach (var error in modelState.Errors)
                        errors.Add(new ValidationError(error.ErrorMessage));

                return BadRequest(new ValidationResultModel(400, errors));
            }

            try
            {
                var result = await _usuarioService.Signin(usuario);

                if (result == null)
                    return BadRequest(
                        new ValidationResultModel(401, [new("Email e/ou senha incorreto.")])
                    );

                return Ok(result);
            }
            catch (Exception ex)
            {
                var errors = new List<ValidationError> { new(ex.Message) };
                return BadRequest(new ValidationResultModel(400, errors));
            }
        }   

        [HttpGet("validate")]
        public async Task<IActionResult> ValidateToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["TokenConfigurations:SecretKey"]);

            try
            {
                var authorizationHeader = Request.Headers.Authorization.ToString();
                if (
                    string.IsNullOrEmpty(authorizationHeader)
                    || !authorizationHeader.StartsWith("Bearer ")
                )
                    return BadRequest(new ValidationResultModel(401, [new("token inválido.")]));


                var token = authorizationHeader.Substring("Bearer ".Length).Trim();

                var user = await _usuarioService.validateToken(token);

                if (user == null)
                    return BadRequest();

                return Ok(user);
            }
            catch (Exception ex)
            {
                var errors = new List<ValidationError> { new(ex.Message) };
                return BadRequest(new ValidationResultModel(400, errors));
            }
        }

        [HttpGet("usuarios")]
        public IActionResult GetAllUsers()
        {
            try
            {
                var usuarios = _usuarioService.BuscarTodosUsuarios();
                return Ok(usuarios);
            }
            catch (Exception ex)
            {
                var errors = new List<ValidationError> { new ValidationError(ex.Message) };
                return BadRequest(new ValidationResultModel(400, errors));
            }
        }


        [HttpGet("{id}")]
        public IActionResult Get([FromRoute] int id)
        {
            try
            {
                var usuario = _usuarioService.BuscarUsuarioPorId(id);
                if (usuario == null)
                {
                    return NotFound(new { message = "Usuário não encontrado." });
                }
                return Ok(usuario);
            }
            catch (Exception ex)
            {
                var errors = new List<ValidationError> { new ValidationError(ex.Message) };
                return BadRequest(new ValidationResultModel(400, errors));
            }
        }

    }
}
