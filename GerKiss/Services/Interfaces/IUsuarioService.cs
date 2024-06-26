using GerKiss.Models;
using GerKiss.Exceptions;

namespace GerKiss.Services.Interfaces
{
    public interface IUsuarioService
    {
        Task<ValidationResultModel> Register(UsuarioSignupModel usuario);
        Task<UsuarioSigninRespModel> Signin(UsuarioSigninModel usuario);
        Task<UsuarioSigninRespModel> validateToken(string token);
        void Adicionar(UsuarioSignupModel usuario);
        UsuarioModel BuscarUsuarioPorId(int id);

        List<UsuarioModel> BuscarTodosUsuarios();


    }
}
