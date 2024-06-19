using GerKiss.Enums;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace GerKiss.Models
{
    public class UsuarioModel
    {
        public int Id { get; set; }
        public string Nome { get; set; }
        public DateTime DataNascimento { get; set; }
        public string Cpf { get; set; }
        public string Sex { get; set; } = string.Empty;
        public string Email { get; set; }
        public string Senha { get; set; }
        public PerfilEnum Perfil { get; set; }
        public DateTime DataCadastro { get; set; }
        public DateTime? DataAlteracao { get; set; }
    }

    public class UsuarioSignupModel
    {
        [Required(ErrorMessage = "O campo nome é obrigatório.")]
        public string Nome { get; set; }

        [Required(ErrorMessage = "O campo data de nascimento é obrigatório.")]
        [DataType(DataType.Date)]
        public DateTime DataNascimento { get; set; }


        [Required(ErrorMessage = "O campo CPF é obrigatório.")]
        public string Cpf { get; set; }


        [Required(ErrorMessage = "O campo email é obrigatório.")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }


        [Required(ErrorMessage = "O campo senha é obrigatório.")]
        [DataType(DataType.Password)]
        public string Senha { get; set; }


        public PerfilEnum Perfil { get; set; }
        public DateTime DataCadastro { get; set; }
    }

    public class UsuarioSigninModel
    {
        [Required(ErrorMessage = "O campo email é obrigatório.")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo senha é obrigatório.")]
        [DataType(DataType.Password)]
        public string Senha { get; set; }
    }

    public class  UsuarioSigninRespModel
    {
        public string id { get; set; }
        public string nome { get; set; }
        public string email { get; set; }
        public string token { get; set; }
    }
}
