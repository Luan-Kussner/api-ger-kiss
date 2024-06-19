using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using GerKiss.Models;

namespace GerKiss.Data
{
    public class BancoContext : IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        public BancoContext(DbContextOptions<BancoContext> options) : base(options)
        {
        }
        public DbSet<UsuarioModel> Usuarios { get; set; }
    }
}
