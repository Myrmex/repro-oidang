using Microsoft.EntityFrameworkCore;
using OpenIddict;

namespace OidAng.Models
{
    public class ApplicationDbContext : OpenIddictDbContext<ApplicationUser, ApplicationRole>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
    }
}
