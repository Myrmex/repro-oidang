using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace OidAng.Models
{
    public class ApplicationRole : IdentityRole
    {
        public ApplicationRole()
        {
        }

        public ApplicationRole(string roleName) : base(roleName)
        {
        }
    }
}
