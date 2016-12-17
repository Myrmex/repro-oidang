using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using OidAng.Models;

namespace OidAng.Services
{
    public sealed class DatabaseInitializer : IDatabaseInitializer
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public DatabaseInitializer(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _context = context;
            _roleManager = roleManager;
        }

        public async Task Seed()
        {
            await _context.Database.EnsureCreatedAsync();

            // users
            const string sEmail = "fake@nowhere.com";
            ApplicationUser user;
            if (await _userManager.FindByEmailAsync(sEmail) == null)
            {
                // use the create rather than addorupdate so can set password
                user = new ApplicationUser
                {
                    UserName = "zeus",
                    Email = sEmail,
                    EmailConfirmed = true,
                    FirstName = "John",
                    LastName = "Doe"
                };
                await _userManager.CreateAsync(user, "P4ssw0rd!");
            }

            user = await _userManager.FindByEmailAsync(sEmail);
            string sRoleName = "admin";
            if (await _roleManager.FindByNameAsync(sRoleName) == null)
                await _roleManager.CreateAsync(new IdentityRole { Name = sRoleName });

            if (!await _userManager.IsInRoleAsync(user, sRoleName))
                await _userManager.AddToRoleAsync(user, sRoleName);
        }
    }

    public interface IDatabaseInitializer
    {
        Task Seed();
    }
}
