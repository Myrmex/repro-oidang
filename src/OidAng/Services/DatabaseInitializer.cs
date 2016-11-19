using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using OidAng.Models;
using OpenIddict;

namespace OidAng.Services
{
    public sealed class DatabaseInitializer : IDatabaseInitializer
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        public DatabaseInitializer(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _context = context;
            _roleManager = roleManager;
        }

        public async Task Seed()
        {
            await _context.Database.EnsureCreatedAsync();

            // Add Mvc.Client to the known applications.
            if (_context.Applications.Any())
            {
                foreach (OpenIddictApplication application in _context.Applications)
                    _context.Remove(application);
                _context.SaveChanges();
            }

            // no need to register an Application in this example
            //_context.Applications.Add(new Application
            //{
            //    Id = "openiddict-test",
            //    DisplayName = "My test application",
            //    RedirectUri = "http://localhost:58292/signin-oidc",
            //    LogoutRedirectUri = "http://localhost:58292/",
            //    Secret = Crypto.HashPassword("secret_secret_secret"),
            //    Type = OpenIddictConstants.ApplicationTypes.Public
            //});
            //_context.SaveChanges();

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
                await _roleManager.CreateAsync(new ApplicationRole { Name = sRoleName });

            if (!await _userManager.IsInRoleAsync(user, sRoleName))
                await _userManager.AddToRoleAsync(user, sRoleName);
        }
    }

    public interface IDatabaseInitializer
    {
        Task Seed();
    }
}
