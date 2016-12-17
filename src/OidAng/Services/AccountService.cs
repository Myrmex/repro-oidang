using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using OidAng.Models;

namespace OidAng.Services
{
    public sealed class AccountService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AccountService(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _context = context;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> Register(ApplicationUser user, string password,
            IEnumerable<IdentityRole> roles)
        {
            if (await _userManager.FindByEmailAsync(user.Email) != null)
                return new BadRequestObjectResult($"User {user.Email} already exists.");

            IdentityResult result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                return new ObjectResult($"User {user.Email} already exists.")
                {
                    StatusCode = (int)HttpStatusCode.InternalServerError
                };
            } //eif

            string code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            // TODO: send email
            return new OkObjectResult($"User {user.Email} created, confirmation email sent.");
        }

        public async Task<IActionResult> Confirm(string email, string code)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new BadRequestObjectResult($"Invalid email: {email}");

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, code);

            if (!result.Succeeded)
                return new BadRequestObjectResult($"Bad confirmation code for email: {email}");

            return new OkObjectResult($"User {email} confirmed");
        }
    }
}
