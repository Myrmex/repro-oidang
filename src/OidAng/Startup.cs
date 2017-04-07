using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;
using OidAng.Models;
using OidAng.Services;

namespace OidAng
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            // allow overriding configuration values from user secrets/environment
            if (env.IsDevelopment())
                builder.AddUserSecrets("aspnet-oidang-04bb693a-d29e-4986-8721-351b6f7d5627");
            builder.AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // setup options with DI
            // https://docs.asp.net/en/latest/fundamentals/configuration.html
            services.AddOptions();

            // CORS (note: if using Azure, remember to enable CORS in the portal, too!)
            services.AddCors();

            // add entity framework and its context(s) using in-memory 
            // (or use the commented line to use a connection string to a real DB)
            services.AddEntityFrameworkSqlServer()
                .AddDbContext<ApplicationDbContext>(options =>
                {
                    // options.UseSqlServer(Configuration.GetConnectionString("Authentication")));
                    options.UseInMemoryDatabase();
                    // register the entity sets needed by OpenIddict.
                    // Note: use the generic overload if you need
                    // to replace the default OpenIddict entities.
                    options.UseOpenIddict();
                });

            // register the Identity services
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });

            // register the OpenIddict services
            services.AddOpenIddict(options =>
            {
                // register the Entity Framework stores
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();

                // register the ASP.NET Core MVC binder used by OpenIddict.
                // Note: if you don't call this method, you won't be able to
                // bind OpenIdConnectRequest or OpenIdConnectResponse parameters
                // to action methods. Alternatively, you can still use the lower-level
                // HttpContext.GetOpenIdConnectRequest() API.
                options.AddMvcBinders();

                // enable the endpoints
                options.EnableTokenEndpoint("/connect/token");
                options.EnableLogoutEndpoint("/connect/logout");
                // http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                options.EnableUserinfoEndpoint("/connect/userinfo");

                // enable the password flow
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                // during development, you can disable the HTTPS requirement
                options.DisableHttpsRequirement();

                // Note: to use JWT access tokens instead of the default
                // encrypted format, the following lines are required:
                // options.UseJsonWebTokens();
                // options.AddEphemeralSigningKey();
            });

            // add framework services
            services.AddMvc()
                .AddJsonOptions(options =>
                {
                    options.SerializerSettings.ContractResolver =
                        new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver();
                });

            // seed the database with the demo user details
            services.AddTransient<IDatabaseInitializer, DatabaseInitializer>();

            // swagger
            services.AddSwaggerGen();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory,
            IDatabaseInitializer databaseInitializer)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();
            loggerFactory.AddNLog();

            // https://docs.microsoft.com/en-us/aspnet/core/fundamentals/error-handling
            if (env.IsDevelopment()) app.UseDeveloperExceptionPage();

            // to serve up index.html
            app.UseDefaultFiles();
            app.UseStaticFiles();

            // CORS
            // https://docs.asp.net/en/latest/security/cors.html
            app.UseCors(builder =>
                    builder.WithOrigins("http://localhost:4200")
                        .AllowAnyHeader()
                        .AllowAnyMethod());

            // add a middleware used to validate access tokens and protect the API endpoints
            app.UseOAuthValidation();

            app.UseOpenIddict();

            app.UseMvc();

            // app.UseMvcWithDefaultRoute();
            // app.UseWelcomePage();

            // seed the database
            databaseInitializer.Seed().GetAwaiter().GetResult();

            // swagger
            // enable middleware to serve generated Swagger as a JSON endpoint
            app.UseSwagger();
            // enable middleware to serve swagger-ui assets (HTML, JS, CSS etc.)
            app.UseSwaggerUi();
        }
    }
}
