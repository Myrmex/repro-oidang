﻿using AspNet.Security.OpenIdConnect.Primitives;
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
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            // allow overriding configuration values from user secrets/environment
            if (env.IsDevelopment()) builder.AddUserSecrets();
            builder.AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // setup options with DI
            // https://docs.asp.net/en/latest/fundamentals/configuration.html
            services.AddOptions();

            // CORS
            services.AddCors();

            // add entity framework and its context(s) using in memory (or config connection string)
            services.AddEntityFrameworkSqlServer()
                .AddDbContext<ApplicationDbContext>(options =>
                {
                    // options.UseSqlServer(Configuration.GetConnectionString("Authentication")));
                    options.UseInMemoryDatabase();
                    options.UseOpenIddict();
                });

            // add identity
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

            // add OpenIddict
/*            services.AddOpenIddict()
                // Register the Entity Framework stores.
                .AddEntityFrameworkCoreStores<ApplicationDbContext>()
                .DisableHttpsRequirement()
                .EnableTokenEndpoint("/connect/token")
                .EnableLogoutEndpoint("/connect/logout")
                // http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                .EnableUserinfoEndpoint("/connect/userinfo")
                .AllowPasswordFlow()
                .AllowRefreshTokenFlow()
                .AddEphemeralSigningKey();
*/
            services.AddOpenIddict(options =>
            {
                // Register the Entity Framework stores.
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();

                // Register the ASP.NET Core MVC binder used by OpenIddict.
                // Note: if you don't call this method, you won't be able to
                // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
                // options.AddMvcBinders();

                // Enable the token endpoint.
                options.EnableTokenEndpoint("/connect/token");
                options.EnableLogoutEndpoint("/connect/logout");
                // http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                options.EnableUserinfoEndpoint("/connect/userinfo");

                // Enable the password flow.
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();
                options.AddEphemeralSigningKey();

                // During development, you can disable the HTTPS requirement.
                options.DisableHttpsRequirement();

                // Note: to use JWT access tokens instead of the default
                // encrypted format, the following lines are required:
                //
                // options.UseJsonWebTokens();
                // options.AddEphemeralSigningKey();
            });
///////////////

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

            // to serve up index.html
            app.UseDefaultFiles();
            app.UseStaticFiles();

            // CORS
            // https://docs.asp.net/en/latest/security/cors.html
            app.UseCors(builder =>
                    builder.WithOrigins("http://localhost:4200")
                        .AllowAnyHeader()
                        .AllowAnyMethod());

            // Add a middleware used to validate access tokens and protect the API endpoints.
            app.UseOAuthValidation();

            app.UseOpenIddict();

            app.UseMvc();

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
