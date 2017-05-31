# OpenIdDict with Angular2 (Credentials Flow)

Sample token request:

```http
POST http://localhost:50728/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&scope=offline_access profile email roles&resource=http://localhost:4200&username=zeus&password=P4ssw0rd!
```

After getting the token in the response, make requests like:

```http
GET http://localhost:50728/api/values
Content-Type: application/json
Authorization: Bearer ...
```

The sample for this flow in OpenIdDict is located at https://github.com/openiddict/openiddict-samples/blob/master/samples/PasswordFlow/AuthorizationServer/Startup.cs .

## Server side

1.create a new WebAPI app without any authentication.

2.add the appropriate MyGet repositories to your NuGet sources. This can be done by adding a new `NuGet.Config` file at the root of your solution:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="NuGet" value="https://api.nuget.org/v3/index.json" />
    <add key="aspnet-contrib" value="https://www.myget.org/F/aspnet-contrib/api/v3/index.json" />
  </packageSources>
</configuration>
```

3.ensure that you have these packages in the project (you can list them using a NuGet command like `get-package | Format-Table -AutoSize` in the NuGet console):

```
AspNet.Security.OAuth.Validation
MailKit
Microsoft.AspNetCore.Authentication.Cookies
Microsoft.AspNetCore.Authentication.JwtBearer
Microsoft.AspNetCore.Diagnostics
Microsoft.AspNetCore.Identity.EntityFrameworkCore
Microsoft.AspNetCore.Mvc
Microsoft.AspNetCore.Routing
Microsoft.AspNetCore.Server.IISIntegration
Microsoft.AspNetCore.Server.Kestrel
Microsoft.AspNetCore.StaticFiles
Microsoft.EntityFrameworkCore.InMemory
Microsoft.EntityFrameworkCore.SqlServer
Microsoft.Extensions.Configuration.CommandLine
Microsoft.Extensions.Configuration.EnvironmentVariables
Microsoft.Extensions.Configuration.FileExtensions
Microsoft.Extensions.Configuration.Json
Microsoft.Extensions.Configuration.UserSecrets
Microsoft.Extensions.Logging
Microsoft.Extensions.Logging.Console
Microsoft.Extensions.Logging.Debug
Microsoft.Extensions.Options.ConfigurationExtensions
Microsoft.NETCore.App
NLog.Extensions.Logging
OpenIddict
OpenIddict.EntityFrameworkCore
OpenIddict.Mvc
Swashbuckle
```

MailKit is used for mailing, Swashbuckle for Swagger, NLog for file-based logging.

4.in `Program.cs`, you can configure logging:

```c#
// ...
using Microsoft.Extensions.Logging;

public static void Main(string[] args)
{
    var configuration = new ConfigurationBuilder()
        .AddEnvironmentVariables()
        .AddCommandLine(args)
        .Build();

    IWebHost host = new WebHostBuilder()
        .ConfigureLogging(options => options.AddConsole())
        .ConfigureLogging(options => options.AddDebug())
        .UseKestrel()
        .UseContentRoot(Directory.GetCurrentDirectory())
        .UseIISIntegration()
        .UseStartup<Startup>()
        .Build();

    host.Run();
}
```

5.under `Models`, add identity models (`ApplicationUser`, `ApplicationDbContext`).

6.under `Services`, add `DatabaseInitializer` and `AccountService.cs`.

7.eventually, add your database connection string to `appsettings.json`. You will then override it using an environment variable source (or a production-targeted version of appsettings) for production. 

Alternatively, just use an in-memory database (see below).

8.`Startup.cs/ConfigureServices`: in **constructor**, add these lines to allow overriding configuration values from user secrets or environment variables:

```c#
// allow overriding configuration values from user secrets/environment
if (env.IsDevelopment()) builder.AddUserSecrets();
builder.AddEnvironmentVariables();
```

in **ConfigureServices**, add (*before* `AddMvc`):

```c#
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

// add OpenIddict
services.AddOpenIddict()
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
```

To output camel-cased property names in JSON, append to `AddMvc()`:

```c#
.AddJsonOptions(options =>
{
    options.SerializerSettings.ContractResolver =
        new Newtonsoft.Json.Serialization.CamelCasePropertyNamesContractResolver();
});
```

Finally, add (*after* `AddMvc()`):

```c#
// add my services
// services.AddTransient<ISomeService, SomeServiceImpl>();

// seed the database
services.AddTransient<IDatabaseInitializer, DatabaseInitializer>();

// swagger
services.AddSwaggerGen();
```

In **Configure** (requires `using NLog.Extensions.Logging;`):

- add as parameter `IDatabaseInitializer databaseInitializer`. This will be injected by DI.
- add NLog after the other loggers: `loggerFactory.AddNLog();`.
- add *before* `UseMvc()`:

```c#
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
```

Note: if deploying to Azure, ensure to CORS-enable your web app in the portal too.

- add *after* `UseMvc()`:

```c#
// seed the database
databaseInitializer.Seed().GetAwaiter().GetResult();

//needed for non-NETSTANDARD platforms: configure nlog.config in your project root
env.ConfigureNLog("nlog.config");

// swagger
// enable middleware to serve generated Swagger as a JSON endpoint
app.UseSwagger();
// enable middleware to serve swagger-ui assets (HTML, JS, CSS etc.)
app.UseSwaggerUi();
```

Note that if you want to add tables to an existing database the seed does not seem to work.

9.for NLog, add file `nlog.config` to your project's root. Here is a sample:

```xml
<?xml version="1.0" encoding="utf-8" ?>
<nlog xmlns="http://www.nlog-project.org/schemas/NLog.xsd"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      autoReload="true"
      internalLogLevel="Warn"
      internalLogFile="c:\temp\internal-nlog.txt">

  <!-- define various log targets -->
  <targets>
    <!-- write logs to file -->
    <target xsi:type="File" name="allfile" fileName="c:\temp\nlog-all-${shortdate}.log"
                 layout="${longdate}|${event-properties:item=EventId.Id}|${logger}|${uppercase:${level}}|${message} ${exception}" />

   
    <target xsi:type="File" name="ownFile-web" fileName="c:\temp\nlog-own-${shortdate}.log"
             layout="${longdate}|${event-properties:item=EventId.Id}|${logger}|${uppercase:${level}}|  ${message} ${exception}" />

    <target xsi:type="Null" name="blackhole" />
  </targets>

  <rules>
    <!--All logs, including from Microsoft-->
    <logger name="*" minlevel="Trace" writeTo="allfile" />

    <!--Skip Microsoft logs and so log only own logs-->
    <logger name="Microsoft.*" minlevel="Trace" writeTo="blackhole" final="true" />
    <logger name="*" minlevel="Trace" writeTo="ownFile-web" />
  </rules>
</nlog>
```

10.under `Controllers`, add `AuthorizationController.cs`.

11.in the `csproj` file add your user secrets ID if you are going to use the secrets manager, e.g.:

```xml
<UserSecretsId>aspnet-oidang-04bb693a-d29e-4986-8721-351b6f7d5627</UserSecretsId>
```

(change the GUID with another one, e.g. from https://www.guidgen.com/, or use any other unique ID for your app).

- for NLog: under `publishOptions`, add:

```json
"include": [
	...
	"nlog.config"
]
```

To secure your API, add an `[Authorize]` or `[Authorize(Roles = "some roles here")]` attribute to your controller or controller's method.

**Last updated: May 31, 2017**
