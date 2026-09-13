using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api;
using Sentinel.Api.Auth;
using Sentinel.Api.Endpoints;
using Sentinel.Application.Security;
using Sentinel.Infrastructure;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Infrastructure.Security;

// The control plane: the REST API and the console that sits on it.
//
// Composed without AddSentinelEngine, so nothing here evaluates a rule on a schedule. Several of these can
// run against one engine — they scale on how many people are reading, which has nothing to do with how
// large the estate being watched is.

var builder = WebApplication.CreateBuilder(args);

var connection = builder.Configuration.GetConnectionString("Sentinel")
                 ?? throw new InvalidOperationException(
                     "ConnectionStrings:Sentinel is required. Supply it from the environment.");

builder.Services.AddSentinel(builder.Configuration, builder.Environment.IsProduction());
builder.Services.AddSentinelPersistence(connection);

builder.Services.AddScoped<IIdentityService, IdentityService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<CurrentUser>();
builder.Services.AddProblemDetails();

// Session keys in the database rather than on the pod. ASP.NET Core builds a key ring per process by
// default, so two API replicas sign cookies with different keys — everyone is signed out the moment the
// load balancer sends them to the other pod, and it looks like an authentication bug rather than a
// deployment one. The application name is pinned because it otherwise derives from the content root,
// which is a path that can differ between a container and a developer's machine.
builder.Services
    .AddDataProtection()
    .SetApplicationName("sentinel")
    .PersistKeysToDbContext<SentinelDbContext>();

// Behind an ingress the socket address is the proxy's, so every audit row would record the proxy rather
// than the person — on a platform whose whole output is "who did what". X-Forwarded-For is trusted only
// from networks an operator has named: a header anyone can set is not evidence, and defaulting to
// trusting it would let a caller write whatever address they liked into the audit trail.
var trustedProxies = builder.Configuration.GetSection("Hosting:TrustedProxies").Get<string[]>() ?? [];

if (trustedProxies.Length > 0)
{
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

        // Cleared because both default to loopback only, which is never where a Kubernetes ingress sits.
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();

        foreach (var network in trustedProxies)
        {
            // TryParse rather than the constructor: it also rejects a range whose host bits are set, which
            // is the mistake an operator actually makes, and which would otherwise stop the pod on startup
            // with a framework message that never names the setting it came from.
            if (System.Net.IPNetwork.TryParse(network, out var range))
                options.KnownIPNetworks.Add(range);
            else if (IPAddress.TryParse(network, out var proxy))
                options.KnownProxies.Add(proxy);
            else
                throw new InvalidOperationException(
                    $"Hosting:TrustedProxies contains '{network}', which is neither an address nor a CIDR " +
                    "range with its host bits cleared - write '10.42.0.0/16', not '10.42.0.5/16'.");
        }
    });
}

builder.Services
    .AddAuthentication(SignInCookie.Scheme)
    .AddCookie(SignInCookie.Scheme, options =>
    {
        options.Cookie.Name = "sentinel.session";
        options.Cookie.HttpOnly = true;

        // Lax, not Strict. Strict withholds the cookie on any navigation that started somewhere else, so
        // following a link to an alert — from a chat message, a ticket, an email — lands on a sign-in page
        // even though the session is valid. For a platform whose whole job is to tell people to come and
        // look at something, that is the common case rather than an edge one.
        //
        // Lax still withholds it from cross-site POST, which is the request shape CSRF needs.
        options.Cookie.SameSite = SameSiteMode.Lax;

        // Always over HTTPS outside development. A session cookie for a console that blocks network
        // traffic must not travel in the clear.
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;

        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;

        // This is an API behind a single-page console: a redirect to a login page would arrive at fetch()
        // as a 200 containing HTML, which is worse than an honest status.
        options.Events.OnRedirectToLogin = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Roles are reconciled with the code on every start, and a first administrator is created only when no
// account exists at all. The generated password is printed once — a platform that ships with a known
// default password is a platform with no password, and this one can block traffic.
await using (var scope = app.Services.CreateAsyncScope())
{
    // Resolved before anything serves traffic so a malformed encryption key fails the boot rather than the
    // first request that happens to touch a credential — which would be a pod that starts, passes its
    // readiness probe, and then cannot read a single connection.
    _ = scope.ServiceProvider.GetRequiredService<ISecretProtector>();

    if (builder.Configuration.GetValue("Database:MigrateOnStartup", false))
        await scope.ServiceProvider.GetRequiredService<SentinelDbContext>().Database.MigrateAsync();

    var identity = scope.ServiceProvider.GetRequiredService<IIdentityService>();
    var seeded = await identity.EnsureSeededAsync();

    if (seeded is not null)
    {
        app.Logger.LogWarning(
            "First run. Sign in as 'admin' with this password, then change it — it is not stored anywhere " +
            "it can be read back:\n\n    {Password}\n", seeded);
    }

    // The way back in when nobody can get in: a locked-out administrator, a lost password, an identity
    // provider that has not been wired up yet. Guarded by shell access to the process rather than by a
    // permission, because the case it exists for is precisely that no usable account remains.
    if (args.Contains("--reset-admin-password"))
    {
        var reset = await ResetAdminPasswordAsync(scope.ServiceProvider);

        app.Logger.LogWarning(
            "Reset the password for '{Username}'. It is printed once:\n\n    {Password}\n",
            reset.Username, reset.Password);

        return;
    }
}

// A malformed request — a missing required query parameter, a body that is not JSON — raises
// BadHttpRequestException, which carries the status it deserves. The default handler ignores that and
// answers 500, so a client that spelled a parameter wrong is told the server broke, and the mistake
// lands in whatever alerts on the 5xx rate. Read the status off the exception and keep 500 for the
// failures that really are the platform's.
// Before anything reads an address or a scheme. Only populated when Hosting:TrustedProxies names the
// networks the proxy sits in; otherwise the socket address stands, which is correct and unspoofable.
if (trustedProxies.Length > 0)
    app.UseForwardedHeaders();

app.UseExceptionHandler(errors => errors.Run(async context =>
{
    var thrown = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;

    var status = RequestFailure.StatusFor(thrown);

    await Results
        .Problem(
            statusCode: status,
            detail: RequestFailure.MayDisclose(status) ? thrown?.Message : null)
        .ExecuteAsync(context);
}));
app.UseStatusCodePages();

app.UseDefaultFiles();

// no-cache, not no-store: a browser may keep the file but must ask whether it is still current, and an
// unchanged one comes back as a 304 — one round trip, no bytes.
//
// The console's assets are not fingerprinted — app.js, not app.8f3a91.js — so a browser allowed to cache
// them serves the old console against the new API after an upgrade. That failure is a nasty one here
// because it is per-person and invisible from the cluster: every pod healthy, the API new, and one
// operator's console silently a version behind. Found exactly that way, watching a dashboard render from
// a script the server had already replaced.
//
// These files are tens of kilobytes served from the pod. Revalidating them is not a cost worth trading
// correctness for.
var consoleFiles = new StaticFileOptions
{
    OnPrepareResponse = context =>
        context.Context.Response.Headers.CacheControl = "no-cache, must-revalidate"
};

app.UseStaticFiles(consoleFiles);

app.UseAuthentication();
app.UseAuthorization();

// -- health, before anything that needs a database or a session -------------------------------

app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }));

app.MapGet("/health/ready", async (SentinelDbContext db, CancellationToken ct) =>
    await db.Database.CanConnectAsync(ct)
        ? Results.Ok(new { status = "ready" })
        : Results.Json(new { status = "unready", reason = "database unreachable" }, statusCode: 503));

// -- the estate --------------------------------------------------------------------------------

app.MapAuth();
app.MapUsers();
app.MapConnections();
app.MapRules();
app.MapAlerts();
app.MapOperations();

// Anything that is not an API call and not a file falls through to the console, so its client-side
// routes survive a refresh.
//
// Given the same options as UseStaticFiles above, because it does its own serving and would otherwise
// answer without them — and this is the path that matters most: /alerts and / are how people arrive, so
// caching *these* is what pins a browser to an old console after an upgrade.
app.MapFallbackToFile("index.html", consoleFiles);

await app.RunAsync();

/// <summary>
/// Gives the first administrator a new generated password and makes sure the account can be used.
///
/// Deliberately re-enables the account and restores the Admin role as well as setting the password: the
/// situation this is reached in is "nobody can administer the platform", and fixing only the password
/// would leave a disabled or de-roled account still unable to sign in.
/// </summary>
static async Task<(string Username, string Password)> ResetAdminPasswordAsync(IServiceProvider services)
{
    var identity = services.GetRequiredService<IIdentityService>();
    var users = await identity.ListAsync();

    var admin = users.FirstOrDefault(u => u.Username == "admin") ?? users.FirstOrDefault();

    if (admin is null)
        throw new InvalidOperationException("There are no accounts to reset. Start once to seed the first one.");

    var password = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18))
        .Replace("+", "").Replace("/", "").Replace("=", "");

    var (changed, failure) = await identity.SetPasswordAsync(admin.Id, password);
    if (!changed)
        throw new InvalidOperationException($"Could not reset the password: {failure}");

    await identity.SetEnabledAsync(admin.Id, true);
    await identity.SetRolesAsync(admin.Id, [SystemRole.Admin]);

    return (admin.Username, password);
}

/// <summary>Public so a test host can reference this assembly.</summary>
public partial class Program;
