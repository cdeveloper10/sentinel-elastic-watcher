using System.Security.Claims;
using Sentinel.Application.Audit;
using Sentinel.Application.Security;

namespace Sentinel.Api.Auth;

/// <summary>
/// Who is making this request, resolved from the cookie and then re-read from the database.
///
/// Re-read on purpose. Permissions could be written into the cookie at sign-in and trusted until it
/// expires, which is one fewer query — but then a role taken away keeps working for the life of the
/// session, and this platform blocks network traffic. Revocation has to bite immediately.
/// </summary>
public sealed class CurrentUser(IHttpContextAccessor accessor, IIdentityService identity)
{
    public const string UserIdClaim = "sentinel:uid";

    private SignedInUser? _cached;
    private bool _loaded;

    public async ValueTask<SignedInUser?> GetAsync(CancellationToken ct = default)
    {
        if (_loaded)
            return _cached;

        _loaded = true;

        var context = accessor.HttpContext;
        var claim = context?.User.FindFirst(UserIdClaim)?.Value;

        if (claim is null || !int.TryParse(claim, out var userId))
            return _cached = null;

        // Once per request, not once per permission check.
        return _cached = await identity.LoadAsync(userId, ct);
    }

    /// <summary>The actor an audit entry is attributed to, with the address the request came from.</summary>
    public async ValueTask<Actor> ActorAsync(CancellationToken ct = default)
    {
        var user = await GetAsync(ct);
        var context = accessor.HttpContext;

        return new Actor(
            user?.Username ?? "anonymous",
            context?.Connection.RemoteIpAddress?.ToString(),
            context?.TraceIdentifier);
    }
}

/// <summary>
/// Turns a permission into a filter an endpoint carries.
///
/// Written as a filter rather than checked inside each handler so that an endpoint cannot be added
/// without deciding what it requires — the failure mode being a new write endpoint that quietly needs
/// nothing.
/// </summary>
public sealed class RequirePermissionFilter(string permission) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var current = context.HttpContext.RequestServices.GetRequiredService<CurrentUser>();
        var user = await current.GetAsync(context.HttpContext.RequestAborted);

        if (user is null)
            return Results.Json(new { error = "Not signed in." }, statusCode: StatusCodes.Status401Unauthorized);

        if (!user.Can(permission))
        {
            // Named, because "forbidden" with no detail sends people to the logs to find out which
            // permission they are missing.
            var audit = context.HttpContext.RequestServices.GetRequiredService<IAuditTrail>();

            await audit.RecordAsync(
                await current.ActorAsync(context.HttpContext.RequestAborted),
                "PERMISSION_DENIED",
                "endpoint",
                context.HttpContext.Request.Path,
                result: "DENIED",
                detail: $"Requires {permission}.");

            return Results.Json(
                new { error = $"This needs the '{permission}' permission.", required = permission },
                statusCode: StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }
}

public static class EndpointAuthExtensions
{
    /// <summary>Reads as the sentence it is: this endpoint requires this permission.</summary>
    public static RouteHandlerBuilder Requires(this RouteHandlerBuilder builder, string permission) =>
        builder.AddEndpointFilter(new RequirePermissionFilter(permission));

    public static RouteGroupBuilder Requires(this RouteGroupBuilder builder, string permission) =>
        builder.AddEndpointFilter(new RequirePermissionFilter(permission));

    /// <summary>A signed-in user, whatever their permissions.</summary>
    public static RouteHandlerBuilder RequiresSignIn(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter(async (context, next) =>
        {
            var current = context.HttpContext.RequestServices.GetRequiredService<CurrentUser>();

            return await current.GetAsync(context.HttpContext.RequestAborted) is null
                ? Results.Json(new { error = "Not signed in." }, statusCode: StatusCodes.Status401Unauthorized)
                : await next(context);
        });
}

/// <summary>Signs a user in and out of the cookie scheme.</summary>
public static class SignInCookie
{
    public const string Scheme = "sentinel";

    public static ClaimsPrincipal Principal(SignedInUser user) =>
        new(new ClaimsIdentity(
            [
                new Claim(CurrentUser.UserIdClaim, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username)
            ],
            Scheme));
}
