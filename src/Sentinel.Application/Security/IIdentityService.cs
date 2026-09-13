using Sentinel.Domain.Platform;

namespace Sentinel.Application.Security;

public sealed record SignedInUser(
    int Id,
    string Username,
    string DisplayName,
    IReadOnlySet<string> Permissions,
    IReadOnlyList<string> Roles)
{
    public bool Can(string permission) => Permissions.Contains(permission);
}

public sealed record SignInResult(bool Succeeded, SignedInUser? User, string? Failure)
{
    public static SignInResult Success(SignedInUser user) => new(true, user, null);

    /// <summary>
    /// One message for every kind of failure. Distinguishing "no such user" from "wrong password" tells an
    /// attacker which usernames exist, and a locked account is worth knowing about only to somebody who
    /// already has the password.
    /// </summary>
    public static SignInResult Refused() => new(false, null, "That username and password were not accepted.");

    public static SignInResult Disabled() => new(false, null, "That account is disabled.");
}

/// <summary>Who may sign in, and what they may then do.</summary>
public interface IIdentityService
{
    Task<SignInResult> SignInAsync(string username, string password, CancellationToken ct = default);

    /// <summary>
    /// Re-reads permissions for an already-authenticated session.
    ///
    /// Called on each request rather than trusting what was written into the cookie at sign-in: a role
    /// taken away has to take effect before the cookie expires, and for a platform that blocks addresses
    /// automatically, "their access was revoked an hour ago but the session is still good" is not
    /// acceptable.
    /// </summary>
    Task<SignedInUser?> LoadAsync(int userId, CancellationToken ct = default);

    Task<IReadOnlyList<PlatformUser>> ListAsync(CancellationToken ct = default);

    Task<(bool Created, string? Failure, int UserId)> CreateAsync(
        string username, string displayName, string password, IReadOnlyList<string> roles,
        CancellationToken ct = default);

    Task<bool> SetEnabledAsync(int userId, bool enabled, CancellationToken ct = default);

    Task<(bool Changed, string? Failure)> SetPasswordAsync(
        int userId, string password, CancellationToken ct = default);

    Task<bool> SetRolesAsync(int userId, IReadOnlyList<string> roles, CancellationToken ct = default);

    Task<IReadOnlyList<PlatformRole>> RolesAsync(CancellationToken ct = default);

    /// <summary>
    /// Creates the built-in roles and, when no account exists at all, a first administrator.
    ///
    /// Returns the generated password exactly once, at the moment of creation, because a platform that
    /// ships with a known default password is a platform with no password.
    /// </summary>
    Task<string?> EnsureSeededAsync(CancellationToken ct = default);
}
