using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Security;
using Sentinel.Domain.Platform;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Infrastructure.Security;

public sealed class IdentityService(
    SentinelDbContext db,
    TimeProvider clock,
    ILogger<IdentityService> logger) : IIdentityService
{
    public async Task<SignInResult> SignInAsync(string username, string password, CancellationToken ct = default)
    {
        var user = await db.Users
            .Include(u => u.Roles).ThenInclude(r => r.Role)
            .FirstOrDefaultAsync(u => u.Username == username, ct);

        if (user is null)
        {
            // Still hashes, so a missing account takes about as long as a wrong password. Returning
            // immediately makes username enumeration a matter of timing the response.
            PasswordHasher.Verify(password, PasswordHasher.Hash("absent-account-placeholder", 1_000));
            return SignInResult.Refused();
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
            return SignInResult.Refused();

        if (!user.Enabled)
            return SignInResult.Disabled();

        // Quietly upgrade a hash written under weaker parameters, so raising the iteration count applies
        // to existing accounts and not only to new ones.
        if (PasswordHasher.NeedsRehash(user.PasswordHash))
            user.PasswordHash = PasswordHasher.Hash(password);

        user.LastLoginAt = clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);

        return SignInResult.Success(Describe(user));
    }

    public async Task<SignedInUser?> LoadAsync(int userId, CancellationToken ct = default)
    {
        var user = await db.Users.AsNoTracking()
            .Include(u => u.Roles).ThenInclude(r => r.Role)
            .FirstOrDefaultAsync(u => u.Id == userId, ct);

        // A disabled account reads as absent, so an open session stops working the moment it is disabled
        // rather than when its cookie expires.
        return user is null || !user.Enabled ? null : Describe(user);
    }

    public async Task<IReadOnlyList<PlatformUser>> ListAsync(CancellationToken ct = default) =>
        await db.Users.AsNoTracking()
            .Include(u => u.Roles).ThenInclude(r => r.Role)
            .OrderBy(u => u.Username)
            .ToListAsync(ct);

    public async Task<(bool Created, string? Failure, int UserId)> CreateAsync(
        string username, string displayName, string password, IReadOnlyList<string> roles,
        CancellationToken ct = default)
    {
        username = username?.Trim().ToLowerInvariant() ?? "";

        if (username.Length is < 2 or > 128)
            return (false, "A username is 2 to 128 characters.", 0);

        var policy = PasswordPolicy.Check(password, username);
        if (policy is not null)
            return (false, policy, 0);

        if (await db.Users.AnyAsync(u => u.Username == username, ct))
            return (false, $"'{username}' already exists.", 0);

        var user = new PlatformUser
        {
            Username = username,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
            PasswordHash = PasswordHasher.Hash(password),
            Enabled = true,
            CreatedAt = clock.GetUtcNow().UtcDateTime
        };

        db.Users.Add(user);
        await db.SaveChangesAsync(ct);

        await SetRolesAsync(user.Id, roles, ct);

        return (true, null, user.Id);
    }

    public async Task<bool> SetEnabledAsync(int userId, bool enabled, CancellationToken ct = default)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
            return false;

        user.Enabled = enabled;
        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<(bool Changed, string? Failure)> SetPasswordAsync(
        int userId, string password, CancellationToken ct = default)
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
            return (false, "No such user.");

        var policy = PasswordPolicy.Check(password, user.Username);
        if (policy is not null)
            return (false, policy);

        user.PasswordHash = PasswordHasher.Hash(password);
        await db.SaveChangesAsync(ct);

        return (true, null);
    }

    public async Task<bool> SetRolesAsync(int userId, IReadOnlyList<string> roles, CancellationToken ct = default)
    {
        var user = await db.Users.Include(u => u.Roles).FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
            return false;

        var wanted = await db.Roles
            .Where(r => roles.Contains(r.Name))
            .Select(r => r.Id)
            .ToListAsync(ct);

        db.UserRoles.RemoveRange(user.Roles);
        foreach (var roleId in wanted)
            db.UserRoles.Add(new PlatformUserRole { UserId = userId, RoleId = roleId });

        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<IReadOnlyList<PlatformRole>> RolesAsync(CancellationToken ct = default) =>
        await db.Roles.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);

    public async Task<string?> EnsureSeededAsync(CancellationToken ct = default)
    {
        foreach (var (name, definition) in SystemRole.Definitions)
        {
            var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == name, ct);

            if (role is null)
            {
                db.Roles.Add(new PlatformRole
                {
                    Name = name,
                    Description = definition.Description,
                    PermissionsJson = RolePermissions.Write(definition.Permissions),
                    IsSystem = true
                });
            }
            else if (role.IsSystem)
            {
                // Kept in step with the code, so a permission added in a release reaches the roles that
                // should have it instead of waiting for somebody to notice.
                role.Description = definition.Description;
                role.PermissionsJson = RolePermissions.Write(definition.Permissions);
            }
        }

        await db.SaveChangesAsync(ct);

        if (await db.Users.AnyAsync(ct))
            return null;

        // A generated password, printed once. A platform that ships with a known default password is a
        // platform with no password, and this one can block traffic.
        var password = GeneratePassword();
        var (created, failure, userId) = await CreateAsync("admin", "Administrator", password, [SystemRole.Admin], ct);

        if (!created)
        {
            logger.LogError("Could not create the first administrator: {Failure}", failure);
            return null;
        }

        logger.LogWarning(
            "Created the first administrator (id {UserId}). The password is printed once and not stored anywhere recoverable.",
            userId);

        return password;
    }

    private static SignedInUser Describe(PlatformUser user)
    {
        var roles = user.Roles.Select(r => r.Role?.Name).Where(n => n is not null).Select(n => n!).ToList();

        var permissions = RolePermissions.Effective(
            user.Roles.Select(r => r.Role?.PermissionsJson ?? "[]"));

        return new SignedInUser(user.Id, user.Username, user.DisplayName, permissions, roles);
    }

    /// <summary>Long rather than clever: length is what a machine has to work at.</summary>
    private static string GeneratePassword()
    {
        const string alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var characters = new char[24];

        for (var i = 0; i < characters.Length; i++)
            characters[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];

        return new string(characters);
    }
}
