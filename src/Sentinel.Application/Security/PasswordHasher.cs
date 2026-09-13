using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Application.Security;

/// <summary>
/// Stores a password so that holding the store does not mean holding the password.
///
/// PBKDF2-HMAC-SHA256, from the BCL rather than from a package. Argon2id would be a better choice on a
/// greenfield service, but it needs a dependency and PBKDF2 with a high iteration count is what OWASP
/// still accepts — the failure mode that actually happens is a low iteration count or a shared salt, and
/// both of those are decided here rather than by the algorithm.
///
/// The format carries its own parameters, so raising the iteration count later does not invalidate
/// existing hashes: an old hash still verifies against the count it was written with.
/// </summary>
public static class PasswordHasher
{
    /// <summary>OWASP's floor for PBKDF2-HMAC-SHA256 at the time of writing.</summary>
    public const int DefaultIterations = 600_000;

    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Prefix = "pbkdf2-sha256";

    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        // Per password, never shared. A shared salt lets one rainbow table cover every account at once.
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, iterations);

        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string? stored)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(stored))
            return false;

        var parts = stored.Split('$');

        if (parts.Length != 4 || parts[0] != Prefix || !int.TryParse(parts[1], out var iterations))
            return false;

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || expected.Length == 0 || iterations < 1)
            return false;

        var actual = Derive(password, salt, iterations, expected.Length);

        // Fixed-time: comparing byte by byte and returning early leaks how much of the hash matched, which
        // over enough attempts recovers it.
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Whether a stored hash was written with weaker parameters than the current ones, so a successful
    /// sign-in can quietly upgrade it. Without this the iteration count only ever applies to new accounts.
    /// </summary>
    public static bool NeedsRehash(string? stored, int iterations = DefaultIterations)
    {
        if (string.IsNullOrWhiteSpace(stored))
            return true;

        var parts = stored.Split('$');

        return parts.Length != 4
               || parts[0] != Prefix
               || !int.TryParse(parts[1], out var used)
               || used < iterations;
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int length = HashBytes) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, length);
}

/// <summary>
/// What a password must be before it is accepted.
///
/// Length first and everything else second, which is the opposite of the usual composition rules:
/// character-class requirements push people towards <c>Password1!</c> while a length floor pushes them
/// towards something a machine has to work at.
/// </summary>
public static class PasswordPolicy
{
    public const int MinimumLength = 12;
    public const int MaximumLength = 256;

    /// <summary>Refused outright, however long. A dictionary is out of scope; the obvious ones are not.</summary>
    private static readonly HashSet<string> Obvious = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password123", "administrator", "changeme", "letmein",
        "sentinel", "sentinel123", "elasticsearch", "welcome123", "qwertyuiop"
    };

    public static string? Check(string? password, string? username = null)
    {
        if (string.IsNullOrWhiteSpace(password))
            return "A password is required.";

        if (password.Length < MinimumLength)
            return $"Use at least {MinimumLength} characters. Length matters more than punctuation.";

        if (password.Length > MaximumLength)
            return $"Keep it under {MaximumLength} characters.";

        if (Obvious.Contains(password.Trim()))
            return "That password is one of the first anybody tries.";

        if (!string.IsNullOrWhiteSpace(username) &&
            password.Contains(username, StringComparison.OrdinalIgnoreCase))
            return "The password must not contain the username.";

        return null;
    }
}
