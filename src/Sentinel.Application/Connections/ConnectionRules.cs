using System.Text.RegularExpressions;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Connections;

public sealed record ValidationFailure(string Field, string Message);

public sealed record ValidationResult(IReadOnlyList<ValidationFailure> Failures)
{
    public bool IsValid => Failures.Count == 0;

    public static readonly ValidationResult Success = new([]);

    public static ValidationResult Fail(params ValidationFailure[] failures) => new(failures);
}

/// <summary>
/// What makes a connection definition acceptable, decided without a database or an HTTP client in scope.
///
/// These run before anything is stored, so a rejected connection never becomes a stored endpoint that
/// something later dials. That ordering matters more here than in most validation: the thing being
/// validated is an address the platform will send credentials to.
/// </summary>
public static class ConnectionRules
{
    /// <summary>Lowercase, digits and hyphens. A rule refers to this string, so it has to be stable and unambiguous.</summary>
    private static readonly Regex NamePattern = new("^[a-z0-9][a-z0-9-]{1,62}$", RegexOptions.Compiled);

    public const int MinTimeoutSeconds = 1;
    public const int MaxTimeoutSeconds = 300;

    public static ValidationResult Validate(
        string? name,
        string? type,
        string? endpoint,
        string? authenticationMode,
        int timeoutSeconds,
        IReadOnlyCollection<string> providedSecretKeys,
        OutboundAddressSettings addressSettings,
        string? configurationJson = null)
    {
        var failures = new List<ValidationFailure>();

        // The endpoint each action calls lives on the connection now, so it is checked here: a path
        // written as a full address, or with the leading slash left off, becomes a message at save time
        // rather than a request to the wrong place during an incident.
        failures.AddRange(ConnectionPaths.Validate(configurationJson).Failures);

        // A CA that will not parse, or a fingerprint that is not a SHA-256 hash, is worth saying now. The
        // alternative is a connection that saves cleanly and then fails every handshake with an error
        // about certificates that reads as though the cluster were at fault.
        failures.AddRange(ConnectionTls.Validate(configurationJson).Failures);

        if (string.IsNullOrWhiteSpace(name) || !NamePattern.IsMatch(name))
            failures.Add(new ValidationFailure(
                nameof(name),
                "Use 2–63 characters: lowercase letters, digits and hyphens, starting with a letter or digit."));

        if (!ConnectionType.IsKnown(type))
            failures.Add(new ValidationFailure(
                nameof(type),
                $"Unknown connection type. Expected one of: {string.Join(", ", ConnectionType.All)}."));

        var address = OutboundAddressPolicy.Evaluate(endpoint, addressSettings);
        if (!address.Allowed)
            failures.Add(new ValidationFailure(nameof(endpoint), address.Reason));

        if (!AuthenticationMode.IsKnown(authenticationMode))
            failures.Add(new ValidationFailure(
                nameof(authenticationMode),
                $"Unknown authentication mode. Expected one of: {string.Join(", ", AuthenticationMode.All)}."));
        else
        {
            // Named rather than counted, so the form can point at the field that is missing.
            var missing = AuthenticationMode.RequiredSecrets(authenticationMode!)
                .Where(required => !providedSecretKeys.Contains(required, StringComparer.OrdinalIgnoreCase))
                .ToList();

            if (missing.Count > 0)
                failures.Add(new ValidationFailure(
                    "secrets",
                    $"'{authenticationMode}' authentication needs: {string.Join(", ", missing)}."));
        }

        if (timeoutSeconds is < MinTimeoutSeconds or > MaxTimeoutSeconds)
            failures.Add(new ValidationFailure(
                nameof(timeoutSeconds),
                $"Timeout must be between {MinTimeoutSeconds} and {MaxTimeoutSeconds} seconds."));

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }
}
