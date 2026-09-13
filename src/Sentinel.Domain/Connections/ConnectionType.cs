namespace Sentinel.Domain.Connections;

/// <summary>
/// The kinds of external system the platform talks to. Deliberately a small closed set: a connection type
/// decides which adapter runs, and an open-ended "generic HTTP" type would turn the connection form into a
/// way to make the platform issue arbitrary outbound requests.
/// </summary>
public static class ConnectionType
{
    /// <summary>An event source the detection engine reads from.</summary>
    public const string Elasticsearch = "elasticsearch";

    /// <summary>The API that blocks addresses and accounts.</summary>
    public const string SecurityApi = "security_api";

    /// <summary>An SMS gateway.</summary>
    public const string Sms = "sms";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Elasticsearch, SecurityApi, Sms };

    public static bool IsKnown(string? type) => type is not null && All.Contains(type);

    /// <summary>
    /// The stored form of a type the caller supplied.
    ///
    /// <see cref="IsKnown"/> accepts any casing, but every consumer compares against the constants
    /// ordinally — <c>connection.Type != ConnectionType.Elasticsearch</c>, and <c>switch</c> arms on the
    /// authentication mode. So a connection created as "Elasticsearch" was accepted, stored, and listed,
    /// and then could never be probed or read from: the API said the connection was of a type that "is not
    /// an event source" while naming that very type. Anything that writes a type stores this instead.
    /// </summary>
    public static string Canonical(string type) => All.FirstOrDefault(
        known => string.Equals(known, type, StringComparison.OrdinalIgnoreCase)) ?? type;
}

/// <summary>How the platform proves who it is to the system at the other end.</summary>
public static class AuthenticationMode
{
    public const string None = "none";
    public const string ApiKey = "api_key";
    public const string Basic = "basic";
    public const string Bearer = "bearer";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { None, ApiKey, Basic, Bearer };

    public static bool IsKnown(string? mode) => mode is not null && All.Contains(mode);

    /// <summary>
    /// The stored form of a mode the caller supplied. The stakes here are quieter than for the connection
    /// type and worse: the switch that attaches credentials has no default arm, so a mode stored as
    /// "Bearer" matches nothing and the request goes out unauthenticated rather than failing.
    /// </summary>
    public static string Canonical(string mode) => All.FirstOrDefault(
        known => string.Equals(known, mode, StringComparison.OrdinalIgnoreCase)) ?? mode;

    /// <summary>Secret names each mode expects, so validation can say what is missing rather than failing later.</summary>
    public static IReadOnlyList<string> RequiredSecrets(string mode) => mode?.ToLowerInvariant() switch
    {
        ApiKey => ["apiKey"],
        Bearer => ["token"],
        Basic => ["username", "password"],
        _ => []
    };
}
