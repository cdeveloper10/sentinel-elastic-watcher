using System.Text.Json;

namespace Sentinel.Application.Audit;

/// <summary>Who is acting, and from where.</summary>
public sealed record Actor(string Name, string? SourceIp = null, string? CorrelationId = null)
{
    /// <summary>Work the platform did on its own schedule rather than because somebody asked.</summary>
    public static readonly Actor Engine = new("engine");

    public static Actor System(string component) => new($"system:{component}");
}

/// <summary>
/// What happened and who caused it.
///
/// Separate from the action execution log, which records what the platform did to other systems. This
/// records what people did to the platform. After an incident the question is "who armed the rule that
/// locked out the finance team", and execution records cannot answer it — they show the block, not the
/// decision that led to it.
/// </summary>
public interface IAuditTrail
{
    Task RecordAsync(
        Actor actor,
        string operation,
        string resourceType,
        string resourceId,
        string result = "SUCCESS",
        object? changes = null,
        string? detail = null,
        CancellationToken ct = default);
}

/// <summary>
/// Renders a change set for the audit trail without letting a credential into it.
///
/// The rule is absolute and easy to break by accident: a connection's before/after would otherwise carry
/// its API key into a table that more people can read than are entitled to the key. Secret-bearing fields
/// are recorded as names only — "these were set" — which is what an auditor needs and all they need.
/// </summary>
public static class AuditChanges
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    /// <summary>Field names whose values never reach the audit trail, matched case-insensitively.</summary>
    public static readonly IReadOnlySet<string> NeverRecorded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "secret", "secrets", "password", "apikey", "api_key", "token", "accesstoken", "refreshtoken",
        "clientsecret", "client_secret", "privatekey", "private_key", "ciphertext", "secretciphertext",
        "passwordhash", "authorization", "credential", "credentials"
    };

    public static string? Describe(IReadOnlyDictionary<string, object?>? before, IReadOnlyDictionary<string, object?>? after)
    {
        if (before is null && after is null)
            return null;

        var changed = new Dictionary<string, object?>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);

        if (before is not null) keys.UnionWith(before.Keys);
        if (after is not null) keys.UnionWith(after.Keys);

        foreach (var key in keys.Order(StringComparer.Ordinal))
        {
            var oldValue = before is not null && before.TryGetValue(key, out var b) ? b : null;
            var newValue = after is not null && after.TryGetValue(key, out var a) ? a : null;

            if (Equals(oldValue?.ToString(), newValue?.ToString()))
                continue;

            changed[key] = IsSensitive(key)
                // The fact of the change, never the values on either side of it.
                ? new { from = "***", to = "***" }
                : new { from = oldValue, to = newValue };
        }

        return changed.Count == 0 ? null : Serialize(changed);
    }

    /// <summary>A single object, redacted. Used when there is no before to compare against.</summary>
    public static string Describe(object value)
    {
        var json = JsonSerializer.SerializeToNode(value, Options);

        return json is System.Text.Json.Nodes.JsonObject obj
            ? Serialize(Redact(obj))
            : Serialize(value);
    }

    public static bool IsSensitive(string field) =>
        NeverRecorded.Contains(field) ||
        NeverRecorded.Any(secret => field.Contains(secret, StringComparison.OrdinalIgnoreCase));

    private static System.Text.Json.Nodes.JsonObject Redact(System.Text.Json.Nodes.JsonObject source)
    {
        var redacted = new System.Text.Json.Nodes.JsonObject();

        foreach (var property in source)
        {
            redacted[property.Key] = IsSensitive(property.Key)
                ? "***"
                : property.Value?.DeepClone();
        }

        return redacted;
    }

    private static string Serialize(object value)
    {
        var json = JsonSerializer.Serialize(value, Options);

        // Bounded: an audit row is a record of a decision, not a copy of the object it was made about.
        return json.Length <= 4_000 ? json : json[..4_000];
    }
}
