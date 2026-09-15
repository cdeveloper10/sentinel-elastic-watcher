using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Connections;

/// <summary>
/// Which endpoint on a service each action calls.
///
/// This belongs to the connection, not to the rule. A gateway's send path is a property of that gateway:
/// every rule pointing at it uses the same one, and the day it changes, the change is to the service
/// rather than to forty rules that each happened to write it down. A rule says "send this to this
/// connection" and nothing about the URL — which is the same reason it does not carry the host or the
/// credential either.
///
/// Keyed by action type rather than a single value, because one service legitimately answers on several
/// endpoints: a security API blocks an address at one path and suspends an account at another, and those
/// are two actions through one connection.
///
/// <code>
/// { "paths": { "block_ip": "/security/block/ip", "block_user": "/security/block/user" } }
/// </code>
///
/// Absent means the action's own default, so a connection whose service uses the conventional paths needs
/// no configuration at all.
/// </summary>
public static class ConnectionPaths
{
    /// <summary>The property inside a connection's configuration document.</summary>
    public const string Property = "paths";

    /// <summary>Long enough for any real endpoint; a bound so a path cannot become a payload.</summary>
    public const int MaxLength = 200;

    /// <summary>
    /// The key an action's <em>undo</em> endpoint is configured under: <c>block_ip.reverse</c>.
    ///
    /// A suffix on the same dictionary rather than a second one, so a service that undoes at an
    /// unconventional path is configured exactly the way one that blocks at an unconventional path is.
    /// </summary>
    public static string ReversePathKey(string actionType) => $"{actionType}.reverse";

    /// <summary>
    /// The path this action should call on this connection, or <paramref name="fallback"/> when the
    /// connection says nothing about it.
    /// </summary>
    public static string For(Connection connection, string actionType, string fallback)
    {
        var configured = Read(connection.ConfigurationJson).GetValueOrDefault(actionType);

        return string.IsNullOrWhiteSpace(configured) ? fallback : Normalize(configured);
    }

    /// <summary>What the connection has configured, by action type. Empty when it has nothing or is unreadable.</summary>
    public static IReadOnlyDictionary<string, string> Read(string? configurationJson)
    {
        var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(configurationJson))
            return empty;

        try
        {
            if (JsonNode.Parse(configurationJson) is not JsonObject root ||
                root[Property] is not JsonObject paths)
                return empty;

            foreach (var entry in paths)
            {
                if (entry.Value is JsonValue value && value.TryGetValue<string>(out var path) &&
                    !string.IsNullOrWhiteSpace(path))
                    empty[entry.Key] = Normalize(path);
            }

            return empty;
        }
        catch (JsonException)
        {
            // Unreadable configuration means the defaults apply, not that the action fails. Whether the
            // document is well-formed is settled by validation when it is saved.
            return empty;
        }
    }

    /// <summary>
    /// Writes the paths into a connection's configuration, leaving anything else in it alone.
    ///
    /// Merged rather than replaced because the configuration document is the connection's, and a future
    /// setting stored beside the paths must survive somebody editing a path.
    /// </summary>
    public static string Write(string? configurationJson, IReadOnlyDictionary<string, string> paths)
    {
        JsonObject root;

        try
        {
            root = JsonNode.Parse(string.IsNullOrWhiteSpace(configurationJson) ? "{}" : configurationJson)
                       as JsonObject ?? [];
        }
        catch (JsonException)
        {
            root = [];
        }

        var target = new JsonObject();

        foreach (var (actionType, path) in paths)
        {
            if (!string.IsNullOrWhiteSpace(path))
                target[actionType] = Normalize(path);
        }

        if (target.Count == 0)
            root.Remove(Property);
        else
            root[Property] = target;

        return root.ToJsonString();
    }

    /// <summary>
    /// Checks the paths a connection carries, so a leading slash left off is a message at save time rather
    /// than a request to <c>https://gateway.internalsms/send</c> during an incident.
    /// </summary>
    public static ValidationResult Validate(string? configurationJson)
    {
        if (string.IsNullOrWhiteSpace(configurationJson))
            return ValidationResult.Success;

        JsonNode? parsed;

        try
        {
            parsed = JsonNode.Parse(configurationJson);
        }
        catch (JsonException ex)
        {
            return ValidationResult.Fail(new ValidationFailure(
                "configurationJson", $"This is not valid JSON: {ex.Message}"));
        }

        if (parsed is not JsonObject root)
            return ValidationResult.Fail(new ValidationFailure(
                "configurationJson", "The configuration must be a JSON object."));

        if (root[Property] is null)
            return ValidationResult.Success;

        if (root[Property] is not JsonObject paths)
            return ValidationResult.Fail(new ValidationFailure(
                Property, "'paths' must be an object of action type to endpoint path."));

        var failures = new List<ValidationFailure>();

        foreach (var entry in paths)
        {
            if (entry.Value is not JsonValue value || !value.TryGetValue<string>(out var path))
            {
                failures.Add(new ValidationFailure(Property, $"The path for '{entry.Key}' must be text."));
                continue;
            }

            if (path.Length > MaxLength)
                failures.Add(new ValidationFailure(Property, $"'{entry.Key}' is longer than {MaxLength} characters."));

            // A path, not a URL. Allowing one here would let a connection's own configuration send the
            // platform's credential to a different host than the one its endpoint was checked against.
            if (path.Contains("://", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
                failures.Add(new ValidationFailure(
                    Property,
                    $"'{entry.Key}' must be a path such as /sms/send, not a full address — the address is " +
                    "the connection's endpoint."));
        }

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    /// <summary>A path always starts with one slash, whether or not whoever typed it remembered.</summary>
    private static string Normalize(string path)
    {
        var trimmed = path.Trim();

        return trimmed.StartsWith('/') ? trimmed : "/" + trimmed;
    }
}
