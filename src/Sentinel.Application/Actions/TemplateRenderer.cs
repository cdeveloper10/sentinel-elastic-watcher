using System.Text;
using System.Text.RegularExpressions;

namespace Sentinel.Application.Actions;

public sealed record TemplateResult(string Text, IReadOnlyList<string> MissingPaths)
{
    public bool HadMissing => MissingPaths.Count > 0;
}

/// <summary>
/// Substitutes <c>{{event.source.ip}}</c> and friends into a message.
///
/// Deliberately not a template engine. There is no expression evaluation, no method invocation, no
/// iteration and no way to reach an object that <see cref="ActionContext"/> did not deliberately expose:
/// a placeholder is a path, the path is looked up in a dictionary, and anything else is left alone. A
/// general-purpose engine here would be a scripting surface inside the component that blocks addresses,
/// reachable by anyone who can author a rule.
///
/// <b>This renders text only.</b> Structured payloads are never built by substituting into a JSON string —
/// see <see cref="JsonPayload"/> for why that distinction is the whole security property.
/// </summary>
public static class TemplateRenderer
{
    /// <summary>
    /// Letters, digits, dots, underscores, hyphens and <c>@</c>. Anything else is not a path.
    ///
    /// <c>@</c> is here because <c>@timestamp</c> is the field name Elasticsearch and ECS give the one
    /// field every document has. Without it <c>{{sample.@timestamp}}</c> matched nothing, so it was not
    /// even treated as a placeholder — the literal text went out to the gateway, which is precisely the
    /// outcome the missing-field behaviour below exists to prevent. Found by reading what a real gateway
    /// received.
    ///
    /// Deliberately still a closed set. Widening it to "anything but braces" would let a path swallow
    /// structure, and this is a lookup key, not an expression.
    /// </summary>
    private static readonly Regex Placeholder = new(
        @"\{\{\s*(?<path>[A-Za-z0-9_.\-@]+)\s*\}\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    /// <summary>Beyond this a message is not a message. Bounds what one alert can hand to an SMS gateway.</summary>
    public const int MaxLength = 4_000;

    public static TemplateResult Render(string? template, ActionContext context, string? missingPlaceholder = "")
    {
        if (string.IsNullOrEmpty(template))
            return new TemplateResult("", []);

        var missing = new List<string>();

        var rendered = Placeholder.Replace(template, match =>
        {
            var path = match.Groups["path"].Value;

            if (context.TryResolve(path, out var value))
                return value;

            // A missing field must not leave "{{event.user.id}}" in a message that reaches a person, and
            // must not fail the action either: an address still needs blocking whether or not the account
            // behind it was identified.
            missing.Add(path);
            return missingPlaceholder ?? "";
        });

        if (rendered.Length > MaxLength)
            rendered = rendered[..MaxLength];

        return new TemplateResult(rendered, missing);
    }

    /// <summary>
    /// Which placeholders a template uses, for validation and for the preview an author sees before saving.
    /// </summary>
    public static IReadOnlyList<string> PathsIn(string? template)
    {
        if (string.IsNullOrEmpty(template))
            return [];

        return Placeholder.Matches(template)
            .Select(m => m.Groups["path"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Checks a template against the vocabulary before it is stored, so an author is told about a typo at
    /// save time rather than discovering it in an SMS during an incident.
    /// </summary>
    public static IReadOnlyList<string> UnknownPaths(string? template, IReadOnlyCollection<string> knownPaths)
    {
        var known = new HashSet<string>(knownPaths, StringComparer.OrdinalIgnoreCase);

        return PathsIn(template)
            .Where(path => !known.Contains(path) && !IsWildcardPrefixed(path, known))
            .ToList();
    }

    /// <summary>
    /// Prefixes whose members cannot honestly be enumerated at save time.
    ///
    /// <c>event.*</c> depends on the rule's group-by and on the document. <c>sample.*</c> is whatever
    /// fields the one returned event happens to carry — unknowable until an alert is raised, and different
    /// between two documents in the same index. A prefix match is as strict as this can be without
    /// refusing rules that would have worked.
    /// </summary>
    private static readonly string[] OpenPrefixes = ["event.", "sample.", "enrich."];

    private static bool IsWildcardPrefixed(string path, HashSet<string> known) =>
        OpenPrefixes.Any(prefix =>
            path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            known.Any(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)));
}

/// <summary>
/// Builds the JSON an action sends, by assembling an object rather than substituting into a string.
///
/// The brief's payloads are written as templates inside JSON:
/// <code>{ "userId": "{{event.user.id}}", "reason": "{{rule.name}}" }</code>
/// which is the bug. An account name containing a quote breaks the document; one containing
/// <c>","admin":true</c> adds a field. The value is attacker-influenced by definition — it came out of a
/// log line somebody else wrote — so the only safe construction is to put it into an object model and let
/// the serialiser do the escaping.
/// </summary>
public static class JsonPayload
{
    /// <summary>
    /// Renders each value through <see cref="TemplateRenderer"/> and sets it as a property. Substitution
    /// happens per value, never across the document, so a rendered value cannot become structure.
    /// </summary>
    public static System.Text.Json.Nodes.JsonObject Build(
        IReadOnlyDictionary<string, string> template,
        ActionContext context,
        out IReadOnlyList<string> missing)
    {
        var payload = new System.Text.Json.Nodes.JsonObject();
        var missingPaths = new List<string>();

        foreach (var (key, valueTemplate) in template)
        {
            var result = TemplateRenderer.Render(valueTemplate, context);
            missingPaths.AddRange(result.MissingPaths);
            payload[key] = result.Text;
        }

        missing = missingPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return payload;
    }

    /// <summary>Redacted rendering for the execution log: the shape of what was sent, without the secrets.</summary>
    public static string Summarize(System.Text.Json.Nodes.JsonObject payload, IReadOnlyCollection<string> redactKeys)
    {
        var copy = new System.Text.Json.Nodes.JsonObject();

        foreach (var property in payload)
        {
            copy[property.Key] = redactKeys.Contains(property.Key, StringComparer.OrdinalIgnoreCase)
                ? "***"
                : property.Value?.DeepClone();
        }

        var json = copy.ToJsonString();
        return json.Length <= 2_000 ? json : json[..2_000];
    }
}
