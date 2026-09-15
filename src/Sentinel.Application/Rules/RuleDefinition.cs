using System.Text.Json;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Rules;

/// <summary>One action a rule asks for, and the connection it goes through. No endpoint, no credential.</summary>
public sealed record RuleActionBinding(
    string Type,
    string Connection,
    IReadOnlyDictionary<string, string> Settings,

    /// <summary>
    /// Whether a person has to say yes before this runs.
    ///
    /// On the binding rather than among the provider's settings, because gating is not a property of the
    /// action: every action can be gated, and a provider should not have to know that gating exists. It is
    /// the same kind of decision as which connection to use — the rule's, not the action's.
    /// </summary>
    bool RequiresApproval = false)
{
    public string Setting(string key, string fallback = "") =>
        Settings.TryGetValue(key, out var value) ? value : fallback;

    public int Setting(string key, int fallback) =>
        Settings.TryGetValue(key, out var value) && int.TryParse(value, out var parsed) ? parsed : fallback;
}

/// <summary>
/// A rule version parsed into the form everything downstream works with.
///
/// The stored row keeps its lists as JSON because they are variable-length and never queried on; this is
/// where that becomes typed. Parsing once, at load, means a strategy or the engine cannot be handed a rule
/// whose JSON is malformed — that failure happens where it can be attributed to a rule, not in the middle
/// of an evaluation at three in the morning.
/// </summary>
public sealed record RuleDefinition(
    int RuleId,
    int Version,
    string Name,
    string Description,
    string Severity,
    int ConnectionId,
    IReadOnlyList<string> IndexPatterns,
    string QueryJson,
    string TimestampField,
    string StrategyType,
    IReadOnlyList<string> GroupBy,
    long Threshold,
    TimeSpan Window,
    TimeSpan QueryDelay,
    TimeSpan Interval,
    TimeSpan Cooldown,
    IReadOnlyList<RuleActionBinding> Actions);

public static class RuleDefinitionMapper
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static RuleDefinition From(RuleVersion version, int connectionId) => new(
        version.RuleId,
        version.Version,
        version.Name,
        version.Description,
        version.Severity,
        connectionId,
        ReadStrings(version.IndexPatternsJson),
        version.QueryJson,
        string.IsNullOrWhiteSpace(version.TimestampField) ? "@timestamp" : version.TimestampField,
        version.StrategyType,
        ReadStrings(version.GroupByJson),
        version.Threshold,
        version.Window,
        version.QueryDelay,
        version.Interval,
        version.Cooldown,
        ReadActions(version.ActionsJson));

    public static IReadOnlyList<string> ReadStrings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json, Options) ?? [];
        }
        catch (JsonException)
        {
            // Stored data that will not parse is empty rather than fatal: a rule with no index patterns is
            // refused by validation with a message, where a parse exception mid-evaluation is not.
            return [];
        }
    }

    public static IReadOnlyList<RuleActionBinding> ReadActions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            var raw = JsonSerializer.Deserialize<List<ActionBindingDto>>(json, Options) ?? [];

            return raw
                .Where(binding => !string.IsNullOrWhiteSpace(binding.Type))
                .Select(binding => new RuleActionBinding(
                    binding.Type!.Trim(),
                    binding.Connection?.Trim() ?? "",
                    binding.Settings ?? new Dictionary<string, string>(),

                    // Absent in every version stored before gating existed, and those rules must keep
                    // running exactly as they did — false is the only reading that does not silently
                    // park an action somebody has been relying on.
                    binding.RequiresApproval ?? false))
                .ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    public static string WriteStrings(IEnumerable<string> values) => JsonSerializer.Serialize(values);

    public static string WriteActions(IEnumerable<RuleActionBinding> actions) =>
        JsonSerializer.Serialize(actions.Select(a => new ActionBindingDto
        {
            Type = a.Type,
            Connection = a.Connection,
            Settings = a.Settings.ToDictionary(p => p.Key, p => p.Value),
            RequiresApproval = a.RequiresApproval
        }));

    private sealed class ActionBindingDto
    {
        public string? Type { get; set; }
        public string? Connection { get; set; }
        public Dictionary<string, string>? Settings { get; set; }

        /// <summary>Nullable so an older stored version, which has no such property, reads as false.</summary>
        public bool? RequiresApproval { get; set; }
    }
}
