using Sentinel.Application.Detection;
using Sentinel.Application.Rules;

namespace Sentinel.Application.Actions;

/// <summary>
/// The placeholders a particular rule's alerts will carry.
///
/// Computed from the rule rather than published as one fixed list, because most of it depends on the rule:
/// a threshold rule grouped by <c>SourceIP.keyword</c> offers <c>{{event.SourceIP.keyword}}</c> and
/// <c>{{evidence.eventCount}}</c>, while a match rule offers the matched document and no count at all.
/// A single global list would have to be the union, which would tell an author that a placeholder is
/// available on a rule where it never resolves.
///
/// Used for two things, and they are the same thing seen from either side: the console offers these to
/// click, and the API refuses a payload that references anything else.
/// </summary>
public static class RuleVocabulary
{
    /// <summary>Always present, whatever the rule does.</summary>
    public static readonly IReadOnlyList<string> Always =
    [
        "subject",
        "alert.id", "alert.severity", "alert.timestamp",
        "rule.id", "rule.name", "rule.version"
    ];

    /// <summary>
    /// What the action at <paramref name="actionIndex"/> may reference, which includes the outcomes of the
    /// actions before it and not of the ones after.
    ///
    /// The distinction is not pedantry. Actions run in order, so an action can be told what the previous
    /// ones did and cannot be told what the next ones will do — and a message referring forwards would
    /// render a blank every time, on the one rule where somebody was relying on it.
    /// </summary>
    public static IReadOnlyList<string> ForAction(
        RuleDefinition rule,
        IDetectionStrategyRegistry strategies,
        int actionIndex,
        IEnumerable<string>? enrichmentPaths = null)
    {
        var paths = new List<string>(For(rule, strategies, enrichmentPaths));

        foreach (var preceding in rule.Actions.Take(actionIndex).Select(a => a.Type).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            paths.Add($"actions.{preceding}.status");
            paths.Add($"actions.{preceding}.reason");
            paths.Add($"actions.{preceding}.target");
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <param name="enrichmentPaths">
    /// What the registered enrichments will attach, already prefixed — <c>enrich.asset.owner</c>.
    ///
    /// Passed in rather than discovered here, because which enrichments exist is a composition question
    /// and this class deliberately knows nothing about the container. Absent means none are registered,
    /// and a rule referring to one is then refused — which is right: a deployment without the asset
    /// inventory would render those as blanks for ever.
    /// </param>
    public static IReadOnlyList<string> For(
        RuleDefinition rule,
        IDetectionStrategyRegistry strategies,
        IEnumerable<string>? enrichmentPaths = null)
    {
        var paths = new List<string>(Always);

        // Unlike sample.*, these are knowable in advance: every enrichment declares the facts it produces,
        // so they are enumerated rather than seeded as a prefix.
        if (enrichmentPaths is not null)
            paths.AddRange(enrichmentPaths);

        // Every action that renders a message exposes it under this name, so it can be placed in whichever
        // field the rule's own gateway calls it.
        paths.Add("message");

        if (strategies.TryResolve(rule.StrategyType, out var strategy))
            paths.AddRange(strategy.EvidenceKeys.Select(key => $"evidence.{key}"));

        // The subject is exactly the fields the rule groups by — those are the values that identify what
        // the alert is about, and for a grouped rule they are the only event fields an alert carries.
        paths.AddRange(rule.GroupBy.Select(field => $"event.{field}"));

        // A match rule's alert also carries the document that matched, whose fields are not knowable until
        // one arrives. One representative entry keeps the prefix rule in TemplateRenderer honest without
        // pretending to know the mapping.
        if (rule.GroupBy.Count == 0)
            paths.Add("event.matched");

        // Every alert carries one of the events behind it, whatever the strategy. Which fields it has
        // depends on the document that arrives, so this seeds the prefix rather than enumerating them —
        // the console fills the list in from the connection's real mapping, which it has already
        // discovered by the time an author is writing a message.
        paths.Add("sample.*");

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
