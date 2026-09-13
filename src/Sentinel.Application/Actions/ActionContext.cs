using Sentinel.Domain.Alerts;

namespace Sentinel.Application.Actions;

/// <summary>
/// Everything an action provider is given, and the boundary that keeps providers simple.
///
/// A provider never queries the source. By the time it runs, the index the events came from may have
/// rolled over, the cluster may be down, and the provider would be making its own decision about what the
/// alert was — three ways for the thing that blocks an address to disagree with the thing that decided it
/// should be blocked. The detection engine settles that question once and hands the answer down.
/// </summary>
public sealed record ActionContext(
    string AlertId,
    long AlertRowId,
    int RuleId,
    int RuleVersion,
    string RuleName,
    string Severity,
    DateTimeOffset DetectedAt,

    /// <summary>Subject fields and, for a match rule, the document that matched. Read via <c>event.*</c>.</summary>
    IReadOnlyDictionary<string, string> Event,

    /// <summary>Why the rule fired: counts, threshold, window.</summary>
    IReadOnlyDictionary<string, string> Evidence,

    /// <summary>Per-action settings from the rule's binding, e.g. a block duration.</summary>
    IReadOnlyDictionary<string, string> Settings)
{
    /// <summary>
    /// One of the events behind the alert, read via <c>sample.*</c>.
    ///
    /// Kept apart from <see cref="Event"/> because the two are true of different things. A subject field is
    /// true of every event in the group — the rule grouped by it. A sample field is true of one line out of
    /// fourteen. Both are useful in a message, and confusing them produces one that reads as though it
    /// described all of them.
    /// </summary>
    public IReadOnlyDictionary<string, string> Sample { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// What the actions before this one did, keyed <c>&lt;type&gt;.status</c> and <c>&lt;type&gt;.reason</c>
    /// and read as <c>{{actions.block_ip.status}}</c>.
    ///
    /// The dispatcher runs an alert's actions in order specifically so that "block the address, then tell
    /// somebody it was blocked" works — and until this existed, the telling half had no way to know what
    /// the blocking half did. A rule whose message said "Address blocked." said it whether or not the
    /// block had happened, which during an incident is worse than saying nothing.
    ///
    /// Only actions that ran <i>before</i> this one appear, because only those have an answer yet. Where a
    /// rule has two actions of the same type, the nearest preceding one wins.
    /// </summary>
    public IReadOnlyDictionary<string, string> Outcomes { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Values a provider computed and wants its own templates to be able to reach.
    ///
    /// There is one case, and it is what lets a rule's message and its payload compose: the SMS action
    /// renders the human sentence from its own setting and then exposes it as <c>{{message}}</c>, so an
    /// author writing a gateway's body can place that sentence in whichever field the gateway calls it.
    /// Without this the sentence would have to be written twice and the two copies would drift.
    /// </summary>
    public IReadOnlyDictionary<string, string> Derived { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The same context with one more resolvable name.</summary>
    public ActionContext With(string name, string value) => this with
    {
        Derived = new Dictionary<string, string>(Derived, StringComparer.OrdinalIgnoreCase) { [name] = value }
    };

    /// <summary>
    /// Builds the context from an alert. The one place the mapping lives, so every provider sees the same
    /// vocabulary and a new one needs no bespoke plumbing.
    /// </summary>
    public static ActionContext From(
        Alert alert,
        IReadOnlyDictionary<string, string> subject,
        IReadOnlyDictionary<string, string> evidence,
        IReadOnlyDictionary<string, string> settings,
        IReadOnlyDictionary<string, string>? sample = null,
        IReadOnlyDictionary<string, string>? outcomes = null) =>
        new(alert.AlertId,
            alert.Id,
            alert.RuleId,
            alert.RuleVersion,
            alert.RuleName,
            alert.Severity,
            new DateTimeOffset(alert.DetectedAt, TimeSpan.Zero),
            subject,
            evidence,
            settings)
        {
            Sample = sample ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            Outcomes = outcomes ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };

    /// <summary>
    /// Resolves one template path. The whole vocabulary, enumerated: there is no expression evaluation and
    /// no way to reach an object that was not deliberately exposed here.
    /// </summary>
    public bool TryResolve(string path, out string value)
    {
        value = "";

        if (string.IsNullOrWhiteSpace(path))
            return false;

        var trimmed = path.Trim();

        if (trimmed.StartsWith("event.", StringComparison.OrdinalIgnoreCase))
            return Event.TryGetValue(trimmed[6..], out value!) && value is not null;

        if (trimmed.StartsWith("actions.", StringComparison.OrdinalIgnoreCase))
            return Outcomes.TryGetValue(trimmed[8..], out value!) && value is not null;

        if (trimmed.StartsWith("sample.", StringComparison.OrdinalIgnoreCase))
            return Sample.TryGetValue(trimmed[7..], out value!) && value is not null;

        if (trimmed.StartsWith("evidence.", StringComparison.OrdinalIgnoreCase))
            return Evidence.TryGetValue(trimmed[9..], out value!) && value is not null;

        if (trimmed.StartsWith("setting.", StringComparison.OrdinalIgnoreCase))
            return Settings.TryGetValue(trimmed[8..], out value!) && value is not null;

        if (Derived.TryGetValue(trimmed, out var derived) && derived is not null)
        {
            value = derived;
            return true;
        }

        var resolved = trimmed.ToLowerInvariant() switch
        {
            // What the alert is about, whatever this rule happens to group by. Exists because the
            // alternative is a default message that names specific fields — and a default naming
            // event.source.ip renders a blank line on every rule that groups by anything else, which is
            // most of them. There is no iteration in the template language, so the one path that can be
            // correct for every rule is one the context flattens itself.
            "subject" => Subject(),

            "alert.id" => AlertId,
            "alert.severity" => Severity,
            "alert.timestamp" => DetectedAt.UtcDateTime.ToString("o"),
            "rule.id" => RuleId.ToString(),
            "rule.name" => RuleName,
            "rule.version" => RuleVersion.ToString(),
            _ => null
        };

        if (resolved is null)
            return false;

        value = resolved;
        return true;
    }

    /// <summary>
    /// The subject as one readable string: <c>SourceIP.keyword=203.0.113.44</c>, or several joined by
    /// commas when the rule groups by more than one field. Empty for a rule that groups by nothing, where
    /// the alert is about the window rather than about a subject.
    /// </summary>
    private string Subject() => string.Join(", ", Event.Select(pair => $"{pair.Key}={pair.Value}"));

    /// <summary>Paths that resolve for this alert, so the UI can offer them and a preview can be honest.</summary>
    public IReadOnlyList<string> AvailablePaths() =>
    [
        "subject",
        "alert.id", "alert.severity", "alert.timestamp",
        "rule.id", "rule.name", "rule.version",
        .. Derived.Keys,
        .. Event.Keys.Select(k => $"event.{k}"),
        .. Sample.Keys.Select(k => $"sample.{k}"),
        .. Outcomes.Keys.Select(k => $"actions.{k}"),
        .. Outcomes.Keys.Select(k => $"actions.{k}"),
        .. Evidence.Keys.Select(k => $"evidence.{k}"),
        .. Settings.Keys.Select(k => $"setting.{k}")
    ];
}
