using Sentinel.Application.Connections;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Detection;

/// <summary>
/// Group, count within the window, fire at or above the threshold.
///
/// This is the brief's threshold, frequency and aggregation rules in one implementation, because they are
/// one calculation. What differs between the examples given — group by address, group by account, count
/// 401s — is the rule's configuration, not its logic.
///
/// The counting happens in the source. The threshold is handed down as a floor so the cluster discards the
/// millions of subjects with one event each and returns only what could possibly qualify; nothing here
/// ever sees a document.
/// </summary>
public sealed class ThresholdDetectionStrategy : IDetectionStrategy
{
    /// <summary>
    /// Ceiling on subjects returned from one evaluation. A rule that would fire on more than this has
    /// either been mis-authored or is watching an incident large enough that the platform's job is to say
    /// so, not to act on every subject in it.
    /// </summary>
    public const int MaxSubjectsPerEvaluation = 1_000;

    public string Type => DetectionStrategyType.Threshold;

    /// <summary>Kept beside the dictionary below; a test asserts the two agree.</summary>
    public IReadOnlyList<string> EvidenceKeys =>
        ["eventCount", "threshold", "window", "windowFrom", "windowTo", "groupBy"];

    public ValidationResult Validate(RuleDefinition rule)
    {
        var failures = new List<ValidationFailure>();

        if (rule.GroupBy.Count == 0)
            failures.Add(new ValidationFailure(
                "groupBy",
                "A threshold rule counts per subject, so it needs at least one field to group by — " +
                "source.ip or user.id, for example."));

        if (rule.GroupBy.Count > 3)
            failures.Add(new ValidationFailure(
                "groupBy",
                "Grouping by more than three fields produces subjects too specific to act on."));

        if (rule.GroupBy.Any(string.IsNullOrWhiteSpace))
            failures.Add(new ValidationFailure("groupBy", "A group-by field cannot be blank."));

        if (rule.Threshold < 1)
            failures.Add(new ValidationFailure("threshold", "The threshold must be at least 1."));

        if (rule.Window <= TimeSpan.Zero)
            failures.Add(new ValidationFailure("window", "The window must be longer than zero."));

        if (rule.Window > TimeSpan.FromDays(1))
            failures.Add(new ValidationFailure(
                "window", "A window longer than a day is a report, not a detection. Keep it under 24 hours."));

        // An interval longer than the window leaves gaps: time nobody ever looks at, in a system whose
        // whole purpose is not to miss things.
        if (rule.Interval > rule.Window)
            failures.Add(new ValidationFailure(
                "interval",
                $"The rule runs every {rule.Interval:g} but only looks back {rule.Window:g}, " +
                "so events in between would never be evaluated. Set the interval at or below the window."));

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    public async Task<StrategyResult> EvaluateAsync(
        StrategyRequest request, IEventSource source, CancellationToken ct = default)
    {
        var rule = request.Rule;

        var counted = await source.CountByGroupAsync(
            request.Connection,
            rule.IndexPatterns,
            rule.QueryJson,
            request.Window,
            rule.TimestampField,
            rule.GroupBy,
            // The floor and the rule's threshold are the same number. Passing it is what keeps this cheap.
            minCount: rule.Threshold,
            maxGroups: MaxSubjectsPerEvaluation,
            ct);

        var candidates = counted.Groups
            // The source honoured min_doc_count, but the strategy owns the decision and does not delegate
            // it: a source that ignored the floor would otherwise silently lower the threshold to one.
            .Where(group => group.Count >= rule.Threshold)
            .Select(group => new DetectionCandidate(
                group.Key,
                group.Count,
                request.Window,
                new Dictionary<string, object?>
                {
                    ["eventCount"] = group.Count,
                    ["threshold"] = rule.Threshold,
                    ["window"] = Describe(rule.Window),
                    ["windowFrom"] = request.Window.From.UtcDateTime.ToString("o"),
                    ["windowTo"] = request.Window.To.UtcDateTime.ToString("o"),
                    ["groupBy"] = rule.GroupBy.ToArray()
                },
                // One of the events that made this group qualify, from the same aggregation that counted
                // them. What turns "AiServices returned 14 HTTP 500s" into a message that also says which
                // user, which path and which backend.
                group.Sample))
            .ToList();

        return new StrategyResult(candidates, counted.Truncated, counted.ElapsedMs);
    }

    /// <summary>The window as an operator wrote it, so evidence reads "5m" rather than "00:05:00".</summary>
    internal static string Describe(TimeSpan window) => window switch
    {
        { TotalDays: >= 1 } when window.TotalDays % 1 == 0 => $"{(int)window.TotalDays}d",
        { TotalHours: >= 1 } when window.TotalHours % 1 == 0 => $"{(int)window.TotalHours}h",
        { TotalMinutes: >= 1 } when window.TotalMinutes % 1 == 0 => $"{(int)window.TotalMinutes}m",
        _ => $"{(int)window.TotalSeconds}s"
    };
}
