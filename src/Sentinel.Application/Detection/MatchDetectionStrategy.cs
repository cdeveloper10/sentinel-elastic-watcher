using Sentinel.Application.Connections;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Detection;

/// <summary>
/// One matching event is the detection.
///
/// For conditions where occurrence is the whole story — a privileged account created, a rule-set disabled,
/// a request from a country the estate does not operate in. Counting those would be beside the point:
/// there is no threshold at which "an administrator was added" becomes interesting, because it already is.
///
/// Unlike the threshold strategy this one does read documents, because the document <em>is</em> the
/// evidence. That is why it is bounded hard: a match rule written against a busy index would otherwise
/// turn one evaluation into thousands of alerts, and the cap is what turns that mistake into a truncation
/// flag instead of an outage.
/// </summary>
public sealed class MatchDetectionStrategy : IDetectionStrategy
{
    /// <summary>Documents one evaluation will turn into detections. Beyond this the result is truncated.</summary>
    public const int MaxMatchesPerEvaluation = 100;

    public string Type => DetectionStrategyType.Match;

    /// <summary>Kept beside the dictionary below; a test asserts the two agree.</summary>
    public IReadOnlyList<string> EvidenceKeys =>
        ["matchedEvent", "window", "windowFrom", "windowTo"];

    public ValidationResult Validate(RuleDefinition rule)
    {
        var failures = new List<ValidationFailure>();

        if (string.IsNullOrWhiteSpace(rule.QueryJson))
            failures.Add(new ValidationFailure(
                "query",
                "A match rule fires on every event it finds, so without a query it would fire on all of them. " +
                "Give it something to match."));

        if (rule.Window <= TimeSpan.Zero)
            failures.Add(new ValidationFailure("window", "The window must be longer than zero."));

        if (rule.Interval > rule.Window)
            failures.Add(new ValidationFailure(
                "interval",
                $"The rule runs every {rule.Interval:g} but only looks back {rule.Window:g}, " +
                "so events in between would never be evaluated."));

        // Grouping is optional here: with it, one detection per distinct subject; without, one per event.
        if (rule.GroupBy.Count > 3)
            failures.Add(new ValidationFailure(
                "groupBy", "Grouping by more than three fields produces subjects too specific to act on."));

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    public async Task<StrategyResult> EvaluateAsync(
        StrategyRequest request, IEventSource source, CancellationToken ct = default)
    {
        var rule = request.Rule;

        var preview = await source.PreviewAsync(
            request.Connection,
            rule.IndexPatterns,
            rule.QueryJson,
            request.Window,
            rule.TimestampField,
            MaxMatchesPerEvaluation,
            ct);

        var candidates = new List<DetectionCandidate>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var document in preview.Samples)
        {
            var subject = Subject(rule, document);

            // With a group-by, the first event for a subject is the detection and the rest are the same
            // finding: reporting an address twenty times because twenty of its requests matched is noise,
            // not twenty findings.
            if (rule.GroupBy.Count > 0 && !seen.Add(DetectionFingerprint.SubjectKey(subject)))
                continue;

            candidates.Add(new DetectionCandidate(
                subject,
                EventCount: 1,
                request.Window,
                new Dictionary<string, object?>
                {
                    ["matchedEvent"] = document,
                    ["window"] = ThresholdDetectionStrategy.Describe(rule.Window),
                    ["windowFrom"] = request.Window.From.UtcDateTime.ToString("o"),
                    ["windowTo"] = request.Window.To.UtcDateTime.ToString("o")
                },
                // A match rule's sample is not a sample of many — it is the event, and the only one. Given
                // the same name as the threshold strategy's so an author writes {{sample.UserID}} once and
                // it means the same thing whichever strategy the rule uses.
                document.ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value?.ToString() ?? "",
                    StringComparer.OrdinalIgnoreCase)));
        }

        // More matched than were retrieved, so this evaluation did not see all of them.
        var truncated = preview.TotalIsLowerBound || preview.TotalMatched > preview.Samples.Count;

        return new StrategyResult(candidates, truncated, preview.ElapsedMs);
    }

    /// <summary>
    /// The subject of a match. Grouped rules take it from the named fields; ungrouped ones fall back to the
    /// document itself, so every match is its own subject and cooldown does not collapse unrelated events.
    /// </summary>
    private static IReadOnlyDictionary<string, string> Subject(
        RuleDefinition rule, IReadOnlyDictionary<string, object?> document)
    {
        var subject = new Dictionary<string, string>(StringComparer.Ordinal);

        if (rule.GroupBy.Count == 0)
        {
            subject["_event"] = DocumentIdentity(document);
            return subject;
        }

        foreach (var field in rule.GroupBy)
            subject[field] = document.TryGetValue(field, out var value) ? Text(value) : "";

        return subject;
    }

    /// <summary>
    /// A stable-enough identity for an ungrouped match, so that re-evaluating an overlapping window
    /// recognises the same event rather than alerting on it again.
    /// </summary>
    private static string DocumentIdentity(IReadOnlyDictionary<string, object?> document)
    {
        foreach (var candidate in (string[])["event.id", "@timestamp", "timestamp"])
        {
            if (document.TryGetValue(candidate, out var value) && Text(value) is { Length: > 0 } text)
                return text;
        }

        return string.Join('|', document
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Key}={Text(pair.Value)}"));
    }

    private static string Text(object? value) => value switch
    {
        null => "",
        string s => s,
        string[] many => string.Join(',', many),
        _ => value.ToString() ?? ""
    };
}
