using Sentinel.Application.Connections;

namespace Sentinel.Application.EventSources;

/// <summary>
/// Which index patterns a rule may point at.
///
/// A pattern is the blast radius of every query the engine will run on a schedule, forever. <c>*</c> reads
/// the whole cluster on every evaluation, including the platform's own indices and whatever else shares
/// the deployment; a cross-cluster pattern sends the query somewhere the operator did not configure a
/// connection for. Both are cheap to type into a form and expensive to discover in production.
/// </summary>
public static class IndexPatternRules
{
    public const int MaxPatterns = 10;
    public const int MaxPatternLength = 255;

    /// <summary>Patterns that would read everything. A rule that means "all logs" should name the log indices.</summary>
    private static readonly HashSet<string> Unbounded = new(StringComparer.OrdinalIgnoreCase)
    {
        "*", "_all", "*:*", "**"
    };

    public static ValidationResult Validate(IReadOnlyList<string>? patterns)
    {
        var failures = new List<ValidationFailure>();

        if (patterns is null || patterns.Count == 0)
            return ValidationResult.Fail(new ValidationFailure(
                "indexPatterns", "Name at least one index pattern, for example gateway-logs-*."));

        if (patterns.Count > MaxPatterns)
            failures.Add(new ValidationFailure(
                "indexPatterns", $"A rule may span at most {MaxPatterns} patterns."));

        var included = 0;

        foreach (var raw in patterns)
        {
            var pattern = raw?.Trim() ?? "";

            if (pattern.Length == 0)
            {
                failures.Add(new ValidationFailure("indexPatterns", "An index pattern cannot be empty."));
                continue;
            }

            if (pattern.Length > MaxPatternLength)
            {
                failures.Add(new ValidationFailure(
                    "indexPatterns", $"'{Truncate(pattern)}' is longer than {MaxPatternLength} characters."));
                continue;
            }

            var isExclusion = pattern.StartsWith('-');
            var body = isExclusion ? pattern[1..] : pattern;

            if (body.Length == 0)
            {
                failures.Add(new ValidationFailure("indexPatterns", "'-' on its own excludes nothing."));
                continue;
            }

            if (Unbounded.Contains(body))
            {
                failures.Add(new ValidationFailure(
                    "indexPatterns",
                    $"'{pattern}' would read every index on every evaluation. Name the indices the rule needs."));
                continue;
            }

            if (body.Contains(':'))
            {
                failures.Add(new ValidationFailure(
                    "indexPatterns",
                    $"'{pattern}' looks like a cross-cluster pattern. Configure a connection for that cluster instead."));
                continue;
            }

            if (body.StartsWith('.'))
            {
                failures.Add(new ValidationFailure(
                    "indexPatterns",
                    $"'{pattern}' targets a system index. Rules read event data, not cluster internals."));
                continue;
            }

            if (body.IndexOfAny([' ', '\\', '/', '<', '>', '|', ',', '"']) >= 0)
            {
                failures.Add(new ValidationFailure(
                    "indexPatterns", $"'{pattern}' contains a character an index name cannot hold."));
                continue;
            }

            if (!isExclusion)
                included++;
        }

        if (included == 0 && failures.Count == 0)
            failures.Add(new ValidationFailure(
                "indexPatterns", "At least one pattern has to include indices rather than exclude them."));

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    /// <summary>Normalised form sent to the source: trimmed, deduplicated, order preserved.</summary>
    public static IReadOnlyList<string> Normalize(IEnumerable<string> patterns) =>
        patterns
            .Select(p => p?.Trim() ?? "")
            .Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static string Truncate(string value) =>
        value.Length <= 40 ? value : value[..40] + "…";
}
