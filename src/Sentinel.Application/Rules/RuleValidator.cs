using Sentinel.Application.Connections;
using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Rules;

/// <summary>
/// Everything that has to hold before a rule is allowed to run on a schedule.
///
/// Gathered in one place rather than spread between the API and the engine, because a rule that fails
/// validation at three in the morning fails silently: there is no author watching, and the alert that
/// should have fired simply does not. Every check here is one an author can be shown at save time.
///
/// What is validated per strategy is delegated to the strategy itself — the registry resolves it — so
/// adding a strategy does not mean editing this class.
/// </summary>
public sealed class RuleValidator(IDetectionStrategyRegistry strategies)
{
    /// <summary>Below this a rule queries the cluster more often than most clusters want to be queried.</summary>
    public const int MinIntervalSeconds = 10;

    /// <summary>
    /// A rule that runs less often than this is a report. It also drifts far enough behind that its
    /// checkpoint catch-up does most of the work, which is not what the schedule is for.
    /// </summary>
    public const int MaxIntervalSeconds = 3600;

    /// <param name="queryProblem">
    /// What is wrong with the rule's query, or null when nothing is. A delegate rather than a dependency
    /// because the query language belongs to whichever source the rule reads from, and this class has to
    /// stay able to validate a rule without knowing that the source is currently Elasticsearch.
    ///
    /// It hands back the problem rather than a bool so the author is told what is actually wrong. The
    /// source already produces a precise sentence, and discarding it in favour of "the query is not
    /// valid" would leave the check nearly useless to the person who has to fix it.
    /// </param>
    public ValidationResult Validate(RuleDefinition rule, Func<string, string?>? queryProblem = null)
    {
        var failures = new List<ValidationFailure>();

        if (string.IsNullOrWhiteSpace(rule.Name))
            failures.Add(new ValidationFailure("name", "A rule needs a name; it is what an alert is read by."));
        else if (rule.Name.Length > 200)
            failures.Add(new ValidationFailure("name", "Keep the name under 200 characters."));

        if (!Severity.IsKnown(rule.Severity))
            failures.Add(new ValidationFailure(
                "severity", $"Unknown severity. Expected one of: {string.Join(", ", Severity.All)}."));

        if (rule.ConnectionId <= 0)
            failures.Add(new ValidationFailure("connection", "A rule needs an event source to read from."));

        failures.AddRange(IndexPatternRules.Validate(rule.IndexPatterns).Failures);

        if (string.IsNullOrWhiteSpace(rule.TimestampField))
            failures.Add(new ValidationFailure(
                "timestampField",
                "A rule needs the date field its window applies to, usually @timestamp."));

        if (queryProblem?.Invoke(rule.QueryJson) is { } problem)
            failures.Add(new ValidationFailure("query", problem));

        if (rule.QueryDelay < TimeSpan.Zero)
            failures.Add(new ValidationFailure("queryDelay", "The query delay cannot be negative."));

        if (rule.QueryDelay > TimeSpan.FromHours(1))
            failures.Add(new ValidationFailure(
                "queryDelay",
                "A delay over an hour means detections arrive an hour late. If ingest is that far behind, " +
                "the lag is the problem to fix."));

        var interval = (int)rule.Interval.TotalSeconds;
        if (interval is < MinIntervalSeconds or > MaxIntervalSeconds)
            failures.Add(new ValidationFailure(
                "interval",
                $"The interval must be between {MinIntervalSeconds} seconds and {MaxIntervalSeconds / 60} minutes."));

        if (rule.Cooldown < TimeSpan.Zero)
            failures.Add(new ValidationFailure("cooldown", "The cooldown cannot be negative."));

        // Sliding windows mean a subject keeps qualifying while its events are in range. Without a cooldown
        // covering at least the window, the same subject fires on every evaluation for the whole window.
        if (rule.Cooldown > TimeSpan.Zero && rule.Cooldown < rule.Window)
            failures.Add(new ValidationFailure(
                "cooldown",
                $"A cooldown shorter than the window ({ThresholdDetectionStrategy.Describe(rule.Window)}) lets the " +
                "same subject fire repeatedly on overlapping windows. Set it at or above the window."));

        if (!strategies.TryResolve(rule.StrategyType, out var strategy))
        {
            failures.Add(new ValidationFailure(
                "strategy",
                $"Unknown detection strategy '{rule.StrategyType}'. " +
                $"Available: {string.Join(", ", strategies.Registered)}."));
        }
        else
        {
            failures.AddRange(strategy.Validate(rule).Failures);
        }

        foreach (var failure in ValidateActions(rule.Actions))
            failures.Add(failure);

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    /// <summary>
    /// Action bindings are checked for shape only. Whether the type exists is the action registry's
    /// question and whether the connection exists is the connection store's, both of which need more than
    /// the rule in hand.
    /// </summary>
    private static IEnumerable<ValidationFailure> ValidateActions(IReadOnlyList<RuleActionBinding> actions)
    {
        if (actions.Count > 10)
            yield return new ValidationFailure("actions", "A rule may have at most ten actions.");

        for (var i = 0; i < actions.Count; i++)
        {
            if (string.IsNullOrWhiteSpace(actions[i].Type))
                yield return new ValidationFailure($"actions[{i}].type", "An action needs a type.");

            if (string.IsNullOrWhiteSpace(actions[i].Connection))
                yield return new ValidationFailure(
                    $"actions[{i}].connection",
                    "An action needs a connection: it is where the endpoint and credentials come from, " +
                    "and why a rule never carries them itself.");
        }

        var duplicates = actions
            .GroupBy(a => (a.Type, a.Connection), StringComparerTuple.Instance)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key.Type);

        foreach (var duplicate in duplicates)
            yield return new ValidationFailure(
                "actions",
                $"'{duplicate}' is listed twice through the same connection, which would act twice on one detection.");
    }

    private sealed class StringComparerTuple : IEqualityComparer<(string Type, string Connection)>
    {
        public static readonly StringComparerTuple Instance = new();

        public bool Equals((string Type, string Connection) x, (string Type, string Connection) y) =>
            string.Equals(x.Type, y.Type, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Connection, y.Connection, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Type, string Connection) value) =>
            HashCode.Combine(
                value.Type.ToLowerInvariant(),
                value.Connection.ToLowerInvariant());
    }
}
