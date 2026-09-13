using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Detection;

public sealed record DryRunAction(string Type, string Connection, int WouldExecute);

public sealed record DryRunResult(
    bool Succeeded,
    string Message,
    TimeRange Range,
    int WindowsEvaluated,
    long MatchedEvents,
    bool MatchedIsLowerBound,
    IReadOnlyList<DetectionCandidate> WouldDetect,
    IReadOnlyList<DetectionCandidate> SuppressedByCooldown,
    IReadOnlyList<DryRunAction> WouldExecute,
    bool Truncated,
    long SourceElapsedMs)
{
    public static DryRunResult Failed(string message, TimeRange range) =>
        new(false, message, range, 0, 0, false, [], [], [], false, 0);
}

/// <summary>
/// What a rule would have done over a stretch of history, without doing any of it.
///
/// This is the only honest way to gain confidence in a rule that blocks addresses automatically. An author
/// can see that their threshold would have fired thirty-seven times last hour and blocked four addresses,
/// and decide whether that is a detection or an outage, before arming it.
///
/// The guarantee that nothing is executed is <b>structural, not procedural</b>. This class has no
/// dispatcher, no action registry and no way to reach one: the type it returns describes intent, and there
/// is no code path from here to an action provider. A rule that says "run these actions in dry run" cannot
/// be written, because nothing here reads that instruction. Making the guarantee a matter of discipline —
/// a flag that every provider is trusted to honour — is how a platform eventually sends a real SMS from a
/// test.
/// </summary>
public sealed class DryRunService(IDetectionStrategyRegistry strategies)
{
    /// <summary>Evaluations one dry run will perform, so a request for a week does not become a thousand queries.</summary>
    public const int MaxWindows = 60;

    public async Task<DryRunResult> RunAsync(
        RuleDefinition rule,
        Connection connection,
        IEventSource source,
        TimeRange range,
        CancellationToken ct = default)
    {
        if (range.Duration <= TimeSpan.Zero)
            return DryRunResult.Failed("The time range has to end after it begins.", range);

        if (!strategies.TryResolve(rule.StrategyType, out var strategy))
            return DryRunResult.Failed($"No detection strategy is registered for '{rule.StrategyType}'.", range);

        var validation = strategy.Validate(rule);
        if (!validation.IsValid)
            return DryRunResult.Failed(
                "The rule is not valid yet: " + string.Join("; ", validation.Failures.Select(f => f.Message)),
                range);

        var windows = PlanWindows(rule, range);

        var detected = new List<DetectionCandidate>();
        var suppressed = new List<DetectionCandidate>();
        var truncated = false;
        long elapsed = 0;
        long matched = 0;
        var matchedIsLowerBound = false;

        // Cooldown is replayed rather than ignored, because a rule that looks alarming without it usually
        // looks reasonable with it — and the number an author needs is how many times it would actually
        // have acted.
        var lastFired = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);

        foreach (var window in windows)
        {
            ct.ThrowIfCancellationRequested();

            StrategyResult result;
            try
            {
                result = await strategy.EvaluateAsync(new StrategyRequest(rule, connection, window), source, ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // A timed-out HTTP request arrives as a cancellation. Letting it through here turned an
                // unreachable cluster into an unexplained 500 instead of a rehearsal that failed and said
                // why — only a cancellation the caller asked for should escape.
                return DryRunResult.Failed(
                    $"{connection.Name} did not answer within {connection.TimeoutSeconds} seconds.", range);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return DryRunResult.Failed($"The source could not be queried: {ex.Message}", range);
            }

            truncated |= result.Truncated;
            elapsed += result.SourceElapsedMs;

            foreach (var candidate in result.Candidates)
            {
                matched += candidate.EventCount;

                var key = DetectionFingerprint.SubjectKey(candidate.Subject);

                if (lastFired.TryGetValue(key, out var previous) &&
                    CooldownPolicy.IsSuppressed(previous, window.To, rule.Cooldown))
                {
                    suppressed.Add(candidate);
                    continue;
                }

                lastFired[key] = window.To;
                detected.Add(candidate);
            }
        }

        matchedIsLowerBound = truncated;

        // Counted rather than executed: one action per detection, which is what the dispatcher would do.
        var wouldExecute = rule.Actions
            .Select(action => new DryRunAction(action.Type, action.Connection, detected.Count))
            .ToList();

        return new DryRunResult(
            Succeeded: true,
            Message: windows.Count == MaxWindows
                ? $"Evaluated the first {MaxWindows} windows of the range; narrow the range to see the rest."
                : $"Evaluated {windows.Count} window(s).",
            range,
            windows.Count,
            matched,
            matchedIsLowerBound,
            detected,
            suppressed,
            wouldExecute,
            truncated,
            elapsed);
    }

    /// <summary>
    /// Steps the rule's own interval across the requested range, so a dry run reproduces the schedule the
    /// rule would have kept rather than one long window that no evaluation would ever have used.
    /// </summary>
    private static List<TimeRange> PlanWindows(RuleDefinition rule, TimeRange range)
    {
        var windows = new List<TimeRange>();
        var cursor = range.From + rule.Window;

        if (cursor > range.To)
            cursor = range.To;

        while (windows.Count < MaxWindows)
        {
            windows.Add(TimeRange.EndingAt(cursor, rule.Window));

            if (cursor >= range.To)
                break;

            cursor += rule.Interval;
            if (cursor > range.To)
                cursor = range.To;
        }

        return windows;
    }
}
