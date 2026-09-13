using Sentinel.Application.EventSources;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Detection;

/// <summary>One subject the condition found, how many events it had, and whether that reaches the threshold.</summary>
public sealed record PreviewGroup(
    IReadOnlyDictionary<string, string> Key,
    long Count,
    bool ReachesThreshold);

public sealed record ConditionPreviewResult(
    bool Succeeded,
    string Message,
    long TotalMatched,
    bool TotalIsLowerBound,
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Samples,
    IReadOnlyList<PreviewGroup> Groups,
    bool GroupsTruncated,
    int WouldTrigger,
    long ElapsedMs)
{
    public static ConditionPreviewResult Failed(string message) =>
        new(false, message, 0, false, [], [], false, 0, 0);
}

/// <summary>
/// What a condition matches right now, before anything is saved.
///
/// This exists because of how long the loop used to be. Writing a rule meant typing a query blind, saving
/// it, arming it, sending traffic, and waiting — and when nothing happened the cause could equally be the
/// query, the threshold, the grouping, the cooldown, deduplication, or an ingest delay. Six candidates,
/// several minutes per attempt, and no way to tell them apart. Answering "does this query match anything,
/// and how much" in one second removes the first three from the list every time.
///
/// It is not a dry run and does not replace one. A dry run replays the rule's own schedule and its
/// cooldown across history and says what it would have done; this asks one question about one window. The
/// difference matters when reading the answer: a subject shown here as reaching the threshold may still
/// have been suppressed in practice.
///
/// Like <see cref="DryRunService"/> it cannot execute anything — there is no dispatcher here and no way to
/// reach one.
/// </summary>
public sealed class ConditionPreviewService
{
    /// <summary>Enough to see what the log lines look like; few enough that the response stays small.</summary>
    public const int SampleSize = 3;

    /// <summary>Subjects returned. A condition producing more than this is grouped by the wrong field.</summary>
    public const int MaxGroups = 25;

    public async Task<ConditionPreviewResult> RunAsync(
        Connection connection,
        IEventSource source,
        IReadOnlyList<string> indexPatterns,
        string queryJson,
        string timestampField,
        IReadOnlyList<string> groupBy,
        long threshold,
        TimeRange range,
        CancellationToken ct = default)
    {
        if (range.Duration <= TimeSpan.Zero)
            return ConditionPreviewResult.Failed("The time range has to end after it begins.");

        if (indexPatterns.Count == 0)
            return ConditionPreviewResult.Failed("Give at least one index pattern to look in.");

        if (string.IsNullOrWhiteSpace(timestampField))
            return ConditionPreviewResult.Failed("A preview needs the date field the window applies to.");

        QueryPreview preview;

        try
        {
            preview = await source.PreviewAsync(
                connection, indexPatterns, queryJson, range, timestampField, SampleSize, ct);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // A timed-out HTTP request arrives as a cancellation, and treating it as one meant an
            // unreachable cluster — the commonest thing an author hits — came back as a bare 500 instead
            // of a sentence. Only a cancellation the caller actually asked for is allowed through.
            return ConditionPreviewResult.Failed(Timeout(connection));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The source's own message, which now names the index and the shard reason when a mapping
            // conflict is what refused it. That sentence is the entire value of this call when it fails.
            return ConditionPreviewResult.Failed(ex.Message);
        }

        var elapsed = preview.ElapsedMs;
        var groups = new List<PreviewGroup>();
        var truncated = false;

        if (groupBy.Count > 0 && preview.TotalMatched > 0)
        {
            GroupCountResult counted;

            try
            {
                // minCount 1, not the threshold. The engine pushes the threshold down because it only
                // cares which subjects cross it; an author needs the opposite — the subject sitting at
                // fourteen against a threshold of twenty is exactly the information that says whether the
                // number is wrong, and pushing the threshold down would hide it.
                counted = await source.CountByGroupAsync(
                    connection, indexPatterns, queryJson, range, timestampField, groupBy,
                    minCount: 1, maxGroups: MaxGroups, ct);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return ConditionPreviewResult.Failed(Timeout(connection));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return ConditionPreviewResult.Failed(ex.Message);
            }

            elapsed += counted.ElapsedMs;
            truncated = counted.Truncated;

            groups.AddRange(counted.Groups
                .OrderByDescending(g => g.Count)
                .Select(g => new PreviewGroup(g.Key, g.Count, threshold > 0 && g.Count >= threshold)));
        }

        return new ConditionPreviewResult(
            Succeeded: true,
            Message: Describe(preview, groupBy, groups, threshold),
            preview.TotalMatched,
            preview.TotalIsLowerBound,
            preview.Samples,
            groups,
            truncated,
            groups.Count(g => g.ReachesThreshold),
            elapsed);
    }

    private static string Timeout(Connection connection) =>
        $"{connection.Name} did not answer within {connection.TimeoutSeconds} seconds. The cluster may be " +
        "unreachable from here, or the query may be too wide for the window — try a shorter lookback, or " +
        "test the connection.";

    /// <summary>
    /// A sentence saying what the numbers mean, because the numbers alone are ambiguous in the one case
    /// that matters: nothing matched. That is either a condition that is wrong or a window that is quiet,
    /// and which one it is changes what the author does next.
    /// </summary>
    private static string Describe(
        QueryPreview preview,
        IReadOnlyList<string> groupBy,
        IReadOnlyList<PreviewGroup> groups,
        long threshold)
    {
        if (preview.TotalMatched == 0)
            return "Nothing in this window matched. Either the condition is wrong or the window is quiet — " +
                   "widen the lookback to tell which.";

        var matched = preview.TotalIsLowerBound
            ? $"At least {preview.TotalMatched} events matched"
            : $"{preview.TotalMatched} event(s) matched";

        if (groupBy.Count == 0)
            return $"{matched}. Add a group-by to see how they divide between subjects.";

        if (groups.Count == 0)
            return $"{matched}, but none of them carry {string.Join(" and ", groupBy)} — " +
                   "check the spelling, and that the field is aggregatable.";

        var crossing = groups.Count(g => g.ReachesThreshold);
        var highest = groups.Max(g => g.Count);

        if (threshold <= 0)
            return $"{matched} across {groups.Count} subject(s). The busiest had {highest}.";

        return crossing > 0
            ? $"{matched}. {crossing} subject(s) reach the threshold of {threshold}; the busiest had {highest}."
            : $"{matched} across {groups.Count} subject(s), but none reach {threshold} — the busiest had " +
              $"{highest}, so this rule would not have fired.";
    }
}
