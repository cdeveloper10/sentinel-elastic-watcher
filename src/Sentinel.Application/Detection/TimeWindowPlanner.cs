using Sentinel.Application.EventSources;

namespace Sentinel.Application.Detection;

/// <summary>
/// Which stretches of time an evaluation should look at, and where the checkpoint moves to afterwards.
/// </summary>
public sealed record EvaluationPlan(
    IReadOnlyList<TimeRange> Windows,
    DateTimeOffset Checkpoint,
    bool SkippedBacklog,
    string Reason)
{
    public bool HasWork => Windows.Count > 0;
}

/// <summary>
/// The scheduling arithmetic, and the two decisions in it that a detection platform lives or dies by.
///
/// <b>Elasticsearch is not synchronous with the world.</b> A log line written at 10:00:00 may not be
/// searchable until 10:00:20. Querying up to <c>now</c> would miss it permanently — the window it belonged
/// to has been evaluated and will never be looked at again. So evaluation always trails real time by a
/// configured delay. This is the most common way a detection platform silently stops detecting, and it
/// leaves no error behind when it happens.
///
/// <b>Windows slide; they do not tile.</b> "Twenty failures in five minutes" against fixed five-minute
/// buckets misses nineteen failures at 10:04 followed by nineteen at 10:06 — which is not a corner case,
/// it is what a paced attack looks like. Each evaluation therefore looks back a full window from where it
/// has reached, and consecutive evaluations overlap. The cost of that overlap is that a subject keeps
/// qualifying for as long as its events are in range, which is precisely what cooldown exists to absorb.
/// </summary>
public static class TimeWindowPlanner
{
    /// <summary>
    /// How many evaluations a single run will catch up on. A rule re-enabled after a week must not turn
    /// into ten thousand queries against the cluster in one tick.
    /// </summary>
    public const int DefaultMaxCatchUpWindows = 12;

    public static EvaluationPlan Plan(
        DateTimeOffset now,
        DateTimeOffset? checkpoint,
        TimeSpan window,
        TimeSpan queryDelay,
        TimeSpan interval,
        int maxCatchUpWindows = DefaultMaxCatchUpWindows)
    {
        if (window <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(window), "A rule's window must be positive.");

        if (interval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(interval), "A rule's interval must be positive.");

        var maxCatchUp = Math.Max(1, maxCatchUpWindows);

        // The latest instant the source can be trusted to have finished ingesting.
        var horizon = now - (queryDelay < TimeSpan.Zero ? TimeSpan.Zero : queryDelay);

        if (checkpoint is null)
        {
            // A rule that has never run looks back one window and no further. Replaying history on first
            // enable would fire on events an operator has already dealt with — and, with actions attached,
            // would act on them.
            return new EvaluationPlan(
                [TimeRange.EndingAt(horizon, window)],
                horizon,
                SkippedBacklog: false,
                "First evaluation: one window back from the ingest horizon.");
        }

        var from = checkpoint.Value;

        if (horizon <= from)
            return new EvaluationPlan(
                [],
                from,
                SkippedBacklog: false,
                "Nothing new to evaluate yet: the ingest horizon has not passed the checkpoint.");

        var elapsed = horizon - from;
        var steps = (int)Math.Ceiling(elapsed / interval);
        var skipped = false;

        if (steps > maxCatchUp)
        {
            // Evaluate the most recent stretches rather than the oldest. After an outage the question worth
            // answering is what is happening now; the gap is reported so it is not mistaken for coverage.
            steps = maxCatchUp;
            skipped = true;
        }

        var windows = new List<TimeRange>(steps);

        for (var step = steps - 1; step >= 0; step--)
        {
            var end = horizon - interval * step;
            windows.Add(TimeRange.EndingAt(end, window));
        }

        return new EvaluationPlan(
            windows,
            horizon,
            skipped,
            skipped
                ? $"Behind by {elapsed:g}; evaluated the most recent {steps} of {(int)Math.Ceiling(elapsed / interval)} windows."
                : $"Evaluated {steps} window(s) up to the ingest horizon.");
    }

    /// <summary>
    /// Where a checkpoint should be placed when an operator asks to re-scan from a chosen time.
    ///
    /// Clamped to the horizon so that rewinding cannot move the checkpoint into time the source has not
    /// finished ingesting, which would make the first window after the reset read half-written data.
    /// </summary>
    public static DateTimeOffset ResetTo(DateTimeOffset requested, DateTimeOffset now, TimeSpan queryDelay)
    {
        var horizon = now - (queryDelay < TimeSpan.Zero ? TimeSpan.Zero : queryDelay);
        return requested > horizon ? horizon : requested;
    }
}
