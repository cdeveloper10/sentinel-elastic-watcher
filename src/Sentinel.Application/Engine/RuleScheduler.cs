using Microsoft.Extensions.Logging;

namespace Sentinel.Application.Engine;

public sealed class EngineSettings
{
    /// <summary>Stops evaluation entirely without disabling rules, for when the platform itself is the problem.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often the scheduler looks for work. Not how often a rule runs — that is the rule's interval.</summary>
    public int TickSeconds { get; set; } = 10;

    /// <summary>How long a node holds a rule. Long enough to finish an evaluation, short enough to recover from a lost node.</summary>
    public int LeaseSeconds { get; set; } = 120;

    /// <summary>Rules evaluated at once on one node.</summary>
    public int MaxConcurrentRules { get; set; } = 4;

    /// <summary>Ceiling on the delay a repeatedly failing rule is held back by.</summary>
    public int MaxBackoffSeconds { get; set; } = 900;

    /// <summary>Identifies this node in leases and logs. Defaults to the machine name.</summary>
    public string NodeId { get; set; } = Environment.MachineName;
}

/// <summary>
/// Short-lived ownership of a rule.
///
/// Per rule rather than one leader for the whole engine: a single leader leaves every other node idle and
/// makes the platform's throughput that of one machine. Leasing each rule spreads the work and still
/// answers the only question that matters — that two nodes never evaluate one rule at the same moment,
/// which would double every alert and every block.
///
/// Leases expire rather than being released, so a node that dies mid-evaluation does not hold its rules
/// hostage until somebody notices.
/// </summary>
public interface IRuleLeaseStore
{
    Task<bool> TryAcquireAsync(int ruleId, string owner, TimeSpan duration, CancellationToken ct = default);

    Task ReleaseAsync(int ruleId, string owner, CancellationToken ct = default);
}

/// <summary>
/// Everything one rule's evaluation needs, isolated from the other rules in the same tick.
///
/// This interface exists because of a defect. The scheduler evaluates up to
/// <see cref="EngineSettings.MaxConcurrentRules"/> rules at once, and the engine took one scope per tick —
/// so every concurrent evaluation shared one <c>DbContext</c>, which is not thread-safe. With a single rule
/// armed, nothing ever went wrong. With three, two of them threw "a second operation was started on this
/// context instance" and simply did not evaluate: no alert, no failure recorded against the rule, nothing
/// anywhere but the engine's own log — a platform quietly detecting less than it was asked to.
///
/// A scope per rule rather than a lock around the context, because the point of the concurrency is to
/// overlap the waiting: a rule spends its time querying Elasticsearch, not the database.
/// </summary>
public interface IRuleEvaluationSlot : IAsyncDisposable
{
    RuleEvaluator Evaluator { get; }

    IRuleLeaseStore Leases { get; }
}

/// <summary>Hands out one slot per rule. Implemented over the container's scopes.</summary>
public interface IRuleEvaluationSlotFactory
{
    IRuleEvaluationSlot Create();
}

/// <summary>
/// A slot factory that hands back the same instances every time.
///
/// For a caller that evaluates one rule at a time and knows it — a test, or a single rule run by hand from
/// the console. Using it under concurrency reintroduces exactly the defect <see cref="IRuleEvaluationSlot"/>
/// describes, which is why the engine host does not.
/// </summary>
public sealed class SharedRuleEvaluationSlots(RuleEvaluator evaluator, IRuleLeaseStore leases)
    : IRuleEvaluationSlotFactory, IRuleEvaluationSlot
{
    public RuleEvaluator Evaluator { get; } = evaluator;

    public IRuleLeaseStore Leases { get; } = leases;

    public IRuleEvaluationSlot Create() => this;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>
/// Decides which rules are due and evaluates them, one tick at a time.
///
/// Not a hosted service — this is the loop body, callable once. The host wraps it; a test calls
/// <see cref="TickAsync"/> and asserts on the result rather than waiting on a timer.
/// </summary>
public sealed class RuleScheduler(
    IRuleRuntimeSource rules,
    ICheckpointStore checkpoints,
    IRuleEvaluationSlotFactory slots,
    EngineSettings settings,
    ILogger<RuleScheduler> logger,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<IReadOnlyList<EvaluationOutcome>> TickAsync(CancellationToken ct = default)
    {
        if (!settings.Enabled)
            return [];

        var active = await rules.ActiveRulesAsync(ct);
        var now = _clock.GetUtcNow();
        var outcomes = new List<EvaluationOutcome>();

        // Bounded concurrency: a hundred due rules must not open a hundred simultaneous searches against a
        // cluster that is also serving the estate.
        using var permits = new SemaphoreSlim(Math.Max(1, settings.MaxConcurrentRules));
        var running = new List<Task<EvaluationOutcome?>>();

        foreach (var (rule, source) in active)
        {
            if (ct.IsCancellationRequested)
                break;

            if (!await IsDueAsync(rule.RuleId, rule.Interval, now, ct))
                continue;

            await permits.WaitAsync(ct);

            running.Add(Task.Run(async () =>
            {
                try
                {
                    // Its own slot, and so its own database connection. Everything below this line runs
                    // alongside the other rules in this tick and must share nothing with them.
                    await using var slot = slots.Create();

                    // Claimed before any work. A node that cannot claim moves on rather than waiting:
                    // whoever holds it is already doing this.
                    if (!await slot.Leases.TryAcquireAsync(rule.RuleId, settings.NodeId, Lease(), ct))
                        return null;

                    try
                    {
                        return await slot.Evaluator.EvaluateAsync(rule, source, dispatchActions: true, ct);
                    }
                    finally
                    {
                        await slot.Leases.ReleaseAsync(rule.RuleId, settings.NodeId, CancellationToken.None);
                    }
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
                catch (Exception ex)
                {
                    // Never allowed to escape: one broken rule must not stop the scheduler from evaluating
                    // the rest, which is exactly how a single bad rule becomes a platform outage.
                    logger.LogError(ex, "Rule {RuleId} threw outside its evaluator", rule.RuleId);
                    return null;
                }
                finally
                {
                    permits.Release();
                }
            }, ct));
        }

        foreach (var result in await Task.WhenAll(running))
        {
            if (result is not null)
                outcomes.Add(result);
        }

        return outcomes;
    }

    /// <summary>
    /// Whether enough time has passed since the rule last reached a checkpoint — and, if it has been
    /// failing, whether its backoff has elapsed.
    /// </summary>
    private async Task<bool> IsDueAsync(int ruleId, TimeSpan interval, DateTimeOffset now, CancellationToken ct)
    {
        var checkpoint = await checkpoints.ReadAsync(ruleId, ct);

        if (checkpoint is null)
            return true; // Never run. The planner decides where a first window starts.

        var failures = await checkpoints.ConsecutiveFailuresAsync(ruleId, ct);
        var due = checkpoint.Value + interval + Backoff(failures);

        return now >= due;
    }

    /// <summary>
    /// Holds a failing rule back, so an unreachable cluster is queried on a widening interval rather than
    /// every tick by every node. Capped, because a rule that has backed off to an hour is a rule that will
    /// not notice the cluster coming back.
    /// </summary>
    internal TimeSpan Backoff(int consecutiveFailures)
    {
        if (consecutiveFailures <= 0)
            return TimeSpan.Zero;

        var seconds = Math.Min(
            settings.MaxBackoffSeconds,
            Math.Pow(2, Math.Min(consecutiveFailures, 12)) * 5);

        return TimeSpan.FromSeconds(seconds);
    }

    private TimeSpan Lease() => TimeSpan.FromSeconds(Math.Max(10, settings.LeaseSeconds));
}
