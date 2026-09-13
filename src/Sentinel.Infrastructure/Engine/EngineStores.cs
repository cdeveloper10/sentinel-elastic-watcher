using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Engine;
using Sentinel.Domain.Platform;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Infrastructure.Engine;

/// <summary>
/// Where each rule's evaluation has reached, and how its last run went.
///
/// Persisted because the alternative — starting a window back after every restart — means a rolling
/// update silently skips whatever happened while the pod was down. The checkpoint is the difference
/// between a deploy costing latency and a deploy costing coverage.
/// </summary>
public sealed class EfCheckpointStore(SentinelDbContext db, TimeProvider clock) : ICheckpointStore
{
    public async Task<DateTimeOffset?> ReadAsync(int ruleId, CancellationToken ct = default)
    {
        var checkpoint = await db.Checkpoints.AsNoTracking().FirstOrDefaultAsync(c => c.RuleId == ruleId, ct);

        return checkpoint is null ? null : new DateTimeOffset(checkpoint.EvaluatedTo, TimeSpan.Zero);
    }

    public async Task WriteAsync(int ruleId, EvaluationOutcome outcome, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var checkpoint = await db.Checkpoints.FirstOrDefaultAsync(c => c.RuleId == ruleId, ct);

        if (checkpoint is null)
        {
            checkpoint = new RuleCheckpoint { RuleId = ruleId };
            db.Checkpoints.Add(checkpoint);
        }

        checkpoint.EvaluatedTo = outcome.Checkpoint.UtcDateTime;
        checkpoint.UpdatedAt = now;
        checkpoint.LastRunAt = now;
        checkpoint.LastRunWindows = outcome.WindowsEvaluated;
        checkpoint.LastRunAlerts = outcome.AlertsRaised;
        checkpoint.LastRunDurationMs = outcome.DurationMs;
        checkpoint.LastRunSkippedBacklog = outcome.SkippedBacklog;

        if (outcome.Failed)
        {
            checkpoint.LastError = Truncate(outcome.Error, 2_000);
            checkpoint.LastErrorAt = now;

            // Counted, not just recorded: the scheduler reads this to widen the interval, so a cluster
            // that is down is queried on a growing delay rather than by every node every tick.
            checkpoint.ConsecutiveFailures++;
        }
        else
        {
            // Kept rather than cleared, so "this rule was failing an hour ago" stays answerable in the UI
            // after it recovers.
            checkpoint.ConsecutiveFailures = 0;
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Moves a rule's checkpoint, so an operator can re-examine a stretch of time after fixing a rule.
    /// Null starts it from scratch.
    /// </summary>
    public async Task ResetAsync(int ruleId, DateTimeOffset? to, CancellationToken ct = default)
    {
        var checkpoint = await db.Checkpoints.FirstOrDefaultAsync(c => c.RuleId == ruleId, ct);

        if (to is null)
        {
            // No checkpoint at all: the next run starts wherever the planner decides a first window
            // begins, as though the rule had just been created.
            if (checkpoint is not null)
                db.Checkpoints.Remove(checkpoint);
        }
        else
        {
            checkpoint ??= db.Checkpoints.Add(new RuleCheckpoint { RuleId = ruleId }).Entity;
            checkpoint.EvaluatedTo = to.Value.UtcDateTime;
            checkpoint.UpdatedAt = clock.GetUtcNow().UtcDateTime;

            // A reset is an operator saying "try again from here", so the failure history that was holding
            // the rule back goes with it.
            checkpoint.ConsecutiveFailures = 0;
            checkpoint.LastError = null;
            checkpoint.LastErrorAt = null;
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<int> ConsecutiveFailuresAsync(int ruleId, CancellationToken ct = default) =>
        await db.Checkpoints.AsNoTracking()
            .Where(c => c.RuleId == ruleId)
            .Select(c => c.ConsecutiveFailures)
            .FirstOrDefaultAsync(ct);

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}

/// <summary>
/// Rule ownership as a lease row, claimed by conditional update.
///
/// A conditional <c>UPDATE ... WHERE expired-or-mine</c> rather than a read followed by a write: the read
/// would let two nodes both see a free lease and both take it, which is the one thing this exists to
/// prevent. Expressed as a single statement, the database decides.
///
/// Portable on purpose — a PostgreSQL advisory lock would be neater and would make the whole mechanism
/// untestable anywhere but PostgreSQL.
/// </summary>
public sealed class EfRuleLeaseStore(SentinelDbContext db, TimeProvider clock) : IRuleLeaseStore
{
    public async Task<bool> TryAcquireAsync(
        int ruleId, string owner, TimeSpan duration, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var until = now.Add(duration);

        // Taken only if nobody holds it, the holder's lease has expired, or the holder is this node
        // resuming its own work. ExecuteUpdate is one statement, so the check and the claim cannot be
        // separated by another node's claim.
        var claimed = await db.RuleLeases
            .Where(l => l.RuleId == ruleId && (l.ExpiresAt <= now || l.Owner == owner))
            .ExecuteUpdateAsync(
                set => set.SetProperty(l => l.Owner, owner)
                          .SetProperty(l => l.AcquiredAt, now)
                          .SetProperty(l => l.ExpiresAt, until),
                ct);

        if (claimed > 0)
            return true;

        // No row yet. The unique primary key settles the race between nodes inserting the first one.
        try
        {
            db.RuleLeases.Add(new RuleLease
            {
                RuleId = ruleId,
                Owner = owner,
                AcquiredAt = now,
                ExpiresAt = until
            });

            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            return false; // Another node inserted first; it owns the rule this tick.
        }
    }

    public async Task ReleaseAsync(int ruleId, string owner, CancellationToken ct = default) =>
        // Expired rather than deleted, so the row stays available for the next conditional claim and the
        // last owner remains visible for diagnosis.
        await db.RuleLeases
            .Where(l => l.RuleId == ruleId && l.Owner == owner)
            .ExecuteUpdateAsync(
                set => set.SetProperty(l => l.ExpiresAt, clock.GetUtcNow().UtcDateTime),
                ct);
}
