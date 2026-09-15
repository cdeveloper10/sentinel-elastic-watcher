using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Actions;
using Sentinel.Application.Detection;
using Sentinel.Application.Enrichment;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Platform;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
/// Deduplication, backed by the unique index on <c>alerts.fingerprint</c>.
///
/// The insert is attempted and the failure is the answer. Checking first and then inserting looks tidier
/// and is wrong: between the check and the write another node inserts the same fingerprint, both believe
/// they are first, and one detection becomes two alerts — each with its own dispatch, each blocking the
/// same address.
/// </summary>
public sealed class EfAlertStore(SentinelDbContext db, ILogger<EfAlertStore> logger) : IAlertStore
{
    public async Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default)
    {
        db.Alerts.Add(alert);

        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            db.Entry(alert).State = EntityState.Detached;

            // Provider-agnostic: rather than matching SQLSTATE 23505 against Postgres and error 2067
            // against SQLite, ask whether the row that would have collided is now there. If it is, this
            // was a duplicate; if it is not, the write failed for some other reason and must not be
            // swallowed as one.
            var existing = await db.Alerts
                .AsNoTracking()
                .AnyAsync(a => a.Fingerprint == alert.Fingerprint, ct);

            if (!existing)
                throw;

            logger.LogDebug(
                "Alert {Fingerprint} for rule {RuleId} was already recorded", alert.Fingerprint, alert.RuleId);

            return false;
        }
    }
}

/// <summary>
/// Cooldown state as rows, so it survives a restart.
///
/// Holding this in memory would mean a deploy releases every subject that was being suppressed at once —
/// a rolling update turning into an alert storm, and with actions attached, a wave of blocks.
/// </summary>
public sealed class EfCooldownStore(SentinelDbContext db, TimeProvider clock) : ICooldownStore
{
    public async Task<DateTimeOffset?> LastFiredAtAsync(string key, CancellationToken ct = default)
    {
        var entry = await db.Cooldowns.AsNoTracking().FirstOrDefaultAsync(c => c.Key == key, ct);

        if (entry is null)
            return null;

        // An expired row is not a cooldown. Read as absent rather than waiting for the sweeper, so
        // suppression ends exactly when it should rather than whenever cleanup last ran.
        return entry.ExpiresAt <= clock.GetUtcNow().UtcDateTime
            ? null
            : new DateTimeOffset(entry.FiredAt, TimeSpan.Zero);
    }

    public async Task RecordAsync(string key, DateTimeOffset firedAt, TimeSpan retention, CancellationToken ct = default)
    {
        var existing = await db.Cooldowns.FirstOrDefaultAsync(c => c.Key == key, ct);
        var expires = firedAt.Add(retention).UtcDateTime;

        if (existing is null)
        {
            db.Cooldowns.Add(new CooldownEntry
            {
                Key = key,
                FiredAt = firedAt.UtcDateTime,
                ExpiresAt = expires
            });
        }
        else
        {
            existing.FiredAt = firedAt.UtcDateTime;
            existing.ExpiresAt = expires;
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Another node recorded the same subject in the same instant. Both mean "this fired"; the
            // stored value is equivalent either way.
            db.ChangeTracker.Clear();
        }
    }

    /// <summary>Removes expired rows. One per subject per rule adds up on a busy estate.</summary>
    public Task<int> SweepAsync(CancellationToken ct = default) =>
        db.Cooldowns.Where(c => c.ExpiresAt <= clock.GetUtcNow().UtcDateTime).ExecuteDeleteAsync(ct);
}

/// <summary>
/// The action claim, backed by the unique index on <c>action_executions.idempotency_key</c>.
///
/// This is what makes "if the same alert is processed twice, do not block twice" true rather than
/// intended. The dispatcher asks to claim before its first attempt, and a refused claim means somebody
/// else — another node, or this one before a restart — already owns the action.
/// </summary>
public sealed class EfActionExecutionStore(
    SentinelDbContext db, ILogger<EfActionExecutionStore> logger) : IActionExecutionStore, IApprovalSweep
{
    public async Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default)
    {
        db.ActionExecutions.Add(execution);

        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            db.Entry(execution).State = EntityState.Detached;

            var claimed = await db.ActionExecutions
                .AsNoTracking()
                .AnyAsync(e => e.IdempotencyKey == execution.IdempotencyKey, ct);

            if (!claimed)
                throw;

            logger.LogInformation(
                "Action {Action} for alert {Alert} was already claimed under {Key}",
                execution.ActionType, execution.AlertId, execution.IdempotencyKey);

            return false;
        }
    }

    public async Task UpdateAsync(ActionExecution execution, CancellationToken ct = default)
    {
        db.ActionExecutions.Update(execution);
        await db.SaveChangesAsync(ct);
    }

    public async Task<int> ExpireApprovalsAsync(DateTime asOf, CancellationToken ct = default)
    {
        // One statement rather than loading the rows: this runs on every tick on every node, and nothing
        // is holding what it touches. The filter is the one the index covers.
        var expired = await db.ActionExecutions
            .Where(e => e.Status == ActionExecutionStatus.PendingApproval &&
                        e.ApprovalExpiresAt != null &&
                        e.ApprovalExpiresAt <= asOf)
            .ExecuteUpdateAsync(set => set
                .SetProperty(e => e.Status, ActionExecutionStatus.Expired)
                .SetProperty(e => e.ErrorCode, "APPROVAL_EXPIRED")
                .SetProperty(e => e.ErrorMessage, "Nobody approved it in time, so it was not carried out.")
                .SetProperty(e => e.FinishedAt, asOf), ct);

        if (expired > 0)
            logger.LogWarning("{Count} held action(s) expired without a decision", expired);

        return expired;
    }
}

/// <summary>
/// The asset inventory, read whole.
///
/// Cached for a short while because it is read on the path that records every alert and changes about
/// once a week. Short enough that an operator who has just corrected an entry sees it take effect inside
/// a minute, which is the interval at which somebody fixing a wrong criticality gives up and asks whether
/// the feature works.
/// </summary>
public sealed class EfAssetLookup(SentinelDbContext db, TimeProvider clock) : IAssetLookup
{
    private static readonly TimeSpan Freshness = TimeSpan.FromSeconds(30);

    // Static, so the cache is shared across the scoped instances the engine creates per tick rather than
    // being discarded with each one — which would make it no cache at all.
    private static IReadOnlyList<Asset> _cached = [];
    private static DateTimeOffset _readAt = DateTimeOffset.MinValue;
    private static readonly SemaphoreSlim Refreshing = new(1, 1);

    public async Task<IReadOnlyList<Asset>> AllAsync(CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();

        if (now - _readAt < Freshness)
            return _cached;

        await Refreshing.WaitAsync(ct);

        try
        {
            // Checked again inside the gate: several rules evaluating at once would otherwise all find it
            // stale and all read the table.
            if (clock.GetUtcNow() - _readAt < Freshness)
                return _cached;

            _cached = await db.Assets.AsNoTracking().ToListAsync(ct);
            _readAt = clock.GetUtcNow();

            return _cached;
        }
        finally
        {
            Refreshing.Release();
        }
    }

    /// <summary>Drops the cache, so an edit in the console is visible on the next alert rather than in half a minute.</summary>
    public static void Invalidate() => _readAt = DateTimeOffset.MinValue;
}

/// <summary>
/// Counts disruptive actions in a fixed window, so the safety caps hold across restarts and nodes.
///
/// Fixed rather than sliding on purpose: this is a circuit breaker on the platform's own behaviour, not a
/// billing meter. Being approximately right at the window boundary costs nothing, and the simpler shape
/// is one row per key rather than one per event.
/// </summary>
public sealed class EfActionRateStore(SentinelDbContext db, TimeProvider clock) : IActionRateStore
{
    public async Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var counter = await db.ActionRateCounters.FirstOrDefaultAsync(c => c.Key == key, ct);

        if (counter is null)
        {
            counter = new ActionRateCounter
            {
                Key = key,
                WindowStart = now,
                Count = 1,
                ExpiresAt = now.Add(window)
            };

            db.ActionRateCounters.Add(counter);
        }
        else if (counter.ExpiresAt <= now)
        {
            counter.WindowStart = now;
            counter.Count = 1;
            counter.ExpiresAt = now.Add(window);
        }
        else
        {
            counter.Count++;
        }

        try
        {
            await db.SaveChangesAsync(ct);
            return counter.Count;
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();

            // Lost a race. Reading the winner's value keeps the cap conservative, which is the direction
            // to err in for a control that exists to stop the platform doing too much.
            var current = await db.ActionRateCounters.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Key == key, ct);

            return current?.Count ?? 1;
        }
    }

    public async Task<int> CurrentAsync(string key, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;

        var counter = await db.ActionRateCounters.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Key == key, ct);

        return counter is null || counter.ExpiresAt <= now ? 0 : counter.Count;
    }

    public Task<int> SweepAsync(CancellationToken ct = default) =>
        db.ActionRateCounters.Where(c => c.ExpiresAt <= clock.GetUtcNow().UtcDateTime).ExecuteDeleteAsync(ct);
}

/// <summary>Resolves the connection an action binding names.</summary>
public sealed class EfConnectionLookup(SentinelDbContext db) : IConnectionLookup
{
    public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
        db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Name == name, ct);
}
