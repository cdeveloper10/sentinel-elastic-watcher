using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Engine;
using Sentinel.Domain.Platform;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
/// The engine's own row, written after every tick.
///
/// An upsert rather than an insert: a node reports continuously and only its latest state is interesting.
/// Written after the tick rather than before, so "last seen" means "last completed a full evaluation pass"
/// — an engine wedged mid-tick stops reporting, which is precisely what an operator needs to see.
/// </summary>
public sealed class EfEngineNodeStore(SentinelDbContext db) : IEngineNodeStore
{
    public async Task ReportAsync(EngineHeartbeat heartbeat, CancellationToken ct = default)
    {
        var node = await db.EngineNodes.FirstOrDefaultAsync(n => n.NodeId == heartbeat.NodeId, ct);

        if (node is null)
        {
            node = new EngineNode { NodeId = heartbeat.NodeId, StartedAt = heartbeat.StartedAt.UtcDateTime };
            db.EngineNodes.Add(node);
        }

        node.LastSeenAt = DateTime.UtcNow;
        node.Version = heartbeat.Version;
        node.Enabled = heartbeat.Enabled;
        node.TickSeconds = heartbeat.TickSeconds;
        node.MaxConcurrentRules = heartbeat.MaxConcurrentRules;
        node.ActionsEnabled = heartbeat.ActionsEnabled;
        node.NeverActEntries = heartbeat.NeverActEntries;
        node.LastTickRulesEvaluated = heartbeat.RulesEvaluated;
        node.LastTickAlertsRaised = heartbeat.AlertsRaised;
        node.LastTickDurationMs = heartbeat.DurationMs;

        await db.SaveChangesAsync(ct);
    }

    public Task<int> SweepAsync(TimeSpan olderThan, CancellationToken ct = default)
    {
        var cutoff = DateTime.UtcNow - olderThan;

        return db.EngineNodes.Where(n => n.LastSeenAt < cutoff).ExecuteDeleteAsync(ct);
    }
}
