using Microsoft.Extensions.Logging;
using Sentinel.Application.Audit;
using Sentinel.Domain.Platform;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
/// The audit trail, as rows.
///
/// One decision worth stating: a failure to write an audit row is logged and swallowed rather than
/// propagated. That is the opposite of the usual instinct, and it is deliberate — the alternative is that
/// a full disk or a locked table stops the platform from blocking an address during an incident. Losing
/// the record of an action is bad; losing the action is worse.
///
/// The trade is only acceptable because the loss is loud: it goes to the application log at error level,
/// where the platform's own monitoring sees it.
/// </summary>
public sealed class EfAuditTrail(
    SentinelDbContext db,
    TimeProvider clock,
    ILogger<EfAuditTrail> logger) : IAuditTrail
{
    public async Task RecordAsync(
        Actor actor,
        string operation,
        string resourceType,
        string resourceId,
        string result = "SUCCESS",
        object? changes = null,
        string? detail = null,
        CancellationToken ct = default)
    {
        var entry = new AuditEntry
        {
            OccurredAt = clock.GetUtcNow().UtcDateTime,
            Actor = actor.Name,
            Operation = operation,
            ResourceType = resourceType,
            ResourceId = resourceId,
            Result = result,
            SourceIp = actor.SourceIp,
            CorrelationId = actor.CorrelationId,

            // Redacted here rather than at every call site: relying on each caller to remember would mean
            // one forgetful controller puts an API key in the audit table.
            Changes = changes is null ? null : AuditChanges.Describe(changes),
            Detail = Truncate(detail, 2_000)
        };

        try
        {
            db.AuditEntries.Add(entry);
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex)
        {
            db.ChangeTracker.Clear();

            logger.LogError(ex,
                "Failed to record audit entry {Operation} on {ResourceType}/{ResourceId} by {Actor}",
                operation, resourceType, resourceId, actor.Name);
        }
    }

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
