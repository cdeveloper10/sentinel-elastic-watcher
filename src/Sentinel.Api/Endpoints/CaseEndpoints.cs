using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Auth;
using Sentinel.Application.Audit;
using Sentinel.Application.Security;
using Sentinel.Domain.Alerts;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Api.Endpoints;

/// <summary>
/// Investigations.
///
/// Read with <c>alerts.read</c> and worked with <c>alerts.acknowledge</c> and <c>alerts.resolve</c>: a case
/// is a view onto alerts, and somebody who may close an alert may close the investigation it belongs to.
/// A separate permission would mean an analyst with every alert permission still could not do their job.
/// </summary>
public static class CaseEndpoints
{
    public static void MapCases(this WebApplication app)
    {
        var group = app.MapGroup("/api/cases").WithTags("Cases");

        group.MapGet("", async (
            SentinelDbContext db, CancellationToken ct, string? status = null, int take = 100) =>
        {
            var query = db.Cases.AsNoTracking();

            // "open" as a single filter rather than making the console ask for two statuses, because the
            // queue somebody works from is everything not yet closed.
            if (string.Equals(status, "open", StringComparison.OrdinalIgnoreCase))
                query = query.Where(c => c.Status != CaseStatus.Closed);
            else if (CaseStatus.Canonical(status) is { } exact)
                query = query.Where(c => c.Status == exact);

            return Results.Ok(await query
                .OrderByDescending(c => c.LastAlertAt)
                .Take(Math.Clamp(take, 1, 200))
                .Select(c => new
                {
                    c.Id, c.CaseId, c.Title, c.EntityLabel, c.Status, c.Severity,
                    c.AssignedTo, c.AlertCount, c.OpenedAt, c.LastAlertAt, c.ClosedAt, c.Disposition
                })
                .ToListAsync(ct));
        }).Requires(Permission.AlertsRead);

        group.MapGet("/{id:int}", async (int id, SentinelDbContext db, CancellationToken ct) =>
        {
            var found = await db.Cases.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);

            if (found is null)
                return Results.NotFound();

            var alerts = await db.Alerts.AsNoTracking()
                .Where(a => a.CaseId == id)
                .OrderByDescending(a => a.DetectedAt)
                .Select(a => new
                {
                    a.Id, a.AlertId, a.RuleName, a.RuleVersion, a.Severity, a.Subject,
                    a.EventCount, a.DetectedAt, a.Status, a.Disposition, a.EnrichmentJson
                })
                .ToListAsync(ct);

            // Ordered by identity, not by timestamp. Rules evaluate concurrently and each captures its
            // own "now" before touching the database, so the alert that *opened* a case can carry a
            // timestamp a microsecond later than one that joined it immediately afterwards — and the
            // timeline then reads "alert added" before "opened", which is not what happened. The
            // insertion order of an append-only log is the order things happened in.
            var timeline = await db.CaseEvents.AsNoTracking()
                .Where(e => e.CaseId == id)
                .OrderBy(e => e.Id)
                .ToListAsync(ct);

            // What the platform did across every alert in the case. During an incident this is the
            // question — "what have we already changed" — and answering it per alert makes somebody
            // assemble it in their head from twelve drawers.
            var alertIds = alerts.Select(a => a.Id).ToList();

            var executions = await db.ActionExecutions.AsNoTracking()
                .Where(e => alertIds.Contains(e.AlertId))
                .OrderByDescending(e => e.CreatedAt)
                .ToListAsync(ct);

            return Results.Ok(new { @case = found, alerts, timeline, executions });
        }).Requires(Permission.AlertsRead);

        group.MapPost("/{id:int}/assign", async (
            int id, AssignCaseRequest request, SentinelDbContext db, IAuditTrail audit,
            CurrentUser current, TimeProvider clock, CancellationToken ct) =>
        {
            var found = await db.Cases.FirstOrDefaultAsync(c => c.Id == id, ct);

            if (found is null)
                return Results.NotFound();

            if (found.Status == CaseStatus.Closed)
                return Results.BadRequest(new { error = "That case is closed." });

            var actor = await current.ActorAsync(ct);
            var now = clock.GetUtcNow().UtcDateTime;

            // Blank means unassign, which is a real action: putting a case back in the queue because you
            // are going off shift is not the same as leaving it assigned to somebody who has gone home.
            var assignee = string.IsNullOrWhiteSpace(request?.To) ? null : request!.To!.Trim();

            found.AssignedTo = assignee;

            // Picking one up moves it out of the untouched queue. Doing that by hand as a second step is
            // a step everybody forgets, and then the queue lies.
            if (assignee is not null && found.Status == CaseStatus.Open)
                found.Status = CaseStatus.Investigating;

            db.CaseEvents.Add(new CaseEvent
            {
                CaseId = id,
                At = now,
                Kind = CaseEventKind.Assigned,
                Author = actor.Name,
                Text = assignee is null ? "Unassigned." : $"Assigned to {assignee}."
            });

            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, "CASE_ASSIGNED", "case", id.ToString(),
                detail: assignee, ct: ct);

            return Results.Ok(new { found.Id, found.Status, found.AssignedTo });
        }).Requires(Permission.AlertsAcknowledge);

        group.MapPost("/{id:int}/note", async (
            int id, CaseNoteRequest request, SentinelDbContext db, CurrentUser current,
            TimeProvider clock, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(request?.Text))
                return Results.BadRequest(new { error = "A note needs something in it." });

            if (!await db.Cases.AnyAsync(c => c.Id == id, ct))
                return Results.NotFound();

            // Allowed on a closed case. What somebody learns a week later belongs on the investigation it
            // is about, and the alternative is that it is written nowhere.
            db.CaseEvents.Add(new CaseEvent
            {
                CaseId = id,
                At = clock.GetUtcNow().UtcDateTime,
                Kind = CaseEventKind.Note,
                Author = (await current.ActorAsync(ct)).Name,
                Text = request!.Text!.Trim()
            });

            await db.SaveChangesAsync(ct);

            return Results.NoContent();
        }).Requires(Permission.AlertsAcknowledge);

        group.MapPost("/{id:int}/close", async (
            int id, CloseCaseRequest request, SentinelDbContext db, IAuditTrail audit,
            CurrentUser current, TimeProvider clock, CancellationToken ct) =>
        {
            var found = await db.Cases.FirstOrDefaultAsync(c => c.Id == id, ct);

            if (found is null)
                return Results.NotFound();

            if (found.Status == CaseStatus.Closed)
                return Results.BadRequest(new { error = $"Already closed at {found.ClosedAt:u}." });

            var disposition = AlertDisposition.Canonical(request?.Disposition);

            if (disposition is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["disposition"] =
                    [
                        "Say what the investigation concluded: " + string.Join(", ", AlertDisposition.All) +
                        ". It is applied to every alert in the case that is still open."
                    ]
                });
            }

            var actor = await current.ActorAsync(ct);
            var now = clock.GetUtcNow().UtcDateTime;

            // The payoff of having cases at all. Twelve alerts about one host are one conclusion, and
            // making somebody record it twelve times is the toil this exists to remove — so closing the
            // case closes the alerts that are still open, with the same disposition.
            var open = await db.Alerts
                .Where(a => a.CaseId == id && a.Status != AlertStatus.Resolved)
                .ToListAsync(ct);

            foreach (var alert in open)
            {
                alert.Status = AlertStatus.Resolved;
                alert.ResolvedBy = actor.Name;
                alert.ResolvedAt = now;
                alert.Disposition = disposition;
                alert.ResolutionNote = request!.Note;
            }

            found.Status = CaseStatus.Closed;
            found.ClosedAt = now;
            found.ClosedBy = actor.Name;
            found.Disposition = disposition;
            found.ClosingNote = request!.Note;

            // Releases the unique index, so the next alert about this entity opens a fresh investigation
            // rather than reopening one somebody has finished with.
            found.OpenKey = null;

            db.CaseEvents.Add(new CaseEvent
            {
                CaseId = id,
                At = now,
                Kind = CaseEventKind.Closed,
                Author = actor.Name,
                Text = open.Count == 0
                    ? $"Closed as {disposition}."
                    : $"Closed as {disposition}. {open.Count} alert(s) resolved with it."
            });

            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, "CASE_CLOSED", "case", id.ToString(),
                detail: $"{disposition}. {open.Count} alert(s) resolved.", ct: ct);

            return Results.Ok(new { found.Id, found.Status, found.Disposition, alertsResolved = open.Count });
        }).Requires(Permission.AlertsResolve);
    }
}
