using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Auth;
using Sentinel.Application.Actions;
using Sentinel.Application.Audit;
using Sentinel.Application.Detection;
using Sentinel.Application.Engine;
using Sentinel.Application.Rules;
using Sentinel.Application.Security;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Platform;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Api.Endpoints;

public static class PlatformEndpoints
{
    // -- signing in ------------------------------------------------------------------------------

    public static void MapAuth(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/sign-in", async (
            SignInRequest request, HttpContext http, IIdentityService identity, IAuditTrail audit,
            CancellationToken ct) =>
        {
            var result = await identity.SignInAsync(request.Username ?? "", request.Password ?? "", ct);

            var actor = new Actor(
                request.Username ?? "unknown",
                http.Connection.RemoteIpAddress?.ToString(),
                http.TraceIdentifier);

            if (!result.Succeeded)
            {
                // Recorded, because a run of these is the signal that matters and it is invisible if only
                // successes are kept.
                await audit.RecordAsync(actor, AuditOperation.UserLoginFailed, "user", request.Username ?? "",
                    result: "DENIED", detail: result.Failure, ct: ct);

                return Results.Json(new { error = result.Failure }, statusCode: StatusCodes.Status401Unauthorized);
            }

            await http.SignInAsync(SignInCookie.Scheme, SignInCookie.Principal(result.User!));

            await audit.RecordAsync(actor, AuditOperation.UserLogin, "user", result.User!.Id.ToString(), ct: ct);

            return Results.Ok(new
            {
                result.User.Username,
                result.User.DisplayName,
                result.User.Roles,
                permissions = result.User.Permissions.Order()
            });
        });

        group.MapPost("/sign-out", async (HttpContext http) =>
        {
            await http.SignOutAsync(SignInCookie.Scheme);
            return Results.NoContent();
        });

        // What the UI reads on load to decide which navigation to render. Anonymous by design: the answer
        // for a signed-out caller is "nobody", which is not a secret.
        group.MapGet("/me", async (CurrentUser current, CancellationToken ct) =>
        {
            var user = await current.GetAsync(ct);

            return user is null
                ? Results.Json(new { signedIn = false }, statusCode: StatusCodes.Status401Unauthorized)
                : Results.Ok(new
                {
                    signedIn = true,
                    user.Username,
                    user.DisplayName,
                    user.Roles,
                    permissions = user.Permissions.Order()
                });
        });

        group.MapPost("/password", async (
            ChangePasswordRequest request, CurrentUser current, IIdentityService identity,
            IAuditTrail audit, CancellationToken ct) =>
        {
            var user = await current.GetAsync(ct);
            if (user is null)
                return Results.Unauthorized();

            // The current password is required even though the session is already trusted: a borrowed
            // screen should not be enough to lock the owner out of their own account.
            var confirm = await identity.SignInAsync(user.Username, request.CurrentPassword ?? "", ct);
            if (!confirm.Succeeded)
                return Results.BadRequest(new { error = "The current password was not accepted." });

            var (changed, failure) = await identity.SetPasswordAsync(user.Id, request.NewPassword ?? "", ct);
            if (!changed)
                return Results.BadRequest(new { error = failure });

            await audit.RecordAsync(await current.ActorAsync(ct),
                "USER_PASSWORD_CHANGED", "user", user.Id.ToString(), ct: ct);

            return Results.NoContent();
        }).RequiresSignIn();
    }

    // -- users -----------------------------------------------------------------------------------

    public static void MapUsers(this WebApplication app)
    {
        var group = app.MapGroup("/api/users").WithTags("Users").Requires(Permission.UsersManage);

        group.MapGet("", async (IIdentityService identity, CancellationToken ct) =>
            Results.Ok((await identity.ListAsync(ct)).Select(u => new
            {
                u.Id, u.Username, u.DisplayName, u.Enabled, u.CreatedAt, u.LastLoginAt,
                Roles = u.Roles.Select(r => r.Role?.Name).Where(n => n is not null)
            })));

        group.MapGet("/roles", async (IIdentityService identity, CancellationToken ct) =>
            Results.Ok((await identity.RolesAsync(ct)).Select(r => new
            {
                r.Name, r.Description, r.IsSystem,
                Permissions = RolePermissions.Read(r.PermissionsJson)
            })));

        group.MapPost("", async (
            CreateUserRequest request, IIdentityService identity, IAuditTrail audit,
            CurrentUser current, CancellationToken ct) =>
        {
            var (created, failure, userId) = await identity.CreateAsync(
                request.Username, request.DisplayName, request.Password, request.Roles ?? [], ct);

            if (!created)
                return Results.BadRequest(new { error = failure });

            await audit.RecordAsync(await current.ActorAsync(ct),
                AuditOperation.UserPermissionChanged, "user", userId.ToString(),
                changes: new { request.Username, roles = request.Roles }, ct: ct);

            return Results.Created($"/api/users/{userId}", new { id = userId });
        });

        group.MapPost("/{id:int}/roles", async (
            int id, SetUserRolesRequest request, IIdentityService identity, IAuditTrail audit,
            CurrentUser current, CancellationToken ct) =>
        {
            if (!await identity.SetRolesAsync(id, request.Roles ?? [], ct))
                return Results.NotFound();

            await audit.RecordAsync(await current.ActorAsync(ct),
                AuditOperation.UserPermissionChanged, "user", id.ToString(),
                changes: new { roles = request.Roles }, ct: ct);

            return Results.NoContent();
        });

        group.MapPost("/{id:int}/password", async (
            int id, SetPasswordRequest request, IIdentityService identity, IAuditTrail audit,
            CurrentUser current, CancellationToken ct) =>
        {
            var (changed, failure) = await identity.SetPasswordAsync(id, request.Password ?? "", ct);
            if (!changed)
                return Results.BadRequest(new { error = failure });

            await audit.RecordAsync(await current.ActorAsync(ct),
                "USER_PASSWORD_RESET", "user", id.ToString(), ct: ct);

            return Results.NoContent();
        });

        group.MapPost("/{id:int}/enable", async (
            int id, IIdentityService identity, IAuditTrail audit, CurrentUser current, CancellationToken ct) =>
            await SetEnabled(id, true, identity, audit, current, ct));

        group.MapPost("/{id:int}/disable", async (
            int id, IIdentityService identity, IAuditTrail audit, CurrentUser current, CancellationToken ct) =>
            await SetEnabled(id, false, identity, audit, current, ct));

        static async Task<IResult> SetEnabled(
            int id, bool enabled, IIdentityService identity, IAuditTrail audit, CurrentUser current,
            CancellationToken ct)
        {
            if (!await identity.SetEnabledAsync(id, enabled, ct))
                return Results.NotFound();

            await audit.RecordAsync(await current.ActorAsync(ct),
                AuditOperation.UserPermissionChanged, "user", id.ToString(),
                changes: new { enabled }, ct: ct);

            return Results.NoContent();
        }
    }

    // -- alerts ----------------------------------------------------------------------------------

    public static void MapAlerts(this WebApplication app)
    {
        var group = app.MapGroup("/api/alerts").WithTags("Alerts");

        group.MapGet("", async (
            SentinelDbContext db, CancellationToken ct,
            string? status = null, int? ruleId = null, int take = 50, int skip = 0) =>
        {
            var query = db.Alerts.AsNoTracking()
                .Where(a => (status == null || a.Status == status) && (ruleId == null || a.RuleId == ruleId));

            var total = await query.CountAsync(ct);

            var items = await query
                .OrderByDescending(a => a.DetectedAt)
                .Skip(Math.Max(0, skip))
                .Take(Math.Clamp(take, 1, 200))
                .ToListAsync(ct);

            return Results.Ok(new { total, items });
        }).Requires(Permission.AlertsRead);

        group.MapGet("/{id:long}", async (long id, SentinelDbContext db, CancellationToken ct) =>
        {
            var alert = await db.Alerts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, ct);
            if (alert is null)
                return Results.NotFound();

            // The version that produced it, not the rule as it is now — which may have been edited
            // because of this very alert.
            var version = await db.RuleVersions.AsNoTracking()
                .FirstOrDefaultAsync(v => v.RuleId == alert.RuleId && v.Version == alert.RuleVersion, ct);

            var executions = await db.ActionExecutions.AsNoTracking()
                .Where(e => e.AlertId == id)
                .OrderBy(e => e.CreatedAt)
                .ToListAsync(ct);

            return Results.Ok(new { alert, ruleVersion = version, executions });
        }).Requires(Permission.AlertsRead);

        group.MapPost("/{id:long}/acknowledge", async (
            long id, SentinelDbContext db, IAuditTrail audit, CurrentUser current,
            TimeProvider clock, CancellationToken ct) =>
        {
            var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id, ct);
            if (alert is null)
                return Results.NotFound();

            var actor = await current.ActorAsync(ct);

            alert.Status = AlertStatus.Acknowledged;
            alert.AcknowledgedBy = actor.Name;
            alert.AcknowledgedAt = clock.GetUtcNow().UtcDateTime;
            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, AuditOperation.AlertAcknowledged, "alert", id.ToString(), ct: ct);

            return Results.Ok(new { alert.Id, alert.Status });
        }).Requires(Permission.AlertsAcknowledge);

        group.MapPost("/{id:long}/resolve", async (
            long id, ResolveAlertRequest request, SentinelDbContext db, IAuditTrail audit,
            CurrentUser current, TimeProvider clock, CancellationToken ct) =>
        {
            var alert = await db.Alerts.FirstOrDefaultAsync(a => a.Id == id, ct);
            if (alert is null)
                return Results.NotFound();

            // Refused rather than defaulted. Guessing a disposition — "probably true" — would put a number
            // into the rule's precision that nobody stands behind, and the rate is only worth anything if
            // every point in it came from somebody who looked.
            var disposition = AlertDisposition.Canonical(request.Disposition);

            if (disposition is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["disposition"] =
                    [
                        "Say what this alert turned out to be: " + string.Join(", ", AlertDisposition.All) +
                        ". FALSE_POSITIVE means the rule was wrong; BENIGN means it was right and the " +
                        "activity was authorised."
                    ]
                });
            }

            var actor = await current.ActorAsync(ct);

            alert.Status = AlertStatus.Resolved;
            alert.ResolvedBy = actor.Name;
            alert.ResolvedAt = clock.GetUtcNow().UtcDateTime;
            alert.ResolutionNote = request.Note;
            alert.Disposition = disposition;
            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, AuditOperation.AlertResolved, "alert", id.ToString(),
                detail: $"{disposition}. {request.Note}".TrimEnd(), ct: ct);

            return Results.Ok(new { alert.Id, alert.Status, alert.Disposition });
        }).Requires(Permission.AlertsResolve);
    }

    // -- everything else -------------------------------------------------------------------------

    public static void MapOperations(this WebApplication app)
    {
        // How each rule has been doing, from the dispositions its alerts were closed with. Read with
        // rules.read: it is a report about rules, and an analyst who can see the rules should be able to
        // see which of them are wasting their time.
        app.MapGet("/api/rules/quality", async (SentinelDbContext db, CancellationToken ct) =>
        {
            var rules = await db.Rules.AsNoTracking()
                .Select(r => new { r.Id, r.Name, r.Enabled })
                .ToListAsync(ct);

            // One grouped pass rather than a query per rule: a hundred rules would otherwise be a hundred
            // round trips to draw one page.
            var counts = await db.Alerts.AsNoTracking()
                .GroupBy(a => new { a.RuleId, a.Disposition })
                .Select(g => new
                {
                    g.Key.RuleId,
                    g.Key.Disposition,
                    Count = g.Count(),
                    Last = g.Max(a => (DateTime?)a.DetectedAt)
                })
                .ToListAsync(ct);

            var quality = rules.Select(rule =>
            {
                var mine = counts.Where(c => c.RuleId == rule.Id).ToList();

                int Of(string disposition) =>
                    mine.Where(c => c.Disposition == disposition).Sum(c => c.Count);

                return new RuleQuality(
                    rule.Id,
                    rule.Name,
                    rule.Enabled,
                    Alerts: mine.Sum(c => c.Count),
                    Judged: mine.Where(c => c.Disposition != null).Sum(c => c.Count),
                    TruePositives: Of(AlertDisposition.TruePositive),
                    FalsePositives: Of(AlertDisposition.FalsePositive),
                    Benign: Of(AlertDisposition.Benign),
                    Duplicates: Of(AlertDisposition.Duplicate),
                    LastAlertAt: mine.Count == 0 ? null : mine.Max(c => c.Last));
            });

            // Worst first: this page exists to be acted on, and the rules doing harm are the point of it.
            return Results.Ok(quality
                .OrderByDescending(q => q.Verdict == RuleVerdict.Harmful)
                .ThenByDescending(q => q.Verdict == RuleVerdict.Tune)
                .ThenByDescending(q => q.FalsePositiveRate)
                .ThenBy(q => q.RuleName)
                .Select(q => new
                {
                    q.RuleId, q.RuleName, q.Enabled, q.Alerts, q.Judged,
                    q.TruePositives, q.FalsePositives, q.Benign, q.Duplicates,
                    q.FalsePositiveRate, q.Verdict, q.Advice, q.LastAlertAt
                }));
        }).Requires(Permission.RulesRead);

        app.MapGet("/api/action-executions", async (
            SentinelDbContext db, CancellationToken ct,
            string? status = null, long? alertId = null, int take = 50) =>
            Results.Ok(await db.ActionExecutions.AsNoTracking()
                .Where(e => (status == null || e.Status == status) && (alertId == null || e.AlertId == alertId))
                .OrderByDescending(e => e.CreatedAt)
                .Take(Math.Clamp(take, 1, 200))
                .ToListAsync(ct)))
            .Requires(Permission.ActionsRead);

        // A stored JSON object read back as the flat string map an action context wants. Unreadable or
        // absent reads as empty: a template naming a field that is not there renders a blank, which is
        // what it does for any missing field.
        static IReadOnlyDictionary<string, string> StoredStrings(string? json)
        {
            var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(json))
                return empty;

            try
            {
                return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                       ?? empty;
            }
            catch (System.Text.Json.JsonException)
            {
                return empty;
            }
        }

        // Carrying out an action the rule deliberately held.
        //
        // The context is rebuilt from the alert and the rule version that produced it rather than stored
        // when it parked. The alert keeps its subject, evidence and sample, and a rule version is
        // immutable — so this renders exactly what would have been sent an hour ago, even if the rule has
        // been edited twice since.
        app.MapPost("/api/action-executions/{id:long}/approve", async (
            long id,
            SentinelDbContext db,
            IActionRegistry registry,
            IConnectionLookup connections,
            ActionDispatcher dispatcher,
            IAuditTrail audit,
            CurrentUser current,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            var execution = await db.ActionExecutions.FirstOrDefaultAsync(e => e.Id == id, ct);

            if (execution is null)
                return Results.NotFound();

            var now = clock.GetUtcNow().UtcDateTime;

            if (execution.Status != ActionExecutionStatus.PendingApproval)
                return Results.BadRequest(new
                {
                    error = $"That action is {execution.Status}, not waiting for approval."
                });

            // Checked here as well as by the sweep, because the sweep runs on the engine's tick and this
            // request may arrive in between. Expiring is the safe direction, so the later of the two wins.
            if (execution.ApprovalExpiresAt is { } expiry && expiry <= now)
            {
                execution.Status = ActionExecutionStatus.Expired;
                execution.ErrorCode = "APPROVAL_EXPIRED";
                execution.ErrorMessage = $"Nobody approved it before {expiry:u}, so it was not carried out.";
                execution.FinishedAt = now;
                await db.SaveChangesAsync(ct);

                return Results.BadRequest(new { error = execution.ErrorMessage });
            }

            var alert = await db.Alerts.AsNoTracking().FirstOrDefaultAsync(a => a.Id == execution.AlertId, ct);

            var version = await db.RuleVersions.AsNoTracking().FirstOrDefaultAsync(
                v => v.RuleId == execution.RuleId && v.Version == execution.RuleVersion, ct);

            if (alert is null || version is null)
                return Results.BadRequest(new
                {
                    error = "The alert or the rule version this action belongs to is no longer stored."
                });

            var rule = RuleDefinitionMapper.From(version, execution.RuleId);

            var binding = rule.Actions.FirstOrDefault(a =>
                a.Type == execution.ActionType && a.Connection == execution.ConnectionName);

            if (binding is null)
                return Results.BadRequest(new
                {
                    error = "That version of the rule no longer carries this action."
                });

            if (!registry.TryResolve(binding.Type, out var provider))
                return Results.BadRequest(new { error = $"No provider is registered for '{binding.Type}'." });

            var connection = await connections.ByNameAsync(binding.Connection, ct);

            if (connection is null || !connection.Enabled)
                return Results.BadRequest(new
                {
                    error = $"Connection '{binding.Connection}' is missing or disabled."
                });

            // What the actions before it did, so a message approved now still reads correctly.
            var siblings = await db.ActionExecutions.AsNoTracking()
                .Where(e => e.AlertId == execution.AlertId && e.Id != execution.Id)
                .ToListAsync(ct);

            var outcomes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var sibling in siblings)
            {
                outcomes[$"{sibling.ActionType}.status"] = sibling.Status;
                outcomes[$"{sibling.ActionType}.reason"] = sibling.ErrorMessage ?? "";
                outcomes[$"{sibling.ActionType}.target"] = sibling.Target ?? "";
            }

            var actor = await current.ActorAsync(ct);

            execution.DecidedBy = actor.Name;
            execution.DecidedAt = now;

            var context = ActionContext.From(
                alert,
                StoredStrings(alert.SubjectJson),
                StoredStrings(alert.EvidenceJson),
                binding.Settings,
                StoredStrings(alert.SampleJson),
                outcomes);

            var result = await dispatcher.ExecuteApprovedAsync(execution, provider, context, connection, ct);

            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, "ACTION_APPROVED", "action_execution", id.ToString(),
                result: result.Status,
                detail: $"{execution.ActionType} on {execution.Target} through {execution.ConnectionName}.",
                ct: ct);

            return Results.Ok(new { result.Id, result.Status, result.ErrorMessage });
        }).Requires(Permission.EngineOperate);

        // Declining one.
        app.MapPost("/api/action-executions/{id:long}/reject", async (
            long id,
            RejectActionRequest request,
            SentinelDbContext db,
            IAuditTrail audit,
            CurrentUser current,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            var execution = await db.ActionExecutions.FirstOrDefaultAsync(e => e.Id == id, ct);

            if (execution is null)
                return Results.NotFound();

            if (execution.Status != ActionExecutionStatus.PendingApproval)
                return Results.BadRequest(new
                {
                    error = $"That action is {execution.Status}, not waiting for approval."
                });

            var actor = await current.ActorAsync(ct);
            var now = clock.GetUtcNow().UtcDateTime;

            execution.Status = ActionExecutionStatus.Rejected;
            execution.DecidedBy = actor.Name;
            execution.DecidedAt = now;
            execution.DecisionNote = request?.Reason;
            execution.FinishedAt = now;
            execution.ErrorCode = "REJECTED";
            execution.ErrorMessage = string.IsNullOrWhiteSpace(request?.Reason)
                ? $"Declined by {actor.Name}."
                : $"Declined by {actor.Name}: {request!.Reason}";

            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, "ACTION_REJECTED", "action_execution", id.ToString(),
                detail: execution.ErrorMessage, ct: ct);

            return Results.Ok(new { execution.Id, execution.Status });
        }).Requires(Permission.EngineOperate);

        // Undoing one thing the platform did.
        //
        // engine.operate rather than actions.read: lifting a block changes a live system, which is the
        // same kind of decision as arming a rule and a different one from reading what happened. It is
        // deliberately not alerts.resolve — closing an alert is paperwork, this is not.
        app.MapPost("/api/action-executions/{id:long}/reverse", async (
            long id,
            SentinelDbContext db,
            IActionRegistry registry,
            IConnectionLookup connections,
            IAuditTrail audit,
            CurrentUser current,
            TimeProvider clock,
            CancellationToken ct) =>
        {
            var execution = await db.ActionExecutions.FirstOrDefaultAsync(e => e.Id == id, ct);

            if (execution is null)
                return Results.NotFound();

            // Only something that actually happened can be undone. A failed or skipped action left the
            // estate as it was, and "reversing" it would send an unblock for an address nobody blocked.
            if (execution.Status != ActionExecutionStatus.Success)
                return Results.BadRequest(new
                {
                    error = $"That action ended as {execution.Status}, so it changed nothing to undo."
                });

            if (execution.ReversedAt is not null)
                return Results.BadRequest(new
                {
                    error = $"Already reversed at {execution.ReversedAt:u} by {execution.ReversedBy}."
                });

            if (!registry.TryResolve(execution.ActionType, out var provider) ||
                provider is not IReversibleAction reversible)
                return Results.BadRequest(new
                {
                    error = $"'{execution.ActionType}' cannot be undone. A message cannot be unsent."
                });

            var connection = await connections.ByNameAsync(execution.ConnectionName, ct);

            if (connection is null || !connection.Enabled)
                return Results.BadRequest(new
                {
                    error = $"Connection '{execution.ConnectionName}' is missing or disabled, so the " +
                            "reversal cannot be delivered."
                });

            var actor = await current.ActorAsync(ct);

            // Its own key, derived from the original. Two people pressing the button at once send one
            // unblock, and a gateway that collapses repeats sees this as distinct from the block it undoes.
            var outcome = await reversible.ReverseAsync(
                execution.Target, connection, $"{execution.IdempotencyKey}:reverse", ct);

            var now = clock.GetUtcNow().UtcDateTime;

            if (!outcome.Succeeded)
            {
                // Recorded on the row rather than only returned, because a reversal that failed is
                // something somebody has to come back to — and the next person to look at this execution
                // needs to know it was attempted.
                execution.ReversalError = outcome.ErrorMessage ?? outcome.ErrorCode;
                await db.SaveChangesAsync(ct);

                await audit.RecordAsync(actor, "ACTION_REVERSE_FAILED", "action_execution", id.ToString(),
                    result: "FAILED", detail: execution.ReversalError, ct: ct);

                return Results.BadRequest(new { error = execution.ReversalError });
            }

            execution.ReversedAt = now;
            execution.ReversedBy = actor.Name;
            execution.ReversalError = null;
            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(actor, "ACTION_REVERSED", "action_execution", id.ToString(),
                detail: $"{execution.ActionType} on {execution.Target} through {execution.ConnectionName}.",
                ct: ct);

            return Results.Ok(new { execution.Id, execution.ReversedAt, execution.ReversedBy });
        }).Requires(Permission.EngineOperate);

        app.MapGet("/api/audit", async (
            SentinelDbContext db, CancellationToken ct,
            string? resourceType = null, string? actor = null, int take = 100) =>
            Results.Ok(await db.AuditEntries.AsNoTracking()
                .Where(a => (resourceType == null || a.ResourceType == resourceType)
                            && (actor == null || a.Actor == actor))
                .OrderByDescending(a => a.OccurredAt)
                .Take(Math.Clamp(take, 1, 500))
                .ToListAsync(ct)))
            .Requires(Permission.AuditRead);

        // The numbers a dashboard opens with, in one query rather than six round trips from the browser.
        app.MapGet("/api/summary", async (SentinelDbContext db, CancellationToken ct) =>
        {
            var since = DateTime.UtcNow.AddDays(-1);

            // Read from what the engines reported, not from this host's configuration. The API evaluates
            // nothing and blocks nothing, so its own EngineSettings and ActionSafetySettings describe a
            // process that is not doing the work — a stopped engine looked healthy, and a never-act list
            // configured here and not there showed as protection nobody was enforcing.
            var nodes = await db.EngineNodes.AsNoTracking().OrderBy(n => n.NodeId).ToListAsync(ct);

            // Silent for several of its own ticks. Generous enough that one slow pass is not an alarm,
            // short enough that a dead engine is noticed long before the next working day.
            var stale = nodes.Count == 0 || nodes.TrueForAll(n =>
                DateTime.UtcNow - n.LastSeenAt > TimeSpan.FromSeconds(Math.Max(60, n.TickSeconds * 6)));

            return Results.Ok(new
            {
                engine = new
                {
                    // Null when nothing has ever reported, which the console shows as "no engine has
                    // checked in" rather than as a healthy platform with nothing to do.
                    reporting = nodes.Count > 0 && !stale,
                    nodes = nodes.Select(n => new
                    {
                        n.NodeId, n.Enabled, n.TickSeconds, n.MaxConcurrentRules, n.Version,
                        n.LastSeenAt, n.StartedAt,
                        n.LastTickRulesEvaluated, n.LastTickAlertsRaised, n.LastTickDurationMs,
                        stale = DateTime.UtcNow - n.LastSeenAt > TimeSpan.FromSeconds(Math.Max(60, n.TickSeconds * 6))
                    })
                },
                safety = new
                {
                    // What the engines are enforcing. Disagreement between nodes is itself worth seeing,
                    // so this reports the weakest: an operator should be told that something can act.
                    actionsEnabled = nodes.Count > 0 && nodes.Exists(n => n.ActionsEnabled),
                    neverBlock = nodes.Count == 0 ? 0 : nodes.Min(n => n.NeverActEntries),
                    nodesDisagree = nodes.Count > 1 &&
                                    (nodes.Select(n => n.ActionsEnabled).Distinct().Count() > 1 ||
                                     nodes.Select(n => n.NeverActEntries).Distinct().Count() > 1)
                },
                rules = new
                {
                    total = await db.Rules.CountAsync(ct),
                    enabled = await db.Rules.CountAsync(r => r.Enabled, ct),
                    failing = await db.Checkpoints.CountAsync(c => c.ConsecutiveFailures > 0, ct)
                },
                alerts = new
                {
                    open = await db.Alerts.CountAsync(a => a.Status == AlertStatus.Detected, ct),
                    critical = await db.Alerts.CountAsync(
                        a => a.Status == AlertStatus.Detected && a.Severity == Domain.Rules.Severity.Critical, ct),
                    lastDay = await db.Alerts.CountAsync(a => a.DetectedAt >= since, ct)
                },
                actions = new
                {
                    succeeded = await db.ActionExecutions.CountAsync(
                        e => e.Status == ActionExecutionStatus.Success && e.CreatedAt >= since, ct),
                    failed = await db.ActionExecutions.CountAsync(
                        e => (e.Status == ActionExecutionStatus.Failed || e.Status == ActionExecutionStatus.DeadLetter)
                             && e.CreatedAt >= since, ct),
                    skipped = await db.ActionExecutions.CountAsync(
                        e => e.Status == ActionExecutionStatus.Skipped && e.CreatedAt >= since, ct)
                },
                connections = await db.Connections.CountAsync(ct)
            });
        }).Requires(Permission.RulesRead);

        app.MapGet("/api/engine", async (SentinelDbContext db, CancellationToken ct) =>
            Results.Ok(new
            {
                // The engines that have reported, rather than this host's idea of one.
                nodes = await db.EngineNodes.AsNoTracking().OrderBy(n => n.NodeId).ToListAsync(ct),
                checkpoints = await db.Checkpoints.AsNoTracking().OrderBy(c => c.RuleId).ToListAsync(ct)
            })).Requires(Permission.RulesRead);

        // Metadata, for a UI that builds its own forms.
        app.MapGet("/api/action-types", (IActionRegistry actions) => Results.Ok(actions.Describe()))
            .RequiresSignIn();

        app.MapGet("/api/detection-strategies", (IDetectionStrategyRegistry strategies) =>
            Results.Ok(strategies.Registered.Order())).RequiresSignIn();

        // What an alert from each strategy carries, so the rule builder can offer an author the
        // placeholders their own rule will produce — rather than a list somebody typed into the frontend
        // and stopped maintaining the day a strategy added a field.
        app.MapGet("/api/placeholders", (
            IDetectionStrategyRegistry strategies,
            Application.Enrichment.EnrichmentPipeline enrichment) => Results.Ok(new
        {
            always = RuleVocabulary.Always,
            message = Sentinel.Infrastructure.Actions.SmsActionProvider.MessagePath,

            // What the registered enrichments will attach to an alert, so the rule builder can offer
            // {{enrich.asset.owner}} as a chip rather than leaving an author to discover it from an alert
            // that has already fired.
            enrich = enrichment.Describe().Select(e => new
            {
                e.Name, e.DisplayName, e.Description,
                paths = e.Facts.Select(f => $"enrich.{e.Name}.{f}")
            }),
            evidence = strategies.Registered.Order().ToDictionary(
                type => type,
                type => strategies.Resolve(type).EvidenceKeys)
        })).RequiresSignIn();

        // Served rather than written into the console's JavaScript, for the reason the placeholder
        // catalogue above is: a template carries a strategy name, builder operators and a compiled query,
        // and all three are things the backend defines. A second copy in the frontend is one that goes
        // stale the first time any of them changes.
        app.MapGet("/api/rule-templates", () => Results.Ok(
            Application.Rules.RuleTemplates.All.Select(t => new
            {
                t.Id, t.Name, t.Summary, t.Purpose, t.Severity, t.StrategyType,
                t.Conditions, t.GroupBy, t.Threshold,
                t.WindowSeconds, t.IntervalSeconds, t.QueryDelaySeconds, t.CooldownSeconds,
                t.Fields, t.Message, t.QueryJson
            }))).RequiresSignIn();

        app.MapGet("/api/permissions", () => Results.Ok(new
        {
            permissions = Permission.All.Order(),
            roles = SystemRole.Definitions.Select(role => new
            {
                name = role.Key,
                description = role.Value.Description,
                permissions = role.Value.Permissions.Order()
            })
        })).RequiresSignIn();
    }
}
