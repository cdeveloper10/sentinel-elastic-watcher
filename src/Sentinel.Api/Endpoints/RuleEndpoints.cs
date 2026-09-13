using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Auth;
using Sentinel.Application.Actions;
using Sentinel.Application.Audit;
using Sentinel.Application.Detection;
using Sentinel.Application.Engine;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Application.Security;
using Sentinel.Domain.Platform;
using Sentinel.Domain.Rules;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Api.Endpoints;

public static class RuleEndpoints
{
    /// <summary>
    /// How a rule version's stored JSON is written. camelCase because the console reads these columns
    /// directly, and everything else it reads from this API is camelCase.
    /// </summary>
    private static readonly JsonSerializerOptions StoredJson =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static void MapRules(this WebApplication app)
    {
        var group = app.MapGroup("/api/rules").WithTags("Rules");

        group.MapGet("", List).Requires(Permission.RulesRead);
        group.MapGet("/{id:int}", Get).Requires(Permission.RulesRead);
        group.MapPost("", Create).Requires(Permission.RulesCreate);
        group.MapPut("/{id:int}", Update).Requires(Permission.RulesUpdate);
        group.MapDelete("/{id:int}", Delete).Requires(Permission.RulesDelete);

        // Arming is its own permission. A saved rule does nothing; an enabled rule starts blocking
        // addresses on a schedule, and those are different decisions.
        group.MapPost("/{id:int}/enable", (int id, HttpContext http) => SetEnabled(id, true, http))
            .Requires(Permission.RulesEnable);

        group.MapPost("/{id:int}/disable", (int id, HttpContext http) => SetEnabled(id, false, http))
            .Requires(Permission.RulesEnable);

        // Reads events, executes nothing — see DryRunService, which has no path to a dispatcher.
        group.MapPost("/{id:int}/dry-run", DryRun).Requires(Permission.RulesTest);

        // Building a condition, before there is a rule to test. Both are rules.test: they read events and
        // change nothing, which is the same authority a rehearsal needs.
        group.MapPost("/condition", CompileCondition).Requires(Permission.RulesTest);
        group.MapPost("/preview", Preview).Requires(Permission.RulesTest);

        // Evaluates for real, including actions. Operational rather than editorial.
        group.MapPost("/{id:int}/run", RunNow).Requires(Permission.EngineOperate);

        group.MapPost("/{id:int}/checkpoint", ResetCheckpoint).Requires(Permission.EngineOperate);
    }

    private static async Task<IResult> List(SentinelDbContext db, CancellationToken ct)
    {
        var rules = await db.Rules.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);
        var ids = rules.Select(r => r.Id).ToList();

        // The checkpoint is what answers "is this rule actually working", so the list carries it rather
        // than making somebody open each rule to find out.
        var checkpoints = await db.Checkpoints.AsNoTracking()
            .Where(c => ids.Contains(c.RuleId))
            .ToDictionaryAsync(c => c.RuleId, ct);

        return Results.Ok(rules.Select(r => new
        {
            r.Id, r.Name, r.Description, r.Enabled, r.Severity, r.ConnectionId,
            r.CurrentVersion, r.UpdatedAt, r.UpdatedBy,
            LastRunAt = Look(checkpoints, r.Id)?.LastRunAt,
            LastRunAlerts = Look(checkpoints, r.Id)?.LastRunAlerts,
            ConsecutiveFailures = Look(checkpoints, r.Id)?.ConsecutiveFailures ?? 0,
            LastError = Look(checkpoints, r.Id)?.LastError
        }));

        static RuleCheckpoint? Look(Dictionary<int, RuleCheckpoint> all, int id) =>
            all.TryGetValue(id, out var found) ? found : null;
    }

    private static async Task<IResult> Get(int id, SentinelDbContext db, CancellationToken ct)
    {
        var rule = await db.Rules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null)
            return Results.NotFound();

        var versions = await db.RuleVersions.AsNoTracking()
            .Where(v => v.RuleId == id)
            .OrderByDescending(v => v.Version)
            .ToListAsync(ct);

        var checkpoint = await db.Checkpoints.AsNoTracking().FirstOrDefaultAsync(c => c.RuleId == id, ct);
        var current = versions.FirstOrDefault(v => v.Version == rule.CurrentVersion);

        return Results.Ok(new
        {
            rule,
            current,
            checkpoint,
            versions = versions.Select(v => new { v.Version, v.CreatedAt, v.CreatedBy, v.ChangeNote })
        });
    }

    private static async Task<IResult> Create(
        RuleRequest request,
        SentinelDbContext db,
        RuleValidator validator,
        IActionRegistry actions,
        IDetectionStrategyRegistry strategies,
        IAuditTrail audit,
        CurrentUser current,
        TimeProvider clock,
        CancellationToken ct)
    {
        var draft = ToDefinition(0, 1, request);
        var validation = await ValidateAsync(validator, db, draft, request.ConnectionId, actions, strategies, ct);

        if (!validation.IsValid)
            return ConnectionEndpoints.Problems(validation);

        if (await db.Rules.AnyAsync(r => r.Name == request.Name, ct))
            return Results.Conflict(new { error = $"A rule named '{request.Name}' already exists." });

        var actor = await current.ActorAsync(ct);
        var now = clock.GetUtcNow().UtcDateTime;

        var rule = new DetectionRule
        {
            Name = request.Name.Trim(),
            Description = request.Description?.Trim() ?? "",
            // Created disarmed, always. A rule that started evaluating the moment it was saved would act
            // on a first draft, and arming is a separate permission for the same reason.
            Enabled = false,
            Severity = request.Severity,
            ConnectionId = request.ConnectionId,
            CurrentVersion = 1,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = actor.Name,
            UpdatedBy = actor.Name
        };

        // One transaction. The version needs the rule's generated id, so this is necessarily two writes —
        // and committing the first alone leaves a rule pointing at a version that does not exist. That rule
        // can never be evaluated, never be dry-run, and reports only "its version or connection is missing",
        // which is a state nobody can repair from the console.
        //
        // Through the execution strategy because retries are enabled: EF refuses a user-managed
        // transaction otherwise, since it cannot know whether a retried block already committed.
        await db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);

            db.Rules.Add(rule);
            await db.SaveChangesAsync(ct);

            db.RuleVersions.Add(ToVersion(rule.Id, 1, request, actor.Name, now));
            await db.SaveChangesAsync(ct);

            await transaction.CommitAsync(ct);
        });

        await audit.RecordAsync(actor, AuditOperation.RuleCreated, "rule", rule.Id.ToString(),
            changes: new { rule.Name, rule.Severity, request.StrategyType, request.Threshold }, ct: ct);

        return Results.Created($"/api/rules/{rule.Id}", new { rule.Id, rule.Name, rule.Enabled });
    }

    private static async Task<IResult> Update(
        int id,
        RuleRequest request,
        SentinelDbContext db,
        RuleValidator validator,
        IActionRegistry actions,
        IDetectionStrategyRegistry strategies,
        IAuditTrail audit,
        CurrentUser current,
        TimeProvider clock,
        CancellationToken ct)
    {
        var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null)
            return Results.NotFound();

        var nextVersion = rule.CurrentVersion + 1;
        var draft = ToDefinition(id, nextVersion, request);
        var validation = await ValidateAsync(validator, db, draft, request.ConnectionId, actions, strategies, ct);

        if (!validation.IsValid)
            return ConnectionEndpoints.Problems(validation);

        if (await db.Rules.AnyAsync(r => r.Name == request.Name && r.Id != id, ct))
            return Results.Conflict(new { error = $"A rule named '{request.Name}' already exists." });

        var actor = await current.ActorAsync(ct);
        var now = clock.GetUtcNow().UtcDateTime;

        // A new version rather than an edit in place. Alerts name the version that produced them, so
        // rewriting one would silently change the history of every alert that cites it — which is exactly
        // what somebody investigating an incident is relying on.
        db.RuleVersions.Add(ToVersion(id, nextVersion, request, actor.Name, now));

        rule.Name = request.Name.Trim();
        rule.Description = request.Description?.Trim() ?? "";
        rule.Severity = request.Severity;
        rule.ConnectionId = request.ConnectionId;
        rule.CurrentVersion = nextVersion;
        rule.UpdatedAt = now;
        rule.UpdatedBy = actor.Name;

        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(actor, AuditOperation.RuleUpdated, "rule", id.ToString(),
            changes: new { version = nextVersion, request.ChangeNote }, ct: ct);

        return Results.Ok(new { rule.Id, version = nextVersion });
    }

    private static async Task<IResult> Delete(
        int id, SentinelDbContext db, IAuditTrail audit, CurrentUser current, CancellationToken ct)
    {
        var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null)
            return Results.NotFound();

        var alerts = await db.Alerts.CountAsync(a => a.RuleId == id, ct);

        // A rule with alerts against it is disabled, not deleted. The alerts cite a version, and deleting
        // the version leaves an investigator with an alert whose reason cannot be reconstructed.
        if (alerts > 0)
        {
            rule.Enabled = false;
            rule.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);

            await audit.RecordAsync(await current.ActorAsync(ct),
                AuditOperation.RuleDisabled, "rule", id.ToString(),
                detail: $"Deletion refused: {alerts} alert(s) cite this rule. Disabled instead.", ct: ct);

            return Results.Conflict(new
            {
                error = $"{alerts} alert(s) cite this rule, so its history has to stay. It has been disabled instead.",
                disabled = true
            });
        }

        db.RuleVersions.RemoveRange(db.RuleVersions.Where(v => v.RuleId == id));
        db.Checkpoints.RemoveRange(db.Checkpoints.Where(c => c.RuleId == id));
        db.RuleLeases.RemoveRange(db.RuleLeases.Where(l => l.RuleId == id));
        db.Rules.Remove(rule);
        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            AuditOperation.RuleDeleted, "rule", id.ToString(), changes: new { rule.Name }, ct: ct);

        return Results.NoContent();
    }

    private static async Task<IResult> SetEnabled(int id, bool enabled, HttpContext http)
    {
        var services = http.RequestServices;
        var db = services.GetRequiredService<SentinelDbContext>();
        var audit = services.GetRequiredService<IAuditTrail>();
        var current = services.GetRequiredService<CurrentUser>();
        var ct = http.RequestAborted;

        var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == id, ct);
        if (rule is null)
            return Results.NotFound();

        rule.Enabled = enabled;
        rule.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            enabled ? AuditOperation.RuleEnabled : AuditOperation.RuleDisabled,
            "rule", id.ToString(), changes: new { rule.Name, enabled }, ct: ct);

        return Results.Ok(new { rule.Id, rule.Enabled });
    }

    /// <summary>
    /// A rehearsal. <see cref="DryRunService"/> takes one dependency — a strategy registry — so there is
    /// no path from here to anything that blocks an address.
    /// </summary>
    private static async Task<IResult> DryRun(
        int id,
        DryRunRequest request,
        IRuleRuntimeSource rules,
        DryRunService dryRun,
        IEventSource source,
        IAuditTrail audit,
        CurrentUser current,
        TimeProvider clock,
        CancellationToken ct)
    {
        var loaded = await rules.ActiveRuleAsync(id, ct);
        if (loaded is null)
            return Results.NotFound(new { error = "No such rule, or its version or connection is missing." });

        var (rule, connection) = loaded.Value;
        var minutes = Math.Clamp(request.LookbackMinutes, 1, 60 * 24 * 7);
        var now = clock.GetUtcNow();
        var range = new TimeRange(now.AddMinutes(-minutes), now);

        var result = await dryRun.RunAsync(rule, connection, source, range, ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            AuditOperation.RuleTested, "rule", id.ToString(),
            detail: $"Dry run over {minutes} minute(s): {result.WouldDetect.Count} detection(s).", ct: ct);

        return Results.Ok(result);
    }

    /// <summary>
    /// Builder rows to a query clause, or a hand-written clause back to rows.
    ///
    /// The compiler lives on the server and there is exactly one of it. The console could compile rows
    /// itself and save a round trip, and then there would be two implementations of what a rule means —
    /// which stays true right up until they differ, at which point the query an author previewed and the
    /// query the engine runs are not the same query and nothing says so.
    /// </summary>
    private static IResult CompileCondition(ConditionRequest request)
    {
        if (request.Conditions is { Count: > 0 } rows)
        {
            var validation = ConditionQuery.Validate(rows);

            if (!validation.IsValid)
                return ConnectionEndpoints.Problems(validation);

            return Results.Ok(new
            {
                queryJson = ConditionQuery.ToQueryJson(rows),
                conditions = rows,
                representable = true
            });
        }

        var raw = request.QueryJson ?? "";

        if (QueryProblem(raw) is { } problem)
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["query"] = [problem] });

        // Whether the builder can show it. False is a normal answer, not a failure: a query using bool
        // should, or a script, is a real query that these rows cannot express, and the console keeps it in
        // the raw editor rather than approximating it.
        var representable = ConditionQuery.TryRead(raw, out var read);

        return Results.Ok(new { queryJson = raw, conditions = read, representable });
    }

    /// <summary>
    /// What a condition matches right now, before there is a rule.
    ///
    /// Not audited, and that is a decision rather than an omission: this runs while somebody is typing, so
    /// recording it would bury the entries that matter — who armed a rule, who changed a connection —
    /// under thousands of keystrokes. It reads events and changes nothing.
    /// </summary>
    private static async Task<IResult> Preview(
        ConditionPreviewRequest request,
        SentinelDbContext db,
        IEventSource source,
        ConditionPreviewService preview,
        TimeProvider clock,
        CancellationToken ct)
    {
        var connection = await db.Connections.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == request.ConnectionId, ct);

        if (connection is null)
            return Results.NotFound(new { error = "That connection does not exist." });

        if (connection.Type != Domain.Connections.ConnectionType.Elasticsearch)
            return Results.BadRequest(new
            {
                error = $"'{connection.Name}' is a {connection.Type} connection, which is not an event source."
            });

        var patterns = (request.IndexPatterns ?? [])
            .Select(p => p.Trim())
            .Where(p => p.Length > 0)
            .ToList();

        // The same check the save path makes, so a preview cannot succeed against a pattern the rule
        // would then be refused for.
        var patternsAreValid = IndexPatternRules.Validate(patterns);

        if (!patternsAreValid.IsValid)
            return ConnectionEndpoints.Problems(patternsAreValid);

        string queryJson;

        if (request.Conditions is { Count: > 0 } rows)
        {
            var validation = ConditionQuery.Validate(rows);

            if (!validation.IsValid)
                return ConnectionEndpoints.Problems(validation);

            queryJson = ConditionQuery.ToQueryJson(rows);
        }
        else
        {
            queryJson = request.QueryJson ?? "";
        }

        if (QueryProblem(queryJson) is { } problem)
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["query"] = [problem] });

        // A week is as far back as a dry run goes, and for the same reason: past that the answer stops
        // being about the condition and starts being about how much history the cluster kept.
        var minutes = Math.Clamp(request.LookbackMinutes, 1, 60 * 24 * 7);
        var now = clock.GetUtcNow();

        var result = await preview.RunAsync(
            connection,
            source,
            patterns,
            queryJson,
            string.IsNullOrWhiteSpace(request.TimestampField) ? "@timestamp" : request.TimestampField.Trim(),
            (request.GroupBy ?? []).Select(g => g.Trim()).Where(g => g.Length > 0).Distinct().ToList(),
            request.Threshold,
            new TimeRange(now.AddMinutes(-minutes), now),
            ct);

        return Results.Ok(new
        {
            result.Succeeded,
            result.Message,
            result.TotalMatched,
            result.TotalIsLowerBound,
            result.Samples,
            result.Groups,
            result.GroupsTruncated,
            result.WouldTrigger,
            result.ElapsedMs,

            // What was actually run. The console stores this as the rule's query, so what was previewed
            // and what gets saved are the same string rather than two compilations of the same intent.
            queryJson,
            lookbackMinutes = minutes
        });
    }

    /// <summary>
    /// What is wrong with a query clause, in the source's own words.
    ///
    /// The validator has taken a delegate for this since it was written and nothing ever passed one, so a
    /// malformed query saved cleanly and failed on the first evaluation — at whatever hour that was. The
    /// check and its message already existed; only the wiring was missing.
    /// </summary>
    private static string? QueryProblem(string? queryJson) =>
        Infrastructure.Elasticsearch.ElasticsearchQueryBuilder.IsValidQuery(queryJson, out var error)
            ? null
            : error;

    /// <summary>
    /// Evaluates now, for real. Distinct from a dry run in exactly one way that matters: this dispatches.
    /// </summary>
    private static async Task<IResult> RunNow(
        int id,
        IRuleRuntimeSource rules,
        RuleEvaluator evaluator,
        IAuditTrail audit,
        CurrentUser current,
        CancellationToken ct)
    {
        var loaded = await rules.ActiveRuleAsync(id, ct);
        if (loaded is null)
            return Results.NotFound();

        var (rule, connection) = loaded.Value;
        var outcome = await evaluator.EvaluateAsync(rule, connection, dispatchActions: true, ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            "RULE_RUN_NOW", "rule", id.ToString(),
            result: outcome.Failed ? "FAILED" : "SUCCESS",
            detail: outcome.Failed
                ? outcome.Error
                : $"{outcome.AlertsRaised} alert(s), {outcome.ActionsSucceeded} action(s).",
            ct: ct);

        return Results.Ok(outcome);
    }

    private static async Task<IResult> ResetCheckpoint(
        int id,
        ResetCheckpointRequest request,
        ICheckpointStore checkpoints,
        IAuditTrail audit,
        CurrentUser current,
        CancellationToken ct)
    {
        await checkpoints.ResetAsync(id, request.To, ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            AuditOperation.CheckpointReset, "rule", id.ToString(),
            detail: request.To is null
                ? "Cleared; the rule starts as though it were new."
                : $"Moved to {request.To:O}.",
            ct: ct);

        return Results.NoContent();
    }

    // -- mapping ---------------------------------------------------------------------------------

    private static async Task<Application.Connections.ValidationResult> ValidateAsync(
        RuleValidator validator,
        SentinelDbContext db,
        RuleDefinition draft,
        int connectionId,
        IActionRegistry actions,
        IDetectionStrategyRegistry strategies,
        CancellationToken ct)
    {
        var failures = validator.Validate(draft, QueryProblem).Failures.ToList();

        var source = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == connectionId, ct);

        if (source is null)
            failures.Add(new Application.Connections.ValidationFailure(
                "connectionId", "That connection does not exist."));
        else if (source.Type != Domain.Connections.ConnectionType.Elasticsearch)
            failures.Add(new Application.Connections.ValidationFailure(
                "connectionId", $"'{source.Name}' is a {source.Type} connection, which is not an event source."));

        failures.AddRange(await ValidateActionsAsync(db, draft, actions, strategies, ct));

        return failures.Count == 0
            ? Application.Connections.ValidationResult.Success
            : new Application.Connections.ValidationResult(failures);
    }

    /// <summary>
    /// Checks each action binding against the provider that will run it and the connection it runs through.
    ///
    /// This is where a rule's configuration of its own service is proved. Until it existed the providers'
    /// <c>Validate</c> was never called from anywhere: a rule could carry a message naming a field the rule
    /// does not produce, a payload that is not JSON, or a gateway connection of the wrong kind, and all
    /// three saved cleanly and then failed on the first alert — at whatever hour that was, with nobody
    /// watching. Nothing here knows what an action is; the registry resolves the provider and the provider
    /// decides.
    /// </summary>
    private static async Task<List<Application.Connections.ValidationFailure>> ValidateActionsAsync(
        SentinelDbContext db,
        RuleDefinition draft,
        IActionRegistry actions,
        IDetectionStrategyRegistry strategies,
        CancellationToken ct)
    {
        var failures = new List<Application.Connections.ValidationFailure>();

        if (draft.Actions.Count == 0)
            return failures;

        var named = draft.Actions
            .Select(a => a.Connection)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var targets = await db.Connections.AsNoTracking()
            .Where(c => named.Contains(c.Name))
            .ToDictionaryAsync(c => c.Name, StringComparer.OrdinalIgnoreCase, ct);

        for (var i = 0; i < draft.Actions.Count; i++)
        {
            var binding = draft.Actions[i];

            if (!actions.TryResolve(binding.Type, out var provider))
            {
                failures.Add(new Application.Connections.ValidationFailure(
                    $"actions[{i}].type",
                    $"No action named '{binding.Type}' exists. Available: " +
                    $"{string.Join(", ", actions.Describe().Select(d => d.Type))}."));

                continue;
            }

            var descriptor = provider.Describe();

            if (!targets.TryGetValue(binding.Connection, out var target))
            {
                failures.Add(new Application.Connections.ValidationFailure(
                    $"actions[{i}].connection", $"There is no connection named '{binding.Connection}'."));
            }
            else if (target.Type != descriptor.RequiredConnectionType)
            {
                failures.Add(new Application.Connections.ValidationFailure(
                    $"actions[{i}].connection",
                    $"'{target.Name}' is a {target.Type} connection; " +
                    $"{descriptor.DisplayName} needs a {descriptor.RequiredConnectionType} one."));
            }
            else if (!target.Enabled)
            {
                // Not a failure of shape but of intent: a rule whose action runs through a disabled
                // connection raises alerts and responds to none of them, which reads as the gateway
                // being broken rather than as a decision somebody made.
                failures.Add(new Application.Connections.ValidationFailure(
                    $"actions[{i}].connection",
                    $"'{target.Name}' is disabled, so this action would never run."));
            }

            // Per action, not per rule: an action may name what the actions before it did, and must not be
            // allowed to name what the ones after it will do.
            var vocabulary = RuleVocabulary.ForAction(draft, strategies, i);

            failures.AddRange(provider.Validate(binding.Settings, vocabulary).Failures
                .Select(f => new Application.Connections.ValidationFailure($"actions[{i}].{f.Field}", f.Message)));
        }

        return failures;
    }

    private static RuleDefinition ToDefinition(int ruleId, int version, RuleRequest request) => new(
        ruleId,
        version,
        request.Name ?? "",
        request.Description ?? "",
        request.Severity ?? Severity.Medium,
        request.ConnectionId,
        request.IndexPatterns ?? [],
        request.QueryJson ?? "",
        string.IsNullOrWhiteSpace(request.TimestampField) ? "@timestamp" : request.TimestampField,
        request.StrategyType ?? "",
        request.GroupBy ?? [],
        request.Threshold,
        TimeSpan.FromSeconds(request.WindowSeconds),
        TimeSpan.FromSeconds(request.QueryDelaySeconds),
        TimeSpan.FromSeconds(request.IntervalSeconds),
        TimeSpan.FromSeconds(request.CooldownSeconds),
        (request.Actions ?? []).Select(a => new RuleActionBinding(
            a.Type, a.Connection, a.Settings ?? new Dictionary<string, string>())).ToList());

    private static RuleVersion ToVersion(
        int ruleId, int version, RuleRequest request, string author, DateTime now) => new()
    {
        RuleId = ruleId,
        Version = version,
        Name = request.Name.Trim(),
        Description = request.Description?.Trim() ?? "",
        Severity = request.Severity,
        IndexPatternsJson = JsonSerializer.Serialize(request.IndexPatterns ?? []),
        QueryJson = request.QueryJson ?? "",
        TimestampField = string.IsNullOrWhiteSpace(request.TimestampField) ? "@timestamp" : request.TimestampField,
        StrategyType = request.StrategyType,
        GroupByJson = JsonSerializer.Serialize(request.GroupBy ?? []),
        Threshold = request.Threshold,
        WindowSeconds = request.WindowSeconds,
        QueryDelaySeconds = request.QueryDelaySeconds,
        IntervalSeconds = request.IntervalSeconds,
        CooldownSeconds = request.CooldownSeconds,
        // camelCase, matching every other document this API emits. It was PascalCase — which is what
        // JsonSerializer.Serialize does with no options — and that made a rule's actions invisible in the
        // console the moment it was reopened: the editor looks for `type`, found `Type`, could not resolve
        // the provider, rendered not one setting, and offered connections of the wrong kind. The engine
        // never noticed, because it reads this back case-insensitively.
        ActionsJson = JsonSerializer.Serialize(request.Actions ?? [], StoredJson),
        CreatedAt = now,
        CreatedBy = author,

        // Empty rather than null: the column is not nullable, and a first version legitimately has nothing
        // to say about what changed — there was nothing before it.
        ChangeNote = request.ChangeNote?.Trim() ?? ""
    };
}
