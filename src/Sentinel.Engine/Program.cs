using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Engine;
using Sentinel.Infrastructure;
using Sentinel.Infrastructure.Persistence;

// The detection engine.
//
// A separate process from the API on purpose. The API is scaled for how many people are reading; the
// engine is scaled for how large the estate being watched is, and the two have nothing to do with each
// other. Run several API pods against one engine and neither constrains the other.
//
// It is a web host rather than a bare worker only because a container has to be probeable. The listener
// serves two health endpoints and nothing else.

var builder = WebApplication.CreateBuilder(args);

var connection = builder.Configuration.GetConnectionString("Sentinel")
                 ?? throw new InvalidOperationException(
                     "ConnectionStrings:Sentinel is required. Supply it from the environment, " +
                     "for example ConnectionStrings__Sentinel from a Kubernetes secret.");

builder.Services.AddSentinel(builder.Configuration, builder.Environment.IsProduction());
builder.Services.AddSentinelPersistence(connection);
builder.Services.AddSentinelEngine();

var app = builder.Build();

// Migrate and stop, without ever starting the evaluation loop.
//
// This is what the Kubernetes Job runs, from the same image as the engine itself. Applying the schema
// becomes one thing that happens once, at a moment somebody chose, rather than a side effect of whichever
// replica started first — and a migration that fails fails the Job, visibly, instead of leaving pods
// crash-looping with the reason buried in their logs.
if (args.Contains("--migrate"))
{
    using var scope = app.Services.CreateScope();
    var database = scope.ServiceProvider.GetRequiredService<SentinelDbContext>().Database;

    var pending = (await database.GetPendingMigrationsAsync()).ToList();

    if (pending.Count == 0)
    {
        app.Logger.LogInformation("The schema is up to date; nothing to apply");
        return;
    }

    app.Logger.LogInformation(
        "Applying {Count} migration(s): {Migrations}", pending.Count, string.Join(", ", pending));

    await database.MigrateAsync();

    app.Logger.LogInformation("Schema applied");
    return;
}

// The same work as a side effect of starting, for a single-machine deployment that has no Job to run.
// Off in Kubernetes, where several replicas racing to migrate one database is how a half-applied schema
// happens.
if (builder.Configuration.GetValue("Database:MigrateOnStartup", false))
{
    using var scope = app.Services.CreateScope();

    app.Logger.LogInformation("Applying database migrations");
    await scope.ServiceProvider.GetRequiredService<SentinelDbContext>().Database.MigrateAsync();
}

// Is the process up.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }));

// Can it work. The database is the only thing it cannot do without — an unreachable event source makes
// individual rules fail and is deliberately not a readiness failure, because taking the engine out of
// service would also stop the rules reading from a cluster that is perfectly healthy.
app.MapGet("/health/ready", async (SentinelDbContext db, CancellationToken ct) =>
{
    try
    {
        return await db.Database.CanConnectAsync(ct)
            ? Results.Ok(new { status = "ready" })
            : Results.Json(new { status = "unready", reason = "database unreachable" }, statusCode: 503);
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning(ex, "Readiness probe failed");
        return Results.Json(new { status = "unready", reason = "database unreachable" }, statusCode: 503);
    }
});

// What the engine is doing, for an operator who wants to know why a rule is quiet without opening the
// database. Read-only and unauthenticated by design: it names rules and counts, never their content.
app.MapGet("/status", async (SentinelDbContext db, EngineSettings engine, CancellationToken ct) =>
{
    var checkpoints = await db.Checkpoints.AsNoTracking()
        .OrderBy(c => c.RuleId)
        .Select(c => new
        {
            c.RuleId,
            c.EvaluatedTo,
            c.LastRunAt,
            c.LastRunWindows,
            c.LastRunAlerts,
            c.LastRunDurationMs,
            c.ConsecutiveFailures,
            c.LastError,
            c.LastRunSkippedBacklog
        })
        .ToListAsync(ct);

    return Results.Ok(new
    {
        node = engine.NodeId,
        enabled = engine.Enabled,
        tickSeconds = engine.TickSeconds,
        rules = checkpoints
    });
});

await app.RunAsync();
