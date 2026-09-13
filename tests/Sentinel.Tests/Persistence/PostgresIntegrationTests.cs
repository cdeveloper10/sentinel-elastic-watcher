using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Tests.Persistence;

/// <summary>
/// The same guarantees, against the database a deployment actually runs on.
///
/// <see cref="StoreTests"/> proves the constraints on SQLite, which is fast and needs nothing installed —
/// but SQLite serialises writers by locking the whole database, so it cannot show what happens when two
/// nodes insert the same fingerprint at the same instant. PostgreSQL can, and that is the case the
/// platform's deduplication exists for.
///
/// Skipped unless <c>SENTINEL_CONNECTION</c> names a reachable server, so the suite stays runnable on a
/// machine with no database.
/// </summary>
[Collection("postgres")]
public class PostgresIntegrationTests : IAsyncLifetime
{
    private readonly string? _connection = Environment.GetEnvironmentVariable("SENTINEL_CONNECTION");
    private string _prefix = "";

    private bool Available => !string.IsNullOrWhiteSpace(_connection);

    public async Task InitializeAsync()
    {
        if (!Available)
            return;

        // Every row this class writes carries a unique prefix, so a run leaves nothing behind that a later
        // run could collide with — and so two people running the suite against one server do not fight.
        _prefix = $"it-{Guid.NewGuid():n}"[..12];

        await using var context = NewContext();
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        if (!Available)
            return;

        await using var context = NewContext();

        await context.ActionExecutions.Where(e => e.IdempotencyKey.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.Alerts.Where(a => a.Fingerprint.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.Cooldowns.Where(c => c.Key.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.ActionRateCounters.Where(c => c.Key.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.Connections.Where(c => c.Name.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.AuditEntries.Where(a => a.ResourceId.StartsWith(_prefix)).ExecuteDeleteAsync();
    }

    [SkippableFact]
    public async Task The_migration_produces_the_schema_the_model_expects()
    {
        Skip.IfNot(Available);

        await using var context = NewContext();

        // No pending model changes: the migration and the model agree, which is the thing that silently
        // stops being true after somebody edits an entity and forgets to add a migration.
        Assert.False(context.Database.HasPendingModelChanges(),
            "The model has changed since the last migration. Run 'dotnet ef migrations add'.");

        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    [SkippableFact]
    public async Task Concurrent_nodes_inserting_one_fingerprint_produce_one_alert()
    {
        Skip.IfNot(Available);

        // Real concurrency, which SQLite cannot show: eight connections racing into one unique index.
        var fingerprint = $"{_prefix}-race";

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            await NewAlertStore().TryInsertAsync(Alert(fingerprint)))));

        Assert.Equal(1, results.Count(won => won));

        await using var context = NewContext();
        Assert.Equal(1, await context.Alerts.CountAsync(a => a.Fingerprint == fingerprint));
    }

    [SkippableFact]
    public async Task Concurrent_nodes_claiming_one_action_block_the_address_once()
    {
        Skip.IfNot(Available);

        var alert = Alert($"{_prefix}-claim");
        await NewAlertStore().TryInsertAsync(alert);

        var key = $"{_prefix}-shared-key";

        var claims = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            await NewExecutionStore().TryClaimAsync(Execution(alert.Id, key)))));

        Assert.Equal(1, claims.Count(won => won));
    }

    [SkippableFact]
    public async Task A_write_that_breaks_a_different_constraint_still_surfaces()
    {
        Skip.IfNot(Available);

        // PostgreSQL reports 23505 for both collisions, so the store cannot tell them apart by error code —
        // which is exactly why it re-reads the fingerprint rather than matching on SQLSTATE.
        var first = Alert($"{_prefix}-one");
        first.AlertId = $"{_prefix}-collides";
        Assert.True(await NewAlertStore().TryInsertAsync(first));

        var second = Alert($"{_prefix}-two");
        second.AlertId = $"{_prefix}-collides";

        await Assert.ThrowsAsync<DbUpdateException>(() => NewAlertStore().TryInsertAsync(second));
    }

    [SkippableFact]
    public async Task A_connection_round_trips_with_its_secret_still_encrypted()
    {
        Skip.IfNot(Available);

        await using (var write = NewContext())
        {
            write.Connections.Add(new Connection
            {
                Name = $"{_prefix}-es",
                Type = ConnectionType.Elasticsearch,
                Endpoint = "https://es.internal:9200",
                AuthenticationMode = AuthenticationMode.ApiKey,
                SecretCiphertext = "ZW5jcnlwdGVkLWJsb2I=",
                SecretKeysJson = """["apiKey"]""",
                Enabled = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            });

            await write.SaveChangesAsync();
        }

        await using var read = NewContext();
        var stored = await read.Connections.AsNoTracking().SingleAsync(c => c.Name == $"{_prefix}-es");

        // Ciphertext in, ciphertext out. Nothing in the persistence layer decrypts on the way past.
        Assert.Equal("ZW5jcnlwdGVkLWJsb2I=", stored.SecretCiphertext);
    }

    [SkippableFact]
    public async Task Timestamps_survive_the_round_trip_as_utc_to_microsecond_precision()
    {
        Skip.IfNot(Available);

        // Npgsql maps DateTime to timestamptz and is strict about Kind. A local-time value written here
        // would come back shifted, and every window the engine planned would be wrong by the offset — so
        // Kind is the assertion that matters.
        //
        // The value is compared to the microsecond, not exactly: PostgreSQL's timestamptz holds
        // microseconds while .NET ticks are hundreds of nanoseconds, so a round trip truncates. Harmless
        // here — windows are seconds wide — but worth pinning, because any code that compares a stored
        // timestamp to an in-memory one for equality will fail on that last digit and the reason is not
        // obvious from the failure.
        var alert = Alert($"{_prefix}-utc");
        var detected = alert.DetectedAt;

        await NewAlertStore().TryInsertAsync(alert);

        await using var context = NewContext();
        var stored = await context.Alerts.AsNoTracking().SingleAsync(a => a.Fingerprint == alert.Fingerprint);

        Assert.Equal(DateTimeKind.Utc, stored.DetectedAt.Kind);
        Assert.True((stored.DetectedAt - detected).Duration() < TimeSpan.FromMicroseconds(1),
            $"Expected {detected:O} back within a microsecond, got {stored.DetectedAt:O}.");
    }

    // -- helpers -----------------------------------------------------------------------------

    private SentinelDbContext NewContext() =>
        new(new DbContextOptionsBuilder<SentinelDbContext>().UseNpgsql(_connection).Options);

    private EfAlertStore NewAlertStore() => new(NewContext(), NullLogger<EfAlertStore>.Instance);

    private EfActionExecutionStore NewExecutionStore() =>
        new(NewContext(), NullLogger<EfActionExecutionStore>.Instance);

    private Alert Alert(string fingerprint) => new()
    {
        AlertId = $"{_prefix}-{Guid.NewGuid():n}"[..24],
        Fingerprint = fingerprint,
        RuleId = 1,
        RuleVersion = 1,
        RuleName = "Brute Force Detection",
        Severity = "HIGH",
        Status = AlertStatus.Detected,
        Subject = "source.ip=10.10.10.20",
        SubjectJson = """{"source.ip":"10.10.10.20"}""",
        EvidenceJson = """{"eventCount":"31"}""",
        SourceIp = "10.10.10.20",
        EventCount = 31,
        WindowFrom = DateTime.UtcNow.AddMinutes(-5),
        WindowTo = DateTime.UtcNow,
        DetectedAt = DateTime.UtcNow
    };

    private ActionExecution Execution(long alertId, string key) => new()
    {
        AlertId = alertId,
        RuleId = 1,
        RuleVersion = 1,
        ActionType = "block_ip",
        ConnectionName = "security-api",
        IdempotencyKey = key,
        Status = ActionExecutionStatus.Pending,
        Target = "10.10.10.20",
        CreatedAt = DateTime.UtcNow
    };
}

/// <summary>Serialised, because these share one database and clean up by prefix.</summary>
[CollectionDefinition("postgres", DisableParallelization = true)]
public sealed class PostgresCollection;
