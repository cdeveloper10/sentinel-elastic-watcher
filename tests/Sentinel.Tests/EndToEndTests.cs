using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Detection;
using Sentinel.Application.Engine;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Application.Security;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Rules;
using Sentinel.Infrastructure.Elasticsearch;
using Sentinel.Infrastructure.Engine;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Infrastructure.Security;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;
using Microsoft.Extensions.Options;

namespace Sentinel.Tests;

/// <summary>
/// The whole platform against the systems it will actually run on: a real PostgreSQL for its own state
/// and a real Elasticsearch for events. Nothing is faked below the adapters.
///
/// Actions are deliberately not dispatched. There is no security API to call here, and a test that
/// blocked an address to prove it could would be exactly the accident the safety rails exist to prevent.
/// What this establishes is the path up to the point of dispatch: a rule in the database becomes a query
/// against a live cluster, the counts come back, the threshold decides, and an alert is written.
///
/// Skipped unless both <c>SENTINEL_CONNECTION</c> and <c>SENTINEL_ES</c> are set.
/// </summary>
[Collection("postgres")]
public class EndToEndTests : IAsyncLifetime
{
    private readonly string? _database = Environment.GetEnvironmentVariable("SENTINEL_CONNECTION");
    private readonly string? _elasticsearch = Environment.GetEnvironmentVariable("SENTINEL_ES");

    private string _prefix = "";
    private int _connectionId;
    private int _ruleId;

    private bool Available => !string.IsNullOrWhiteSpace(_database) && !string.IsNullOrWhiteSpace(_elasticsearch);

    public async Task InitializeAsync()
    {
        if (!Available)
            return;

        _prefix = $"e2e{Guid.NewGuid():n}"[..10];

        await using var context = NewContext();
        await context.Database.MigrateAsync();

        var connection = new Connection
        {
            Name = $"{_prefix}-es",
            DisplayName = "Test cluster",
            Type = ConnectionType.Elasticsearch,
            Endpoint = _elasticsearch!,
            AuthenticationMode = AuthenticationMode.None,
            TimeoutSeconds = 30,
            Enabled = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = "test",
            UpdatedBy = "test"
        };

        context.Connections.Add(connection);
        await context.SaveChangesAsync();
        _connectionId = connection.Id;

        var rule = new DetectionRule
        {
            Name = $"{_prefix} API abuse",
            Description = "More than a hundred calls from one account in two hours.",
            Enabled = true,
            Severity = Severity.High,
            ConnectionId = _connectionId,
            CurrentVersion = 1,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = "test",
            UpdatedBy = "test"
        };

        context.Rules.Add(rule);
        await context.SaveChangesAsync();
        _ruleId = rule.Id;

        context.RuleVersions.Add(new RuleVersion
        {
            RuleId = _ruleId,
            Version = 1,
            Name = rule.Name,
            Description = rule.Description,
            Severity = Severity.High,
            IndexPatternsJson = """["wso2_2024-07-*"]""",
            QueryJson = "",
            TimestampField = "@timestamp",
            StrategyType = DetectionStrategyType.Threshold,
            GroupByJson = """["UserID.keyword"]""",
            Threshold = 100,
            WindowSeconds = 7200,
            QueryDelaySeconds = 30,
            IntervalSeconds = 900,
            CooldownSeconds = 21600,
            ActionsJson = "[]",
            CreatedAt = DateTime.UtcNow,
            CreatedBy = "test"
        });

        await context.SaveChangesAsync();
    }

    public async Task DisposeAsync()
    {
        if (!Available)
            return;

        await using var context = NewContext();

        await context.ActionExecutions.Where(e => e.IdempotencyKey.StartsWith(_prefix)).ExecuteDeleteAsync();
        await context.Alerts.Where(a => a.RuleId == _ruleId).ExecuteDeleteAsync();
        await context.Cooldowns.Where(c => c.Key.Contains($"|{_ruleId}|")).ExecuteDeleteAsync();
        await context.Checkpoints.Where(c => c.RuleId == _ruleId).ExecuteDeleteAsync();
        await context.RuleLeases.Where(l => l.RuleId == _ruleId).ExecuteDeleteAsync();
        await context.RuleVersions.Where(v => v.RuleId == _ruleId).ExecuteDeleteAsync();
        await context.Rules.Where(r => r.Id == _ruleId).ExecuteDeleteAsync();
        await context.Connections.Where(c => c.Id == _connectionId).ExecuteDeleteAsync();
    }

    [SkippableFact]
    public async Task The_cluster_answers_and_reports_what_it_is()
    {
        Skip.IfNot(Available);

        var probe = await NewEventSource().ProbeAsync(await LoadConnection());

        Assert.True(probe.Reachable, probe.Message);
        Assert.NotNull(probe.Version);
    }

    [SkippableFact]
    public async Task Fields_are_discovered_from_the_real_mapping()
    {
        Skip.IfNot(Available);

        // What makes a rule builder able to offer real field names rather than a text box.
        var catalog = await NewEventSource().DescribeFieldsAsync(
            await LoadConnection(), ["wso2_2024-07-*"]);

        Assert.NotEmpty(catalog.Fields);
        Assert.NotEmpty(catalog.IndicesInspected);

        // A timestamp to window on, and at least one field that can carry a group-by.
        Assert.Contains(catalog.Timestamps, f => f.Path == "@timestamp");
        Assert.Contains(catalog.Groupable, f => f.Path == "UserID.keyword");

        // The analysed parent is present but not offered for grouping — the distinction the reader exists
        // to draw, here against a real mapping rather than a hand-written one.
        Assert.Contains(catalog.Fields, f => f.Path == "UserID" && !f.Aggregatable);
    }

    [SkippableFact]
    public async Task A_rule_in_the_database_becomes_an_alert_from_live_events()
    {
        Skip.IfNot(Available);

        // The clock is fixed just after the events being looked for. A detection platform evaluates
        // forward from where it has reached, so reaching two-year-old data means telling it what "now" is
        // rather than asking it to replay history — which it deliberately refuses to do.
        var clock = new FixedClock(new DateTimeOffset(2024, 7, 28, 9, 0, 0, TimeSpan.Zero));

        var loaded = await NewRuntimeSource().ActiveRuleAsync(_ruleId);
        Assert.NotNull(loaded);

        var (rule, source) = loaded.Value;
        Assert.Equal("UserID.keyword", Assert.Single(rule.GroupBy));

        var outcome = await NewEvaluator(clock).EvaluateAsync(
            rule, source,
            // No security API in this test, and blocking something to prove the wiring works would be
            // exactly the accident the safety rails exist to prevent.
            dispatchActions: false);

        Assert.False(outcome.Failed, outcome.Error);
        Assert.True(outcome.CandidatesFound > 0,
            "Expected at least one account over the threshold in the sample data.");
        Assert.True(outcome.AlertsRaised > 0);

        await using var context = NewContext();
        var alerts = await context.Alerts.AsNoTracking().Where(a => a.RuleId == _ruleId).ToListAsync();

        Assert.NotEmpty(alerts);

        var alert = alerts[0];
        Assert.Equal(1, alert.RuleVersion);            // The version that produced it, for forensics.
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Equal(AlertStatus.Detected, alert.Status);
        Assert.True(alert.EventCount >= 100);
        Assert.Contains("apiuser", alert.Subject, StringComparison.OrdinalIgnoreCase);

        // The checkpoint moved, so the next run does not look at the same window again.
        var checkpoint = await context.Checkpoints.AsNoTracking().SingleAsync(c => c.RuleId == _ruleId);
        Assert.Equal(0, checkpoint.ConsecutiveFailures);
        Assert.True(checkpoint.LastRunAlerts > 0);
    }

    [SkippableFact]
    public async Task Evaluating_the_same_window_twice_does_not_alert_twice()
    {
        Skip.IfNot(Available);

        // Deduplication and cooldown, end to end against the real database: the second pass sees the same
        // accounts over the same threshold and records nothing new.
        var clock = new FixedClock(new DateTimeOffset(2024, 7, 28, 9, 0, 0, TimeSpan.Zero));
        var loaded = await NewRuntimeSource().ActiveRuleAsync(_ruleId);
        var (rule, source) = loaded!.Value;

        var first = await NewEvaluator(clock).EvaluateAsync(rule, source, dispatchActions: false);

        await NewCheckpoints(clock).ResetAsync(_ruleId, null);
        var second = await NewEvaluator(clock).EvaluateAsync(rule, source, dispatchActions: false);

        Assert.True(first.AlertsRaised > 0);
        Assert.Equal(0, second.AlertsRaised);
        Assert.True(second.Suppressed > 0 || second.CandidatesFound == 0);

        await using var context = NewContext();
        Assert.Equal(first.AlertsRaised,
            await context.Alerts.CountAsync(a => a.RuleId == _ruleId));
    }

    [SkippableFact]
    public async Task An_unreachable_cluster_fails_the_rule_without_losing_its_place()
    {
        Skip.IfNot(Available);

        var clock = new FixedClock(new DateTimeOffset(2024, 7, 28, 9, 0, 0, TimeSpan.Zero));

        await using (var seed = NewContext())
        {
            var broken = await seed.Connections.SingleAsync(c => c.Id == _connectionId);
            broken.Endpoint = "http://192.0.2.1:9200";  // TEST-NET-1: routable, never answers.
            broken.TimeoutSeconds = 2;
            await seed.SaveChangesAsync();
        }

        var loaded = await NewRuntimeSource().ActiveRuleAsync(_ruleId);
        var (rule, source) = loaded!.Value;

        var outcome = await NewEvaluator(clock).EvaluateAsync(rule, source, dispatchActions: false);

        Assert.True(outcome.Failed);
        Assert.Equal(0, outcome.AlertsRaised);

        await using var context = NewContext();
        var checkpoint = await context.Checkpoints.AsNoTracking().SingleAsync(c => c.RuleId == _ruleId);

        // The failure is visible and counted, and the rule has not skipped the window it could not read.
        Assert.Equal(1, checkpoint.ConsecutiveFailures);
        Assert.NotNull(checkpoint.LastError);
    }

    // -- wiring ------------------------------------------------------------------------------

    private SentinelDbContext NewContext() =>
        new(new DbContextOptionsBuilder<SentinelDbContext>().UseNpgsql(_database).Options);

    private async Task<Connection> LoadConnection()
    {
        await using var context = NewContext();
        return await context.Connections.AsNoTracking().SingleAsync(c => c.Id == _connectionId);
    }

    private static ElasticsearchEventSource NewEventSource() => new(
        new ConnectionHttpClients(new HttpClientHandler()),
        new ConnectionSecrets(new AesGcmSecretProtector(
            Options.Create(new SecretProtectionSettings()), isProduction: false)),
        NullLogger<ElasticsearchEventSource>.Instance);

    private EfRuleRuntimeSource NewRuntimeSource() =>
        new(NewContext(), NullLogger<EfRuleRuntimeSource>.Instance);

    private EfCheckpointStore NewCheckpoints(TimeProvider clock) => new(NewContext(), clock);

    private RuleEvaluator NewEvaluator(TimeProvider clock) => new(
        new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]),
        NewEventSource(),
        new DetectionPipeline(
            new EfAlertStore(NewContext(), NullLogger<EfAlertStore>.Instance),
            new EfCooldownStore(NewContext(), clock),
            clock),
        NewDispatcher(clock),
        NewCheckpoints(clock),
        NullLogger<RuleEvaluator>.Instance,
        clock);

    private ActionDispatcher NewDispatcher(TimeProvider clock) => new(
        // Registered but never reached: every call in this class passes dispatchActions: false.
        new ActionRegistry([new UnusableProvider()]),
        new EfConnectionLookup(NewContext()),
        new EfActionExecutionStore(NewContext(), NullLogger<EfActionExecutionStore>.Instance),
        new ActionSafetyPolicy(
            new ActionSafetySettings { ActionsEnabled = false },
            new EfActionRateStore(NewContext(), clock)),
        new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 1 },
        NullLogger<ActionDispatcher>.Instance,
        clock);

    /// <summary>Fails loudly if anything ever reaches it, so a regression cannot quietly start acting.</summary>
    private sealed class UnusableProvider : IActionProvider
    {
        public string Type => "block_ip";

        public ActionDescriptor Describe() => new(
            Type, "Block IP", "", ConnectionType.SecurityApi, true, true, []);

        public Application.Connections.ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            Application.Connections.ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default) =>
            throw new InvalidOperationException("An end-to-end test attempted a real action.");
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
