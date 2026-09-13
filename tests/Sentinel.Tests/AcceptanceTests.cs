using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Rules;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Elasticsearch;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests;

/// <summary>
/// The end-to-end scenario the brief requires, with every layer real except the two systems at the edges.
///
/// Elasticsearch and the security API are recorded HTTP handlers; the detection strategy, the pipeline,
/// the safety policy, the dispatcher and the providers are the production classes wired the way the host
/// wires them. What this proves is not that any one part works — the unit tests do that — but that the
/// seams line up: that a count coming out of an aggregation becomes a subject, becomes an alert, becomes
/// a request to block an address, and that doing it twice does not block twice.
/// </summary>
public class AcceptanceTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    private readonly FakeElasticsearch _cluster = new();
    private readonly FakeElasticsearch _securityApi = new();
    private readonly InMemoryAlerts _alerts = new();
    private readonly InMemoryCooldowns _cooldowns = new();
    private readonly InMemoryExecutions _executions = new();
    private readonly ActionSafetySettings _safety = new();

    /// <summary>The brief's first example rule, verbatim.</summary>
    private static RuleDefinition BruteForceRule(params RuleActionBinding[] actions) => new(
        RuleId: 1,
        Version: 1,
        Name: "Brute Force Detection",
        Description: "More than twenty failed logins from one address in five minutes.",
        Severity: Severity.High,
        ConnectionId: 1,
        IndexPatterns: ["gateway-logs-*"],
        QueryJson: """{"term":{"event.type":"authentication_failed"}}""",
        TimestampField: "@timestamp",
        StrategyType: DetectionStrategyType.Threshold,
        GroupBy: ["source.ip"],
        Threshold: 20,
        Window: TimeSpan.FromMinutes(5),
        QueryDelay: TimeSpan.FromSeconds(30),
        Interval: TimeSpan.FromMinutes(1),
        Cooldown: TimeSpan.FromMinutes(30),
        Actions: actions);

    private static RuleActionBinding BlockIp() =>
        new("block_ip", "security-api", new Dictionary<string, string> { ["targetField"] = "event.source.ip" });

    private static RuleActionBinding Sms() =>
        new("sms", "security-sms", new Dictionary<string, string>());

    [Fact]
    public async Task A_brute_force_rule_detects_blocks_and_notifies_end_to_end()
    {
        // 1. Elasticsearch holds thirty-one failed logins from one address.
        _cluster.Answers("""
        {
          "took": 9,
          "aggregations": {
            "groups": {
              "sum_other_doc_count": 0,
              "buckets": [ { "key": "10.10.10.20", "doc_count": 31 } ]
            }
          }
        }
        """);

        _securityApi.Answers("""{"blocked":true}""").Answers("""{"queued":true}""");

        var rule = BruteForceRule(BlockIp(), Sms());

        // 2. The engine evaluates the window the planner chose.
        var plan = TimeWindowPlanner.Plan(Now, null, rule.Window, rule.QueryDelay, rule.Interval);
        var window = Assert.Single(plan.Windows);

        var source = TestConnections.Source(_cluster);
        var strategy = new ThresholdDetectionStrategy();

        var found = await strategy.EvaluateAsync(
            new StrategyRequest(rule, TestConnections.Elasticsearch(), window), source);

        // 3. The query it sent carried the threshold and asked for no documents.
        Assert.Contains("\"min_doc_count\":20", _cluster.LastBody, StringComparison.Ordinal);
        Assert.Contains("\"size\":0", _cluster.LastBody, StringComparison.Ordinal);

        // 4. One subject qualified.
        var candidate = Assert.Single(found.Candidates);
        Assert.Equal("10.10.10.20", candidate.Subject["source.ip"]);
        Assert.Equal(31, candidate.EventCount);

        // 5. It became an alert.
        var pipeline = new DetectionPipeline(_alerts, _cooldowns, new FixedClock(Now));
        var processed = await pipeline.ProcessAsync(rule, found.Candidates);

        var alert = Assert.Single(processed.NewAlerts);
        Assert.Equal("Brute Force Detection", alert.RuleName);
        Assert.Equal(1, alert.RuleVersion);
        Assert.Equal("10.10.10.20", alert.SourceIp);
        Assert.Equal(AlertStatus.Detected, alert.Status);

        // 6-9. Both actions ran.
        var result = await Dispatcher().DispatchAsync(
            alert, rule, candidate.Subject, Evidence(candidate));

        Assert.Equal(2, result.Succeeded);

        // 8. The security API received the payload the brief specifies.
        var blockRequest = JsonNode.Parse(_securityApi.Bodies[0])!.AsObject();
        Assert.Equal("10.10.10.20", blockRequest["ip"]!.GetValue<string>());
        Assert.Equal(1800, blockRequest["duration"]!.GetValue<int>());
        Assert.Equal("Brute Force Detection", blockRequest["reason"]!.GetValue<string>());

        // 9. The message names the rule and the address.
        var message = JsonNode.Parse(_securityApi.Bodies[1])!["message"]!.GetValue<string>();
        Assert.Contains("Brute Force Detection", message, StringComparison.Ordinal);
        Assert.Contains("10.10.10.20", message, StringComparison.Ordinal);

        // 10. Both executions were recorded, with durations and targets.
        Assert.Equal(2, result.Executions.Count);
        Assert.All(result.Executions, e =>
        {
            Assert.Equal(ActionExecutionStatus.Success, e.Status);
            Assert.NotNull(e.FinishedAt);
            Assert.NotEmpty(e.IdempotencyKey);
        });
    }

    [Fact]
    public async Task If_the_security_api_fails_the_action_is_retried()
    {
        // 14. Two failures then success — one block, three attempts.
        _securityApi
            .Answers("""{"error":"unavailable"}""", System.Net.HttpStatusCode.ServiceUnavailable)
            .Answers("""{"error":"unavailable"}""", System.Net.HttpStatusCode.ServiceUnavailable)
            .Answers("""{"blocked":true}""");

        var rule = BruteForceRule(BlockIp());
        var alert = await DetectOne(31);

        var result = await Dispatcher().DispatchAsync(
            alert, rule, new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" },
            new Dictionary<string, string>());

        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.Success, execution.Status);
        Assert.Equal(2, execution.RetryCount);
        Assert.Equal(3, _securityApi.Requests.Count);
    }

    [Fact]
    public async Task If_the_same_alert_is_processed_twice_the_address_is_blocked_once()
    {
        // 15. The claim is what holds: a retry, a restart mid-run, or a second node.
        _securityApi.Answers("""{"blocked":true}""").Answers("""{"blocked":true}""");

        var rule = BruteForceRule(BlockIp());
        var alert = await DetectOne(31);
        var subject = new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" };

        await Dispatcher().DispatchAsync(alert, rule, subject, new Dictionary<string, string>());
        var second = await Dispatcher().DispatchAsync(alert, rule, subject, new Dictionary<string, string>());

        Assert.Single(_securityApi.Requests);
        Assert.Equal(ActionExecutionStatus.Skipped, Assert.Single(second.Executions).Status);
        Assert.Equal("ALREADY_EXECUTED", second.Executions[0].ErrorCode);
    }

    [Fact]
    public async Task A_dry_run_touches_nothing()
    {
        // 16. No alert is written, no request reaches the security API — and the reason is that a dry run
        // has no path to a dispatcher at all, not that a flag was honoured.
        _cluster.Answers("""
        { "aggregations": { "groups": { "buckets": [ { "key": "10.10.10.20", "doc_count": 31 } ] } } }
        """);

        var dryRun = new DryRunService(
            new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]));

        var result = await dryRun.RunAsync(
            BruteForceRule(BlockIp(), Sms()),
            TestConnections.Elasticsearch(),
            TestConnections.Source(_cluster),
            new TimeRange(Now.AddMinutes(-10), Now));

        Assert.True(result.Succeeded);
        Assert.NotEmpty(result.WouldDetect);
        Assert.Equal(2, result.WouldExecute.Count);

        Assert.Empty(_securityApi.Requests);
        Assert.Empty(_alerts.Stored);
        Assert.Empty(_executions.Claimed);
    }

    [Fact]
    public async Task The_office_egress_address_is_not_blocked_by_a_brute_force_rule()
    {
        // Not in the brief, and the first thing that goes wrong in production: a rule counting failed
        // logins behind NAT identifies the address every employee shares.
        _safety.NeverBlockAddresses = ["10.0.0.0/8"];
        _securityApi.Answers("""{"blocked":true}""");

        var rule = BruteForceRule(BlockIp(), Sms());
        var alert = await DetectOne(31);

        var result = await Dispatcher().DispatchAsync(
            alert, rule, new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" },
            new Dictionary<string, string>());

        var block = Assert.Single(result.Executions, e => e.ActionType == "block_ip");
        Assert.Equal(ActionExecutionStatus.Skipped, block.Status);
        Assert.Equal(ActionSafetyPolicy.CodeAllowlisted, block.ErrorCode);

        // The people who would fix it are still told.
        Assert.Equal(ActionExecutionStatus.Success, Assert.Single(result.Executions, e => e.ActionType == "sms").Status);
    }

    [Fact]
    public async Task A_second_evaluation_in_the_cooldown_does_not_block_again()
    {
        // The brief's own example: a thousand matching events become one detection and one block, not a
        // thousand of each.
        _cluster
            .Answers("""{ "aggregations": { "groups": { "buckets": [ { "key": "10.10.10.20", "doc_count": 31 } ] } } }""")
            .Answers("""{ "aggregations": { "groups": { "buckets": [ { "key": "10.10.10.20", "doc_count": 44 } ] } } }""");

        var rule = BruteForceRule(BlockIp());
        var source = TestConnections.Source(_cluster);
        var strategy = new ThresholdDetectionStrategy();
        var pipeline = new DetectionPipeline(_alerts, _cooldowns, new FixedClock(Now));

        var first = await strategy.EvaluateAsync(
            new StrategyRequest(rule, TestConnections.Elasticsearch(), Window(Now)), source);
        await pipeline.ProcessAsync(rule, first.Candidates);

        // A minute later the address still qualifies in the next overlapping window.
        var laterPipeline = new DetectionPipeline(_alerts, _cooldowns, new FixedClock(Now.AddMinutes(1)));
        var second = await strategy.EvaluateAsync(
            new StrategyRequest(rule, TestConnections.Elasticsearch(), Window(Now.AddMinutes(1))), source);

        var processed = await laterPipeline.ProcessAsync(rule, second.Candidates);

        Assert.Empty(processed.NewAlerts);
        Assert.Equal(1, processed.Suppressed);
        Assert.Single(_alerts.Stored);
    }

    // -- wiring ------------------------------------------------------------------------------

    private ActionDispatcher Dispatcher() => new(
        new ActionRegistry([
            new BlockIpActionProvider(
                new ConnectionHttpClients(_securityApi), new StubSecrets(), NullLogger<BlockIpActionProvider>.Instance),
            new BlockUserActionProvider(
                new ConnectionHttpClients(_securityApi), new StubSecrets(), NullLogger<BlockUserActionProvider>.Instance),
            new SmsActionProvider(
                new ConnectionHttpClients(_securityApi), new StubSecrets(), NullLogger<SmsActionProvider>.Instance)
        ]),
        new Connections(),
        _executions,
        new ActionSafetyPolicy(_safety, new UncountedRates()),
        new RetrySettings { MaxAttempts = 3, BaseDelayMs = 1, MaxDelayMs = 2 },
        NullLogger<ActionDispatcher>.Instance,
        new FixedClock(Now));

    private static TimeRange Window(DateTimeOffset end) => TimeRange.EndingAt(end, TimeSpan.FromMinutes(5));

    private static Dictionary<string, string> Evidence(DetectionCandidate candidate) =>
        candidate.Evidence.ToDictionary(p => p.Key, p => p.Value?.ToString() ?? "", StringComparer.Ordinal);

    private async Task<Alert> DetectOne(long count)
    {
        _cluster.Answers($$"""
        { "aggregations": { "groups": { "buckets": [ { "key": "10.10.10.20", "doc_count": {{count}} } ] } } }
        """);

        var rule = BruteForceRule();
        var found = await new ThresholdDetectionStrategy().EvaluateAsync(
            new StrategyRequest(rule, TestConnections.Elasticsearch(), Window(Now)),
            TestConnections.Source(_cluster));

        var processed = await new DetectionPipeline(_alerts, _cooldowns, new FixedClock(Now))
            .ProcessAsync(rule, found.Candidates);

        return processed.NewAlerts.Single();
    }

    // -- stores --------------------------------------------------------------------------------

    private sealed class InMemoryAlerts : IAlertStore
    {
        public List<Alert> Stored { get; } = [];
        private readonly HashSet<string> _fingerprints = new(StringComparer.Ordinal);

        public Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default)
        {
            if (!_fingerprints.Add(alert.Fingerprint))
                return Task.FromResult(false);

            alert.Id = Stored.Count + 1;
            Stored.Add(alert);
            return Task.FromResult(true);
        }
    }

    private sealed class InMemoryCooldowns : ICooldownStore
    {
        private readonly Dictionary<string, DateTimeOffset> _fired = new(StringComparer.Ordinal);

        public Task<DateTimeOffset?> LastFiredAtAsync(string key, CancellationToken ct = default) =>
            Task.FromResult(_fired.TryGetValue(key, out var at) ? at : (DateTimeOffset?)null);

        public Task RecordAsync(string key, DateTimeOffset firedAt, TimeSpan retention, CancellationToken ct = default)
        {
            _fired[key] = firedAt;
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryExecutions : IActionExecutionStore
    {
        public HashSet<string> Claimed { get; } = new(StringComparer.Ordinal);

        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(Claimed.Add(execution.IdempotencyKey));

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class Connections : IConnectionLookup
    {
        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult<Connection?>(name switch
            {
                "security-api" => new Connection
                {
                    Name = name, Type = ConnectionType.SecurityApi,
                    Endpoint = "https://gateway.internal:5302", Enabled = true, TimeoutSeconds = 30
                },
                "security-sms" => new Connection
                {
                    Name = name, Type = ConnectionType.Sms,
                    Endpoint = "https://sms.internal", Enabled = true, TimeoutSeconds = 30
                },
                _ => null
            });
    }

    private sealed class UncountedRates : IActionRateStore
    {
        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(1);

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) => Task.FromResult(0);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
