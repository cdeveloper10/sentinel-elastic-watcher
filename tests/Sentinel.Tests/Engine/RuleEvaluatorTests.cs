using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Application.Detection;
using Sentinel.Application.Engine;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Engine;

/// <summary>
/// One rule, evaluated once.
///
/// The behaviour worth pinning is what happens when things go wrong, because the failure modes here are
/// silent: a checkpoint advanced past windows that were never examined loses them permanently, and
/// nothing downstream can tell that from a quiet period.
/// </summary>
public class RuleEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    private readonly FakeEventSource _source = new();
    private readonly RecordingCheckpoints _checkpoints = new();
    private readonly InMemoryAlerts _alerts = new();
    private readonly InMemoryCooldowns _cooldowns = new();

    [Fact]
    public async Task A_rule_that_finds_nothing_still_advances_its_checkpoint()
    {
        // Otherwise a quiet period would be re-examined forever and the rule would never catch up.
        // No qualifying subject: the fake returns nothing.

        var outcome = await Evaluate(Rule());

        Assert.Equal(0, outcome.AlertsRaised);
        Assert.True(outcome.Checkpoint > Now.AddMinutes(-10));
        Assert.NotNull(_checkpoints.LastWritten);
    }

    [Fact]
    public async Task A_qualifying_subject_becomes_an_alert()
    {
        _source.WithGroup("source.ip", "10.10.10.20", 31);

        var outcome = await Evaluate(Rule());

        Assert.Equal(1, outcome.CandidatesFound);
        Assert.Equal(1, outcome.AlertsRaised);
        Assert.Single(_alerts.Stored);
    }

    [Fact]
    public async Task A_failed_evaluation_leaves_the_checkpoint_where_it_was()
    {
        // The most important line in the evaluator. A failure has examined nothing it can vouch for, and
        // moving past those windows would lose them with no trace.
        var before = Now.AddMinutes(-3);
        _checkpoints.Checkpoint = before;
        _source.Throws = new HttpRequestException("cluster unreachable");

        var outcome = await Evaluate(Rule());

        Assert.True(outcome.Failed);
        Assert.Equal(before, outcome.Checkpoint);
        Assert.Equal(before, _checkpoints.LastWritten!.Checkpoint);
    }

    [Fact]
    public async Task A_failure_is_recorded_rather_than_thrown()
    {
        // One unreachable cluster must not stop the scheduler evaluating every other rule.
        _source.Throws = new HttpRequestException("cluster unreachable");

        var outcome = await Evaluate(Rule());

        Assert.True(outcome.Failed);
        Assert.Contains("could not be reached", outcome.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_unknown_strategy_is_reported_against_the_rule_not_swallowed()
    {
        var outcome = await Evaluate(Rule() with { StrategyType = "does-not-exist" });

        Assert.True(outcome.Failed);
        Assert.Contains("does-not-exist", outcome.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_shutdown_mid_evaluation_does_not_advance_the_checkpoint()
    {
        // A deploy must cost latency, not coverage.
        using var cancelled = new CancellationTokenSource();
        _source.OnQuery = () => cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Evaluate(Rule(), ct: cancelled.Token));

        Assert.Null(_checkpoints.LastWritten);
    }

    [Fact]
    public async Task Cooldown_suppresses_a_subject_that_already_fired()
    {
        _source.WithGroup("source.ip", "10.10.10.20", 31);
        var rule = Rule();

        await Evaluate(rule);

        // Same subject, next evaluation, still inside the cooldown.
        _checkpoints.Checkpoint = Now;
        var second = await Evaluate(rule, at: Now.AddMinutes(1));

        Assert.Equal(0, second.AlertsRaised);
        Assert.Equal(1, second.Suppressed);
    }

    [Fact]
    public async Task Dispatch_can_be_left_out_so_the_same_path_serves_a_rehearsal()
    {
        _source.WithGroup("source.ip", "10.10.10.20", 31);

        var outcome = await Evaluate(RuleWithActions(), dispatch: false);

        Assert.Equal(1, outcome.AlertsRaised);
        Assert.Equal(0, outcome.ActionsSucceeded);
        Assert.Equal(0, outcome.ActionsFailed);
    }

    [Fact]
    public async Task Truncated_results_still_alert_on_what_was_seen()
    {
        // "At least this many" is not "none". Refusing to act on a partial view would be worse than
        // acting on it and saying so.
        _source.WithGroup("source.ip", "10.10.10.20", 31);
        _source.GroupsTruncated = true;

        var outcome = await Evaluate(Rule());

        Assert.Equal(1, outcome.AlertsRaised);
    }

    // -- helpers -----------------------------------------------------------------------------

    private static RuleDefinition Rule() => TestRules.BruteForce();

    private static RuleDefinition RuleWithActions() => TestRules.BruteForce(actions:
        [new RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>())]);

    private Task<EvaluationOutcome> Evaluate(
        RuleDefinition rule,
        bool dispatch = true,
        DateTimeOffset? at = null,
        CancellationToken ct = default)
    {
        var clock = new FixedClock(at ?? Now);

        var evaluator = new RuleEvaluator(
            new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]),
            _source,
            new DetectionPipeline(_alerts, _cooldowns, clock),
            NoopDispatcher(clock),
            _checkpoints,
            NullLogger<RuleEvaluator>.Instance,
            clock);

        return evaluator.EvaluateAsync(rule, TestConnections.Elasticsearch(), dispatch, ct);
    }

    private static ActionDispatcher NoopDispatcher(TimeProvider clock) => new(
        new ActionRegistry([new NoopProvider()]),
        new NoConnections(),
        new NoExecutions(),
        new ActionSafetyPolicy(new ActionSafetySettings(), new NoRates()),
        new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 1 },
        NullLogger<ActionDispatcher>.Instance,
        clock);

    // -- doubles -----------------------------------------------------------------------------

    private sealed class RecordingCheckpoints : ICheckpointStore
    {
        public DateTimeOffset? Checkpoint { get; set; }
        public EvaluationOutcome? LastWritten { get; private set; }
        public int Failures { get; set; }

        public Task<DateTimeOffset?> ReadAsync(int ruleId, CancellationToken ct = default) =>
            Task.FromResult(Checkpoint);

        public Task WriteAsync(int ruleId, EvaluationOutcome outcome, CancellationToken ct = default)
        {
            LastWritten = outcome;
            Checkpoint = outcome.Checkpoint;
            return Task.CompletedTask;
        }

        public Task ResetAsync(int ruleId, DateTimeOffset? to, CancellationToken ct = default)
        {
            Checkpoint = to;
            return Task.CompletedTask;
        }

        public Task<int> ConsecutiveFailuresAsync(int ruleId, CancellationToken ct = default) =>
            Task.FromResult(Failures);
    }

    private sealed class InMemoryAlerts : IAlertStore
    {
        public List<Alert> Stored { get; } = [];
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

        public Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default)
        {
            if (!_seen.Add(alert.Fingerprint))
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

    private sealed class NoopProvider : IActionProvider
    {
        public string Type => "block_ip";

        public ActionDescriptor Describe() => new(
            Type, "Block IP", "", ConnectionType.SecurityApi, true, true, []);

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default) =>
            Task.FromResult(ActionOutcome.Success());
    }

    private sealed class NoConnections : IConnectionLookup
    {
        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult<Connection?>(null);
    }

    private sealed class NoExecutions : IActionExecutionStore
    {
        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(true);

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class NoRates : IActionRateStore
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

