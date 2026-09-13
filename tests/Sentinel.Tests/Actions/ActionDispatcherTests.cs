using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// Running an alert's actions.
///
/// Everything that is the same for every action lives in the dispatcher — retry, backoff, idempotency, the
/// safety rails, the execution record — so that a new provider inherits all of it rather than
/// reimplementing some of it. There is no conditional on action type anywhere in it, which is what the
/// brief was asking for when it said not to write <c>if action == "sms"</c>.
/// </summary>
public class ActionDispatcherTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    private readonly RecordingProvider _blockIp = new("block_ip", disruptive: true);
    private readonly RecordingProvider _sms = new("sms", disruptive: false, connectionType: ConnectionType.Sms);
    private readonly InMemoryExecutionStore _executions = new();
    private readonly StubConnections _connections = new();
    private readonly ActionSafetySettings _safety = new();

    private ActionDispatcher Dispatcher(RetrySettings? retry = null) => new(
        new ActionRegistry([_blockIp, _sms]),
        _connections,
        _executions,
        new ActionSafetyPolicy(_safety, new NullRateStore()),
        retry ?? new RetrySettings { MaxAttempts = 3, BaseDelayMs = 1, MaxDelayMs = 2 },
        NullLogger<ActionDispatcher>.Instance,
        new FixedClock(Now));

    // -- the happy path ----------------------------------------------------------------------

    [Fact]
    public async Task Each_action_on_a_rule_is_executed_and_recorded()
    {
        var result = await Dispatch(Rule(Binding("block_ip", "security-api"), Binding("sms", "security-sms")));

        Assert.Equal(2, result.Executions.Count);
        Assert.Equal(2, result.Succeeded);
        Assert.Single(_blockIp.Calls);
        Assert.Single(_sms.Calls);
    }

    [Fact]
    public async Task The_execution_record_says_what_was_acted_on()
    {
        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));
        var execution = Assert.Single(result.Executions);

        Assert.Equal("block_ip", execution.ActionType);
        Assert.Equal("security-api", execution.ConnectionName);
        Assert.Equal("10.10.10.20", execution.Target);
        Assert.Equal(ActionExecutionStatus.Success, execution.Status);
        Assert.NotNull(execution.StartedAt);
        Assert.NotNull(execution.FinishedAt);
    }

    [Fact]
    public async Task Actions_run_in_the_order_the_rule_lists_them()
    {
        // They are usually related — block, then say it was blocked — and reporting the message before the
        // block landed would be a lie.
        var order = new List<string>();
        _blockIp.OnExecute = () => order.Add("block_ip");
        _sms.OnExecute = () => order.Add("sms");

        await Dispatch(Rule(Binding("block_ip", "security-api"), Binding("sms", "security-sms")));

        Assert.Equal(["block_ip", "sms"], order);
    }

    // -- idempotency -------------------------------------------------------------------------

    [Fact]
    public async Task The_same_alert_dispatched_twice_acts_once()
    {
        // A retry, a restart mid-run, or two nodes racing. Blocking an address twice is not the same as
        // blocking it once when the second call carries a fresh expiry.
        var rule = Rule(Binding("block_ip", "security-api"));
        var alert = Alert();

        await Dispatcher().DispatchAsync(alert, rule, Subject(), Evidence());
        var second = await Dispatcher().DispatchAsync(alert, rule, Subject(), Evidence());

        Assert.Single(_blockIp.Calls);
        Assert.Equal(ActionExecutionStatus.Skipped, Assert.Single(second.Executions).Status);
        Assert.Equal("ALREADY_EXECUTED", second.Executions[0].ErrorCode);
    }

    [Fact]
    public async Task The_idempotency_key_is_stable_across_processes()
    {
        // Derived from the alert and the binding, never from anything about this process or this moment.
        var binding = Binding("block_ip", "security-api");

        Assert.Equal(
            ActionDispatcher.IdempotencyKey("alert-1", binding),
            ActionDispatcher.IdempotencyKey("alert-1", binding));
    }

    [Fact]
    public void Different_alerts_and_different_actions_get_different_keys()
    {
        Assert.NotEqual(
            ActionDispatcher.IdempotencyKey("alert-1", Binding("block_ip", "security-api")),
            ActionDispatcher.IdempotencyKey("alert-2", Binding("block_ip", "security-api")));

        Assert.NotEqual(
            ActionDispatcher.IdempotencyKey("alert-1", Binding("block_ip", "security-api")),
            ActionDispatcher.IdempotencyKey("alert-1", Binding("sms", "security-api")));
    }

    [Fact]
    public async Task The_key_reaches_the_provider_so_the_far_side_can_collapse_a_repeat()
    {
        await Dispatch(Rule(Binding("block_ip", "security-api")));

        Assert.NotEmpty(Assert.Single(_blockIp.Calls).IdempotencyKey);
    }

    // -- retry -------------------------------------------------------------------------------

    [Fact]
    public async Task A_transient_failure_is_retried_and_can_still_succeed()
    {
        _blockIp.FailTransientlyTimes = 2;

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));
        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.Success, execution.Status);
        Assert.Equal(2, execution.RetryCount);
        Assert.Equal(3, _blockIp.Calls.Count);
    }

    [Fact]
    public async Task A_permanent_failure_is_not_retried()
    {
        // It will fail identically on every attempt; retrying only delays the moment somebody finds out.
        _blockIp.FailPermanently = true;

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));

        Assert.Equal(ActionExecutionStatus.Failed, Assert.Single(result.Executions).Status);
        Assert.Single(_blockIp.Calls);
    }

    [Fact]
    public async Task Exhausted_retries_land_in_dead_letter_rather_than_disappearing()
    {
        // An action that was supposed to block an address and never did is exactly the record an operator
        // needs to find.
        _blockIp.FailTransientlyTimes = 99;

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));
        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.DeadLetter, execution.Status);
        Assert.Equal(3, _blockIp.Calls.Count);
        Assert.NotNull(execution.ErrorMessage);
    }

    [Fact]
    public async Task A_provider_that_throws_is_treated_as_a_transient_failure()
    {
        _blockIp.Throws = new InvalidOperationException("boom");

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));

        Assert.Equal(ActionExecutionStatus.DeadLetter, Assert.Single(result.Executions).Status);
        Assert.Equal("PROVIDER_EXCEPTION", result.Executions[0].ErrorCode);
    }

    [Fact]
    public void Backoff_grows_and_is_capped_and_jittered()
    {
        // The jitter matters more than the growth: without it, twenty actions that failed against one
        // unavailable API retry in lockstep and knock the recovering service over again.
        var dispatcher = Dispatcher(new RetrySettings { MaxAttempts = 5, BaseDelayMs = 1000, MaxDelayMs = 8000 });

        var delays = Enumerable.Range(1, 20).Select(_ => dispatcher.Backoff(3)).ToList();

        Assert.All(delays, d => Assert.InRange(d.TotalMilliseconds, 1, 8000));
        Assert.True(delays.Distinct().Count() > 1, "Backoff must be jittered.");
        Assert.True(dispatcher.Backoff(1) <= dispatcher.Backoff(4) * 4);
    }

    // -- refusals ----------------------------------------------------------------------------

    [Fact]
    public async Task An_unknown_action_type_is_skipped_and_says_so()
    {
        var result = await Dispatch(Rule(Binding("quarantine_host", "security-api")));
        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.Skipped, execution.Status);
        Assert.Equal("UNKNOWN_ACTION", execution.ErrorCode);
    }

    [Fact]
    public async Task A_missing_connection_is_skipped()
    {
        var result = await Dispatch(Rule(Binding("block_ip", "does-not-exist")));

        Assert.Equal("UNKNOWN_CONNECTION", Assert.Single(result.Executions).ErrorCode);
        Assert.Empty(_blockIp.Calls);
    }

    [Fact]
    public async Task A_disabled_connection_is_skipped()
    {
        _connections.Disable("security-api");

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));

        Assert.Equal("CONNECTION_DISABLED", Assert.Single(result.Executions).ErrorCode);
    }

    [Fact]
    public async Task An_action_pointed_at_the_wrong_kind_of_connection_is_skipped()
    {
        // Sending a block to an SMS gateway would either fail confusingly or, worse, succeed against
        // something that was not the security API.
        var result = await Dispatch(Rule(Binding("block_ip", "security-sms")));

        Assert.Equal("CONNECTION_TYPE_MISMATCH", Assert.Single(result.Executions).ErrorCode);
        Assert.Empty(_blockIp.Calls);
    }

    [Fact]
    public async Task A_safety_rail_skips_the_action_and_records_the_reason()
    {
        // "The rule fired and we deliberately did nothing" is a different fact from "the rule did not
        // fire", and only one of them means the rule needs attention.
        _safety.NeverBlockAddresses = ["10.10.10.20"];

        var result = await Dispatch(Rule(Binding("block_ip", "security-api")));
        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.Skipped, execution.Status);
        Assert.Equal(ActionSafetyPolicy.CodeAllowlisted, execution.ErrorCode);
        Assert.Empty(_blockIp.Calls);
    }

    [Fact]
    public async Task A_skipped_action_does_not_stop_the_others()
    {
        _safety.NeverBlockAddresses = ["10.10.10.20"];

        var result = await Dispatch(Rule(Binding("block_ip", "security-api"), Binding("sms", "security-sms")));

        Assert.Equal(1, result.Skipped);
        Assert.Equal(1, result.Succeeded);
        Assert.Single(_sms.Calls);
    }

    [Fact]
    public async Task A_refused_action_never_reaches_the_provider_but_is_still_recorded()
    {
        // The half that matters is unchanged: the kill switch is off, so nothing is blocked.
        //
        // The other half used to be "and claims no key", on the reasoning that a claim is something an
        // operator would have to clear by hand before the action could run again. That worry does not
        // survive reading the call graph — DispatchAsync is reached from one place, at detection time, and
        // nothing re-dispatches a past alert's actions — so the claim stands in nothing's way, while
        // refusing to write it cost the estate its only durable record that a response was deliberately
        // withheld. See SkippedActionRecordTests.
        _safety.ActionsEnabled = false;

        await Dispatch(Rule(Binding("block_ip", "security-api")));

        Assert.Empty(_blockIp.Calls);
        Assert.Single(_executions.Claimed);
    }

    // -- helpers -----------------------------------------------------------------------------

    private Task<DispatchResult> Dispatch(RuleDefinition rule) =>
        Dispatcher().DispatchAsync(Alert(), rule, Subject(), Evidence());

    private static RuleActionBinding Binding(string type, string connection) =>
        new(type, connection, new Dictionary<string, string> { ["targetField"] = "event.source.ip" });

    private static RuleDefinition Rule(params RuleActionBinding[] actions) =>
        TestRules.BruteForce(actions: actions);

    private static Alert Alert() => new()
    {
        Id = 1,
        AlertId = "alert-" + Guid.NewGuid().ToString("n")[..8],
        RuleId = 1,
        RuleVersion = 3,
        RuleName = "Brute Force Detection",
        Severity = "HIGH",
        DetectedAt = Now.UtcDateTime
    };

    private static Dictionary<string, string> Subject() => new() { ["source.ip"] = "10.10.10.20" };

    private static Dictionary<string, string> Evidence() => new() { ["eventCount"] = "31" };

    // -- doubles -----------------------------------------------------------------------------

    private sealed class RecordingProvider(
        string type, bool disruptive, string connectionType = ConnectionType.SecurityApi) : IActionProvider
    {
        public string Type { get; } = type;

        public List<(ActionContext Context, string IdempotencyKey)> Calls { get; } = [];

        public int FailTransientlyTimes { get; set; }
        public bool FailPermanently { get; set; }
        public Exception? Throws { get; set; }
        public Action? OnExecute { get; set; }

        public ActionDescriptor Describe() => new(
            Type, Type, "", connectionType,
            IsIdempotentByNature: true,
            IsDisruptive: disruptive,
            [new ActionSettingSchema("targetField", "Target", "field", true, "event.source.ip")]);

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
        {
            Calls.Add((context, idempotencyKey));
            OnExecute?.Invoke();

            if (Throws is not null)
                throw Throws;

            if (FailPermanently)
                return Task.FromResult(ActionOutcome.Permanent("REJECTED", "The system rejected the request."));

            if (Calls.Count <= FailTransientlyTimes)
                return Task.FromResult(ActionOutcome.Transient("UPSTREAM_ERROR", "Temporarily unavailable."));

            return Task.FromResult(ActionOutcome.Success("{}", 200));
        }
    }

    private sealed class InMemoryExecutionStore : IActionExecutionStore
    {
        public HashSet<string> Claimed { get; } = new(StringComparer.Ordinal);
        public List<ActionExecution> Updates { get; } = [];

        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(Claimed.Add(execution.IdempotencyKey));

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default)
        {
            Updates.Add(execution);
            return Task.CompletedTask;
        }
    }

    private sealed class StubConnections : IConnectionLookup
    {
        private readonly Dictionary<string, Connection> _connections = new(StringComparer.OrdinalIgnoreCase)
        {
            ["security-api"] = new Connection
            {
                Name = "security-api", Type = ConnectionType.SecurityApi,
                Endpoint = "https://gateway.internal:5302", Enabled = true, TimeoutSeconds = 30
            },
            ["security-sms"] = new Connection
            {
                Name = "security-sms", Type = ConnectionType.Sms,
                Endpoint = "https://sms.internal", Enabled = true, TimeoutSeconds = 30
            }
        };

        public void Disable(string name) => _connections[name].Enabled = false;

        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult(_connections.GetValueOrDefault(name));
    }

    private sealed class NullRateStore : IActionRateStore
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
