using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Application.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// An action that was deliberately not carried out leaves a record saying so.
///
/// Found by arming a rule that blocks an address and notifies the on-call, against an address covered by
/// the never-block list. The block was correctly withheld — and left nothing behind: no row, nothing in
/// the console, only a warning in the engine's log. An operator reading the alert saw a message sent and
/// no block, which is indistinguishable from the block never having been configured.
///
/// That is the wrong way round for this particular rail. The never-block list exists so the platform does
/// not block the estate's own egress address, and the moment it fires is exactly the moment somebody needs
/// to read "we did not block 192.168.9.11, because it is on the never-block list".
/// </summary>
public class SkippedActionRecordTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 11, 15, 0, TimeSpan.Zero);

    private static Alert Alert() => new()
    {
        Id = 41,
        AlertId = "a1b2c3",
        RuleId = 11,
        RuleVersion = 1,
        RuleName = "Repeated auth failures by source IP",
        Severity = "CRITICAL",
        DetectedAt = Now.UtcDateTime
    };

    private static RuleDefinition Rule(params RuleActionBinding[] actions) =>
        TestRules.BruteForce(threshold: 10) with { RuleId = 11, Actions = actions };

    [Fact]
    public async Task A_block_the_never_block_list_refuses_is_recorded()
    {
        var store = new RecordingExecutions();

        var dispatcher = Dispatcher(store, new ActionSafetySettings
        {
            NeverBlockAddresses = ["192.168.9.0/24"]
        });

        await dispatcher.DispatchAsync(
            Alert(),
            Rule(new RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>())),
            new Dictionary<string, string> { ["source.ip"] = "192.168.9.11" },
            new Dictionary<string, string> { ["eventCount"] = "12" });

        var written = Assert.Single(store.Claimed);

        Assert.Equal(ActionExecutionStatus.Skipped, written.Status);
        Assert.Equal("192.168.9.11", written.Target);
        Assert.Contains("never", written.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_skipped_action_records_no_start_time()
    {
        // Nothing started, so claiming otherwise would put a duration on something that never ran.
        var store = new RecordingExecutions();

        await Dispatcher(store, new ActionSafetySettings { NeverBlockAddresses = ["192.168.9.0/24"] })
            .DispatchAsync(
                Alert(),
                Rule(new RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>())),
                new Dictionary<string, string> { ["source.ip"] = "192.168.9.11" },
                new Dictionary<string, string>());

        Assert.Null(Assert.Single(store.Claimed).StartedAt);
    }

    [Fact]
    public async Task An_action_through_a_disabled_connection_is_recorded_too()
    {
        // The same silence, a different cause. "Nothing was sent" and "nothing was sent because somebody
        // disabled the gateway" need to be told apart from the alert.
        var store = new RecordingExecutions();

        var dispatcher = Dispatcher(store, new ActionSafetySettings(), connectionEnabled: false);

        await dispatcher.DispatchAsync(
            Alert(),
            Rule(new RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>())),
            new Dictionary<string, string> { ["source.ip"] = "203.0.113.50" },
            new Dictionary<string, string>());

        var written = Assert.Single(store.Claimed);

        Assert.Equal(ActionExecutionStatus.Skipped, written.Status);
        Assert.Equal("CONNECTION_DISABLED", written.ErrorCode);
    }

    [Fact]
    public async Task Failing_to_record_a_skip_does_not_stop_the_other_actions()
    {
        // The skip is a record, not the operation. A database that cannot take the row must not also cost
        // the alert its notification.
        var store = new RefusingExecutions();

        var result = await Dispatcher(store, new ActionSafetySettings { NeverBlockAddresses = ["192.168.9.0/24"] })
            .DispatchAsync(
                Alert(),
                Rule(
                    new RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>()),
                    new RuleActionBinding("noop", "security-api", new Dictionary<string, string>())),
                new Dictionary<string, string> { ["source.ip"] = "192.168.9.11" },
                new Dictionary<string, string>());

        Assert.Equal(2, result.Executions.Count);
        Assert.Equal(ActionExecutionStatus.Skipped, result.Executions[0].Status);

        // The notification still went out, which is the point: the address was not blocked and somebody
        // still had to be told.
        Assert.Equal(ActionExecutionStatus.Success, result.Executions[1].Status);
        Assert.Single(store.Claimed);
    }

    // -- fixtures ------------------------------------------------------------------------------

    private static ActionDispatcher Dispatcher(
        IActionExecutionStore store, ActionSafetySettings safety, bool connectionEnabled = true) => new(
        new ActionRegistry([new BlockingProvider(), new NoopProvider()]),
        new OneConnection(connectionEnabled),
        store,
        new ActionSafetyPolicy(safety, new NoRates()),
        new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 1 },
        NullLogger<ActionDispatcher>.Instance,
        new FixedClock(Now));

    private sealed class RecordingExecutions : IActionExecutionStore
    {
        public List<ActionExecution> Claimed { get; } = [];

        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default)
        {
            Claimed.Add(execution);
            return Task.FromResult(true);
        }

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) => Task.CompletedTask;
    }

    /// <summary>
    /// Refuses to write a skip and accepts everything else, which is the shape of the failure being
    /// tested: recording the refusal breaks, carrying out the next action must not.
    /// </summary>
    private sealed class RefusingExecutions : IActionExecutionStore
    {
        public List<ActionExecution> Claimed { get; } = [];

        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default)
        {
            if (execution.Status == ActionExecutionStatus.Skipped)
                throw new InvalidOperationException("the database would not take the row");

            Claimed.Add(execution);
            return Task.FromResult(true);
        }

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class OneConnection(bool enabled) : IConnectionLookup
    {
        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult<Connection?>(new Connection
            {
                Name = name,
                Type = ConnectionType.SecurityApi,
                Endpoint = "https://gateway.internal",
                TimeoutSeconds = 30,
                Enabled = enabled
            });
    }

    private sealed class NoRates : IActionRateStore
    {
        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(0);

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) => Task.FromResult(0);
    }

    private sealed class BlockingProvider : IActionProvider
    {
        public string Type => "block_ip";

        public ActionDescriptor Describe() => new(
            Type, "Block IP address", "", ConnectionType.SecurityApi,
            IsIdempotentByNature: true, IsDisruptive: true,
            [new ActionSettingSchema("targetField", "Address field", "field", Required: true,
                Default: "event.source.ip")],
            DefaultPath: "/security/block/ip");

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default) =>
            Task.FromResult(ActionOutcome.Success());
    }

    private sealed class NoopProvider : IActionProvider
    {
        public string Type => "noop";

        public ActionDescriptor Describe() => new(
            Type, "Does nothing", "", ConnectionType.SecurityApi,
            IsIdempotentByNature: true, IsDisruptive: false, [], DefaultPath: "/noop");

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default) =>
            Task.FromResult(ActionOutcome.Success());
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
