using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// Holding an action until a person says yes.
///
/// The claim this has to support is structural, not procedural: there is no path from a held action to an
/// executed one that does not pass through somebody deciding. So the tests are mostly about what does
/// <em>not</em> happen — the provider is not called, the gate cannot be used to run an action twice, and
/// an unanswered request ends up not performed rather than performed late.
/// </summary>
public class ApprovalGateTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    private readonly RecordingProvider _blockIp = new("block_ip", disruptive: true);
    private readonly RecordingProvider _sms = new("sms", disruptive: false, connectionType: ConnectionType.Sms);
    private readonly InMemoryExecutions _executions = new();
    private readonly StubConnections _connections = new();
    private readonly ActionSafetySettings _safety = new();

    private ActionDispatcher Dispatcher() => new(
        new ActionRegistry([_blockIp, _sms]),
        _connections,
        _executions,
        new ActionSafetyPolicy(_safety, new NullRates()),
        new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 2 },
        NullLogger<ActionDispatcher>.Instance,
        new FixedClock(Now));

    private static RuleActionBinding Binding(string type, string connection, bool requiresApproval = false) =>
        new(type, connection,
            new Dictionary<string, string> { ["targetField"] = "event.source.ip" },
            requiresApproval);

    private static Alert Alert() => new()
    {
        Id = 1,
        AlertId = "alert-" + Guid.NewGuid().ToString("n")[..8],
        RuleId = 1,
        RuleVersion = 3,
        RuleName = "Brute Force Detection",
        Severity = "HIGH",
        Subject = "10.10.10.20",
        DetectedAt = Now.UtcDateTime
    };

    private Task<DispatchResult> Dispatch(params RuleActionBinding[] actions) =>
        Dispatcher().DispatchAsync(
            Alert(),
            TestRules.BruteForce(actions: actions),
            new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" },
            new Dictionary<string, string> { ["eventCount"] = "31" });

    [Fact]
    public async Task A_gated_action_is_held_and_the_provider_is_never_called()
    {
        var result = await Dispatch(Binding("block_ip", "security-api", requiresApproval: true));

        var execution = Assert.Single(result.Executions);

        Assert.Equal(ActionExecutionStatus.PendingApproval, execution.Status);
        Assert.Equal(1, result.AwaitingApproval);

        // The whole claim, in one assertion: nothing reached the system that blocks addresses.
        Assert.Empty(_blockIp.Calls);
    }

    [Fact]
    public async Task Holding_it_still_claims_the_key()
    {
        // Claimed at the moment it parks, so the gate cannot become a second way to run the action: a
        // node reaching this alert afterwards finds the key already owned rather than starting again.
        var result = await Dispatch(Binding("block_ip", "security-api", requiresApproval: true));

        Assert.Single(_executions.Claimed);
        Assert.Contains(_executions.Claimed, key => key == result.Executions[0].IdempotencyKey);
    }

    [Fact]
    public async Task A_held_action_carries_a_deadline()
    {
        _safety.ApprovalWindowSeconds = 900;

        var result = await Dispatch(Binding("block_ip", "security-api", requiresApproval: true));

        Assert.Equal(Now.UtcDateTime.AddMinutes(15), result.Executions[0].ApprovalExpiresAt);
    }

    [Fact]
    public async Task A_window_shorter_than_a_minute_is_floored()
    {
        // A window that expires before anybody could have seen the request is a gate that always says no,
        // which is not what somebody setting it to five seconds meant.
        _safety.ApprovalWindowSeconds = 5;

        var result = await Dispatch(Binding("block_ip", "security-api", requiresApproval: true));

        Assert.Equal(Now.UtcDateTime.AddMinutes(1), result.Executions[0].ApprovalExpiresAt);
    }

    [Fact]
    public async Task The_actions_after_it_can_see_that_it_is_waiting()
    {
        // What makes the gate honest in the message that goes out. Without this the SMS says "Address
        // blocked." while the block sits waiting for somebody to approve it — which is the same defect
        // the outcome vocabulary was introduced to fix, in a new place.
        var result = await Dispatch(
            Binding("block_ip", "security-api", requiresApproval: true),
            Binding("sms", "security-sms"));

        var message = Assert.Single(_sms.Calls);

        Assert.True(message.Context.TryResolve("actions.block_ip.status", out var status));
        Assert.Equal(ActionExecutionStatus.PendingApproval, status);

        Assert.True(message.Context.TryResolve("actions.block_ip.reason", out var reason));
        Assert.Contains("approval", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_ungated_action_on_the_same_rule_still_runs()
    {
        // Gating is per binding. A rule that holds its block and sends its message immediately is the
        // common case — somebody has to be told there is something to approve.
        var result = await Dispatch(
            Binding("block_ip", "security-api", requiresApproval: true),
            Binding("sms", "security-sms"));

        Assert.Equal(ActionExecutionStatus.PendingApproval, result.Executions[0].Status);
        Assert.Equal(ActionExecutionStatus.Success, result.Executions[1].Status);
        Assert.Single(_sms.Calls);
    }

    [Fact]
    public async Task Approving_it_runs_the_action_through_the_ordinary_path()
    {
        var held = (await Dispatch(Binding("block_ip", "security-api", requiresApproval: true))).Executions[0];

        var context = ActionContext.From(
            Alert(),
            new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" },
            new Dictionary<string, string> { ["eventCount"] = "31" },
            new Dictionary<string, string> { ["targetField"] = "event.source.ip" });

        var result = await Dispatcher().ExecuteApprovedAsync(
            held, _blockIp, context, await _connections.ByNameAsync("security-api") ?? throw new Exception());

        Assert.Equal(ActionExecutionStatus.Success, result.Status);
        Assert.Single(_blockIp.Calls);

        // The same key it claimed when it parked: approving does not claim a second time.
        Assert.Equal(held.IdempotencyKey, _blockIp.Calls[0].IdempotencyKey);
    }

    [Fact]
    public void An_expired_request_is_no_longer_answerable()
    {
        var execution = new ActionExecution
        {
            Status = ActionExecutionStatus.PendingApproval,
            ApprovalExpiresAt = Now.UtcDateTime
        };

        Assert.True(execution.IsAwaitingApproval(Now.UtcDateTime.AddSeconds(-1)));
        Assert.False(execution.IsAwaitingApproval(Now.UtcDateTime));
        Assert.False(execution.IsAwaitingApproval(Now.UtcDateTime.AddSeconds(1)));
    }

    [Fact]
    public void Rejected_and_expired_are_both_final()
    {
        // Neither will change again on its own, so the retry machinery must not pick either back up.
        Assert.True(ActionExecutionStatus.IsTerminal(ActionExecutionStatus.Rejected));
        Assert.True(ActionExecutionStatus.IsTerminal(ActionExecutionStatus.Expired));

        // Waiting is not final: it is the one state that is still expected to move.
        Assert.False(ActionExecutionStatus.IsTerminal(ActionExecutionStatus.PendingApproval));
    }

    [Fact]
    public void A_rule_stored_before_gating_existed_keeps_running()
    {
        // Every version written before this feature has no such property, and reading it as anything but
        // false would silently park an action somebody has been relying on for months.
        var actions = RuleDefinitionMapper.ReadActions(
            """[{"type":"block_ip","connection":"security-api","settings":{}}]""");

        Assert.False(Assert.Single(actions).RequiresApproval);
    }

    [Fact]
    public void The_flag_survives_being_stored_and_read_back()
    {
        var written = RuleDefinitionMapper.WriteActions([Binding("block_ip", "security-api", requiresApproval: true)]);

        Assert.True(Assert.Single(RuleDefinitionMapper.ReadActions(written)).RequiresApproval);
    }

    // -- doubles -------------------------------------------------------------

    /// <summary>Records that it was called, which for these tests is mostly used to prove it was not.</summary>
    private sealed class RecordingProvider(
        string type, bool disruptive, string connectionType = ConnectionType.SecurityApi) : IActionProvider
    {
        public List<(ActionContext Context, string IdempotencyKey)> Calls { get; } = [];

        public string Type => type;

        public ActionDescriptor Describe() => new(
            type, type, "", connectionType,
            IsIdempotentByNature: true,
            IsDisruptive: disruptive,
            [new ActionSettingSchema("targetField", "Target", "field", Required: false,
                Default: "event.source.ip")]);

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
        {
            Calls.Add((context, idempotencyKey));
            return Task.FromResult(ActionOutcome.Success("{}", 200));
        }
    }

    private sealed class InMemoryExecutions : IActionExecutionStore
    {
        public HashSet<string> Claimed { get; } = new(StringComparer.Ordinal);

        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(Claimed.Add(execution.IdempotencyKey));

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.CompletedTask;
    }

    private sealed class StubConnections : IConnectionLookup
    {
        private readonly Dictionary<string, Connection> _connections = new(StringComparer.OrdinalIgnoreCase)
        {
            ["security-api"] = new Connection
            {
                Name = "security-api", Type = ConnectionType.SecurityApi,
                Endpoint = "https://gateway.internal", Enabled = true, TimeoutSeconds = 30
            },
            ["security-sms"] = new Connection
            {
                Name = "security-sms", Type = ConnectionType.Sms,
                Endpoint = "https://sms.internal", Enabled = true, TimeoutSeconds = 30
            }
        };

        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult(_connections.GetValueOrDefault(name));
    }

    private sealed class NullRates : IActionRateStore
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
