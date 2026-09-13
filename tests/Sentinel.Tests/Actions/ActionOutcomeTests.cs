using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Application.Detection;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// A message that can say what the block actually did.
///
/// The dispatcher runs an alert's actions in order, and its own comment says why: "block, then tell
/// somebody it was blocked". Until this existed the telling half had no way to find out — so a rule whose
/// message read "Address blocked." said exactly that whether or not the address had been blocked.
///
/// Found by arming such a rule against an address on the never-block list. The block was correctly
/// withheld and the SMS went out claiming the address had been blocked, which during an incident is worse
/// than saying nothing at all.
/// </summary>
public class ActionOutcomeTests
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

    private static RuleActionBinding Block() =>
        new("block_ip", "security-api", new Dictionary<string, string> { ["targetField"] = "event.source.ip" });

    private static RuleActionBinding Notify(string template) =>
        new("notify", "security-api", new Dictionary<string, string> { ["template"] = template });

    // -- what a later action can see -----------------------------------------------------------

    [Fact]
    public async Task A_message_can_report_that_the_block_succeeded()
    {
        var notify = new RecordingProvider("notify");

        await Dispatch(notify, new ActionSafetySettings(),
            "203.0.113.50",
            Block(),
            Notify("Block: {{actions.block_ip.status}}"));

        Assert.Equal("Block: SUCCESS", notify.LastMessage);
    }

    [Fact]
    public async Task A_message_can_report_that_the_block_was_withheld()
    {
        // The case that produced the lie. The address is on the never-block list, so nothing was blocked,
        // and now the message is able to say so.
        var notify = new RecordingProvider("notify");

        await Dispatch(notify, new ActionSafetySettings { NeverBlockAddresses = ["192.168.9.0/24"] },
            "192.168.9.11",
            Block(),
            Notify("Block: {{actions.block_ip.status}}"));

        Assert.Equal("Block: SKIPPED", notify.LastMessage);
    }

    [Fact]
    public async Task The_reason_is_available_so_a_status_alone_need_not_be_guessed_at()
    {
        // "SKIPPED" does not say whether the address was protected or the gateway was switched off, and
        // those call for different responses from whoever is reading.
        var notify = new RecordingProvider("notify");

        await Dispatch(notify, new ActionSafetySettings { NeverBlockAddresses = ["192.168.9.0/24"] },
            "192.168.9.11",
            Block(),
            Notify("{{actions.block_ip.reason}}"));

        Assert.Contains("never", notify.LastMessage!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_target_of_the_earlier_action_is_available()
    {
        var notify = new RecordingProvider("notify");

        await Dispatch(notify, new ActionSafetySettings(),
            "203.0.113.50",
            Block(),
            Notify("Blocked {{actions.block_ip.target}}"));

        Assert.Equal("Blocked 203.0.113.50", notify.LastMessage);
    }

    [Fact]
    public async Task An_action_cannot_see_what_comes_after_it()
    {
        // Actions run in order, so the first has no answer to give about the second. It renders blank
        // rather than inventing one.
        var notify = new RecordingProvider("notify");

        await Dispatch(notify, new ActionSafetySettings(),
            "203.0.113.50",
            Notify("Block: [{{actions.block_ip.status}}]"),
            Block());

        Assert.Equal("Block: []", notify.LastMessage);
    }

    // -- what an author is offered and allowed --------------------------------------------------

    [Fact]
    public void The_second_action_may_name_the_first_and_the_first_may_not_name_the_second()
    {
        var strategies = new DetectionStrategyRegistry(
            [new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]);

        var rule = TestRules.BruteForce(threshold: 10) with
        {
            Actions = [Block(), Notify("")]
        };

        var forBlock = RuleVocabulary.ForAction(rule, strategies, 0);
        var forNotify = RuleVocabulary.ForAction(rule, strategies, 1);

        Assert.DoesNotContain("actions.notify.status", forBlock);
        Assert.DoesNotContain("actions.block_ip.status", forBlock);

        Assert.Contains("actions.block_ip.status", forNotify);
        Assert.Contains("actions.block_ip.reason", forNotify);
        Assert.DoesNotContain("actions.notify.status", forNotify);
    }

    // -- fixtures ------------------------------------------------------------------------------

    private static async Task Dispatch(
        RecordingProvider notify,
        ActionSafetySettings safety,
        string sourceIp,
        params RuleActionBinding[] actions)
    {
        var dispatcher = new ActionDispatcher(
            new ActionRegistry([new BlockingProvider(), notify]),
            new OneConnection(),
            new AcceptingExecutions(),
            new ActionSafetyPolicy(safety, new NoRates()),
            new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 1 },
            NullLogger<ActionDispatcher>.Instance,
            new FixedClock(Now));

        await dispatcher.DispatchAsync(
            Alert(),
            TestRules.BruteForce(threshold: 10) with { RuleId = 11, Actions = actions },
            new Dictionary<string, string> { ["source.ip"] = sourceIp },
            new Dictionary<string, string> { ["eventCount"] = "12" });
    }

    /// <summary>Renders its template and keeps the result, standing in for anything that notifies.</summary>
    private sealed class RecordingProvider(string type) : IActionProvider
    {
        public string? LastMessage { get; private set; }

        public string Type => type;

        public ActionDescriptor Describe() => new(
            Type, "Notify", "", ConnectionType.SecurityApi,
            IsIdempotentByNature: false, IsDisruptive: false,
            [new ActionSettingSchema("template", "Message", "template", Required: false)],
            DefaultPath: "/notify");

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
        {
            LastMessage = TemplateRenderer.Render(context.Settings["template"], context).Text;
            return Task.FromResult(ActionOutcome.Success());
        }
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

    private sealed class OneConnection : IConnectionLookup
    {
        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult<Connection?>(new Connection
            {
                Name = name,
                Type = ConnectionType.SecurityApi,
                Endpoint = "https://gateway.internal",
                TimeoutSeconds = 30,
                Enabled = true
            });
    }

    private sealed class AcceptingExecutions : IActionExecutionStore
    {
        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(true);

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class NoRates : IActionRateStore
    {
        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(0);

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) => Task.FromResult(0);
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
