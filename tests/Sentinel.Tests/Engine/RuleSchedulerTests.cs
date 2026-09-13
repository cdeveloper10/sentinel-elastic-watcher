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
/// A tick with more than one rule in it.
///
/// There were no tests here at all, and that is exactly why the engine shipped unable to evaluate two
/// rules at once: the scheduler runs up to MaxConcurrentRules evaluations in parallel, and every one of
/// them was handed the same scoped DbContext. With a single rule armed the platform looked healthy. With
/// three, two of them threw "a second operation was started on this context instance", returned nothing,
/// and recorded no failure against the rule — so a rule that was armed and looked fine detected nothing.
///
/// Found by arming three rules against a real database, not by any test. These are the tests that would
/// have found it.
/// </summary>
public class RuleSchedulerTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    // -- isolation between the rules in one tick -----------------------------------------------

    [Fact]
    public async Task Each_rule_evaluates_in_its_own_slot()
    {
        // The invariant, stated directly. Anything shared between two concurrent evaluations is a
        // DbContext shared between two threads.
        var slots = new CountingSlots();
        var scheduler = Scheduler(slots, Rules(3), maxConcurrent: 4);

        await scheduler.TickAsync();

        Assert.Equal(3, slots.Created);
    }

    [Fact]
    public async Task Every_slot_is_disposed_even_though_the_rules_overlap()
    {
        // A slot is a container scope holding a database connection. Leaking one per rule per tick empties
        // the connection pool within minutes.
        var slots = new CountingSlots();

        await Scheduler(slots, Rules(4), maxConcurrent: 4).TickAsync();

        Assert.Equal(slots.Created, slots.Disposed);
    }

    [Fact]
    public async Task No_two_rules_hold_the_same_slot_at_the_same_moment()
    {
        // The property the count alone does not prove. Each evaluation announces itself on entry and on
        // exit; a slot that was live twice at once would be the defect back again.
        var slots = new CountingSlots { HoldFor = TimeSpan.FromMilliseconds(30) };

        await Scheduler(slots, Rules(4), maxConcurrent: 4).TickAsync();

        Assert.True(slots.SawOverlap, "the rules should genuinely have run at the same time");
        Assert.False(slots.SawReuseWhileLive, "a slot was used by two rules at once");
    }

    // -- what a tick returns --------------------------------------------------------------------

    [Fact]
    public async Task Every_due_rule_is_evaluated()
    {
        var slots = new CountingSlots();

        var outcomes = await Scheduler(slots, Rules(3), maxConcurrent: 4).TickAsync();

        Assert.Equal(3, outcomes.Count);
        Assert.Equal([1, 2, 3], outcomes.Select(o => o.RuleId).Order());
    }

    [Fact]
    public async Task A_rule_that_throws_does_not_stop_the_others()
    {
        // One broken rule becoming a platform outage is the failure this catch exists to prevent.
        var slots = new CountingSlots { ThrowForRule = 2 };

        var outcomes = await Scheduler(slots, Rules(3), maxConcurrent: 4).TickAsync();

        Assert.Equal([1, 3], outcomes.Select(o => o.RuleId).Order());
    }

    [Fact]
    public async Task A_rule_whose_lease_is_held_elsewhere_is_left_alone()
    {
        // Two nodes evaluating one rule would double every alert and every block.
        var slots = new CountingSlots { RefuseLeaseForRule = 2 };

        var outcomes = await Scheduler(slots, Rules(3), maxConcurrent: 4).TickAsync();

        Assert.Equal([1, 3], outcomes.Select(o => o.RuleId).Order());
    }

    [Fact]
    public async Task A_lease_is_released_whether_the_evaluation_worked_or_not()
    {
        // Rule 2 fails after its lease was taken. Not releasing it would park the rule until the lease
        // expired — every tick, for as long as the fault lasted.
        var slots = new CountingSlots { ThrowAfterLeaseForRule = 2 };

        await Scheduler(slots, Rules(3), maxConcurrent: 4).TickAsync();

        Assert.Equal([1, 2, 3], slots.Released.Order());
    }

    [Fact]
    public async Task A_lease_that_was_never_taken_is_never_released()
    {
        // The other half of the same rule. Releasing a lease this node does not hold would hand another
        // node's rule away mid-evaluation.
        var slots = new CountingSlots { RefuseLeaseForRule = 2 };

        await Scheduler(slots, Rules(3), maxConcurrent: 4).TickAsync();

        Assert.Equal([1, 3], slots.Released.Order());
    }

    [Fact]
    public async Task The_concurrency_cap_is_respected()
    {
        // A hundred due rules must not open a hundred simultaneous searches against a cluster that is also
        // serving the estate.
        var slots = new CountingSlots { HoldFor = TimeSpan.FromMilliseconds(25) };

        await Scheduler(slots, Rules(6), maxConcurrent: 2).TickAsync();

        Assert.True(slots.PeakLive <= 2, $"ran {slots.PeakLive} rules at once against a cap of 2");
    }

    [Fact]
    public async Task A_disabled_engine_evaluates_nothing()
    {
        var slots = new CountingSlots();

        var scheduler = Scheduler(slots, Rules(3), maxConcurrent: 4, enabled: false);

        Assert.Empty(await scheduler.TickAsync());
        Assert.Equal(0, slots.Created);
    }

    // -- fixtures ------------------------------------------------------------------------------

    private static RuleScheduler Scheduler(
        CountingSlots slots,
        IReadOnlyList<(RuleDefinition, Connection)> active,
        int maxConcurrent,
        bool enabled = true) => new(
        new StaticRules(active),
        new NeverRunCheckpoints(),
        slots,
        new EngineSettings
        {
            Enabled = enabled,
            MaxConcurrentRules = maxConcurrent,
            LeaseSeconds = 60,
            NodeId = "test-node"
        },
        NullLogger<RuleScheduler>.Instance,
        new FixedClock(Now));

    private static IReadOnlyList<(RuleDefinition, Connection)> Rules(int count) =>
        Enumerable.Range(1, count)
            .Select(id => (TestRules.BruteForce(threshold: 5) with { RuleId = id }, TestConnections.Elasticsearch()))
            .ToList();

    // -- doubles -------------------------------------------------------------------------------

    /// <summary>
    /// Stands in for the container's scopes, and watches how they are used.
    ///
    /// Deliberately not a mock of the evaluator: the thing under test is the scheduler's handling of
    /// slots, so the slot is what records.
    /// </summary>
    private sealed class CountingSlots : IRuleEvaluationSlotFactory
    {
        private readonly Lock _padlock = new();
        private int _live;

        public int Created { get; private set; }
        public int Disposed { get; private set; }
        public int PeakLive { get; private set; }
        public bool SawOverlap { get; private set; }
        public bool SawReuseWhileLive { get; private set; }
        public List<int> Released { get; } = [];

        /// <summary>How long an evaluation takes, so the overlap is real rather than assumed.</summary>
        public TimeSpan HoldFor { get; init; } = TimeSpan.Zero;

        /// <summary>Fails where the lease is claimed — before the rule is this node's to evaluate.</summary>
        public int? ThrowForRule { get; init; }

        /// <summary>Fails after the claim succeeded, which is the case that must still release it.</summary>
        public int? ThrowAfterLeaseForRule { get; init; }

        public int? RefuseLeaseForRule { get; init; }

        public IRuleEvaluationSlot Create()
        {
            lock (_padlock)
            {
                Created++;
                return new Slot(this);
            }
        }

        private void Enter(Slot slot)
        {
            lock (_padlock)
            {
                if (slot.Live) SawReuseWhileLive = true;

                slot.Live = true;
                _live++;

                if (_live > PeakLive) PeakLive = _live;
                if (_live > 1) SawOverlap = true;
            }
        }

        private void Exit(Slot slot)
        {
            lock (_padlock)
            {
                slot.Live = false;
                _live--;
            }
        }

        private sealed class Slot(CountingSlots owner) : IRuleEvaluationSlot, IRuleLeaseStore
        {
            public bool Live { get; set; }

            private int _ruleId;

            private readonly RuleEvaluator _evaluator = Isolated.Evaluator();

            // A real evaluator, wired to doubles that find nothing. The scheduler is what is under test,
            // but it has to be exercised through the type it actually calls — a stubbed evaluator would
            // prove only that the stub was called.
            //
            // Reached only after the lease is held, which is what makes this the place to simulate a
            // failure that must still release one.
            public RuleEvaluator Evaluator => owner.ThrowAfterLeaseForRule == _ruleId
                ? throw new InvalidOperationException("A rule failed after its lease was taken.")
                : _evaluator;

            public IRuleLeaseStore Leases => this;

            public async Task<bool> TryAcquireAsync(
                int ruleId, string owner_, TimeSpan duration, CancellationToken ct = default)
            {
                _ruleId = ruleId;

                if (owner.RefuseLeaseForRule == ruleId)
                    return false;

                owner.Enter(this);

                if (owner.HoldFor > TimeSpan.Zero)
                    await Task.Delay(owner.HoldFor, ct);

                if (owner.ThrowForRule == ruleId)
                    throw new InvalidOperationException("A rule threw where the evaluator would have.");

                return true;
            }

            public Task ReleaseAsync(int ruleId, string owner_, CancellationToken ct = default)
            {
                lock (owner._padlock)
                    owner.Released.Add(ruleId);

                owner.Exit(this);
                return Task.CompletedTask;
            }

            public ValueTask DisposeAsync()
            {
                lock (owner._padlock)
                {
                    owner.Disposed++;

                    // A slot that threw never released; the scope disposing is what ends its life.
                    if (Live) owner.Exit(this);
                }

                return ValueTask.CompletedTask;
            }
        }
    }

    /// <summary>
    /// A whole evaluator's worth of collaborators, none of them shared with another slot — which is the
    /// arrangement the engine now composes for real, one container scope at a time.
    /// </summary>
    private static class Isolated
    {
        public static RuleEvaluator Evaluator()
        {
            var clock = new FixedClock(Now);

            return new RuleEvaluator(
                new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]),
                new FakeEventSource(),
                new DetectionPipeline(new DiscardAlerts(), new NoCooldowns(), clock),
                new ActionDispatcher(
                    new ActionRegistry([new UnusedProvider()]),
                    new NoConnections(),
                    new DiscardExecutions(),
                    new ActionSafetyPolicy(new ActionSafetySettings(), new NoRates()),
                    new RetrySettings { MaxAttempts = 1, BaseDelayMs = 1, MaxDelayMs = 1 },
                    NullLogger<ActionDispatcher>.Instance,
                    clock),
                new NeverRunCheckpoints(),
                NullLogger<RuleEvaluator>.Instance,
                clock);
        }
    }

    private sealed class DiscardAlerts : IAlertStore
    {
        public Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default) => Task.FromResult(true);
    }

    private sealed class NoCooldowns : ICooldownStore
    {
        public Task<DateTimeOffset?> LastFiredAtAsync(string key, CancellationToken ct = default) =>
            Task.FromResult<DateTimeOffset?>(null);

        public Task RecordAsync(
            string key, DateTimeOffset firedAt, TimeSpan retention, CancellationToken ct = default) =>
            Task.CompletedTask;
    }

    private sealed class NoConnections : IConnectionLookup
    {
        public Task<Connection?> ByNameAsync(string name, CancellationToken ct = default) =>
            Task.FromResult<Connection?>(null);
    }

    private sealed class DiscardExecutions : IActionExecutionStore
    {
        public Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.FromResult(true);

        public Task UpdateAsync(ActionExecution execution, CancellationToken ct = default) =>
            Task.CompletedTask;
    }

    private sealed class NoRates : IActionRateStore
    {
        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(0);

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) => Task.FromResult(0);
    }

    /// <summary>Registered because a registry needs one; never reached, because no rule here has actions.</summary>
    private sealed class UnusedProvider : IActionProvider
    {
        public string Type => "unused";

        public ActionDescriptor Describe() =>
            new(Type, "Unused", "", ConnectionType.SecurityApi, true, false, []);

        public ValidationResult Validate(
            IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
            ValidationResult.Success;

        public Task<ActionOutcome> ExecuteAsync(
            ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default) =>
            throw new InvalidOperationException("No rule in these tests has an action.");
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class StaticRules(IReadOnlyList<(RuleDefinition, Connection)> active) : IRuleRuntimeSource
    {
        public Task<IReadOnlyList<(RuleDefinition Rule, Connection Source)>> ActiveRulesAsync(
            CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<(RuleDefinition, Connection)>>(active);

        public Task<(RuleDefinition Rule, Connection Source)?> ActiveRuleAsync(
            int ruleId, CancellationToken ct = default) =>
            Task.FromResult(active
                .Where(pair => pair.Item1.RuleId == ruleId)
                .Select(pair => ((RuleDefinition, Connection)?)pair)
                .FirstOrDefault());
    }

    /// <summary>No rule has ever run, so every rule is due.</summary>
    private sealed class NeverRunCheckpoints : ICheckpointStore
    {
        public Task<DateTimeOffset?> ReadAsync(int ruleId, CancellationToken ct = default) =>
            Task.FromResult<DateTimeOffset?>(null);

        public Task WriteAsync(int ruleId, EvaluationOutcome outcome, CancellationToken ct = default) =>
            Task.CompletedTask;

        public Task ResetAsync(int ruleId, DateTimeOffset? to, CancellationToken ct = default) =>
            Task.CompletedTask;

        public Task<int> ConsecutiveFailuresAsync(int ruleId, CancellationToken ct = default) =>
            Task.FromResult(0);
    }
}
