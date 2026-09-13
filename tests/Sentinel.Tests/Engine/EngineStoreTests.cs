using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Engine;
using Sentinel.Infrastructure.Engine;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Engine;

/// <summary>
/// The engine's own bookkeeping: how far each rule has been evaluated, and which node is doing it.
///
/// Both exist because the platform runs as more than one pod and gets restarted. Neither is interesting
/// on a single node that never stops, which is exactly why they are easy to get wrong.
/// </summary>
public class EngineStoreTests : IDisposable
{
    private readonly TestDatabase _database = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero));

    public void Dispose() => _database.Dispose();

    // -- checkpoints -------------------------------------------------------------------------

    [Fact]
    public async Task A_rule_that_has_never_run_has_no_checkpoint() =>
        Assert.Null(await NewCheckpoints().ReadAsync(1));

    [Fact]
    public async Task A_checkpoint_survives_a_restart()
    {
        // The whole reason it is a row. Starting a window back after every restart means a rolling update
        // silently skips whatever happened while the pod was down.
        var reached = _clock.GetUtcNow().AddMinutes(-1);

        await NewCheckpoints().WriteAsync(1, Outcome(1, reached));

        Assert.Equal(reached, await NewCheckpoints().ReadAsync(1));
    }

    [Fact]
    public async Task A_successful_run_records_what_it_did()
    {
        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow(), windows: 3, alerts: 2, durationMs: 450));

        await using var context = _database.NewContext();
        var checkpoint = await context.Checkpoints.SingleAsync();

        Assert.Equal(3, checkpoint.LastRunWindows);
        Assert.Equal(2, checkpoint.LastRunAlerts);
        Assert.Equal(450, checkpoint.LastRunDurationMs);
        Assert.Null(checkpoint.LastError);
    }

    [Fact]
    public async Task A_failed_run_keeps_the_error_so_a_quiet_rule_can_be_explained()
    {
        // "Why has this rule not alerted?" has to have an answer that is not "look in the pod logs".
        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow(), error: "The cluster refused the query."));

        await using var context = _database.NewContext();
        var checkpoint = await context.Checkpoints.SingleAsync();

        Assert.Equal("The cluster refused the query.", checkpoint.LastError);
        Assert.NotNull(checkpoint.LastErrorAt);
        Assert.Equal(1, checkpoint.ConsecutiveFailures);
    }

    [Fact]
    public async Task Consecutive_failures_accumulate_and_reset_on_success()
    {
        // The scheduler reads this to widen the interval, so a cluster that is down is queried on a
        // growing delay rather than by every node every tick.
        var store = NewCheckpoints();

        await store.WriteAsync(1, Outcome(1, _clock.GetUtcNow(), error: "down"));
        await store.WriteAsync(1, Outcome(1, _clock.GetUtcNow(), error: "down"));
        await store.WriteAsync(1, Outcome(1, _clock.GetUtcNow(), error: "down"));

        Assert.Equal(3, await NewCheckpoints().ConsecutiveFailuresAsync(1));

        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow()));
        Assert.Equal(0, await NewCheckpoints().ConsecutiveFailuresAsync(1));
    }

    [Fact]
    public async Task A_reset_moves_the_checkpoint_and_clears_the_failure_history()
    {
        // An operator saying "try again from here" after fixing a rule; the backoff that was holding it
        // back goes with it.
        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow(), error: "down"));

        var target = _clock.GetUtcNow().AddHours(-2);
        await NewCheckpoints().ResetAsync(1, target);

        Assert.Equal(target, await NewCheckpoints().ReadAsync(1));
        Assert.Equal(0, await NewCheckpoints().ConsecutiveFailuresAsync(1));
    }

    [Fact]
    public async Task Resetting_to_nothing_makes_the_rule_start_as_though_it_were_new()
    {
        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow()));

        await NewCheckpoints().ResetAsync(1, null);

        Assert.Null(await NewCheckpoints().ReadAsync(1));
    }

    [Fact]
    public async Task A_capped_catch_up_is_recorded_so_missing_coverage_is_visible()
    {
        // A stretch of time was never examined. An operator deciding whether an incident was missed needs
        // that fact, not an absence of alerts.
        await NewCheckpoints().WriteAsync(1, Outcome(1, _clock.GetUtcNow()) with { SkippedBacklog = true });

        await using var context = _database.NewContext();
        Assert.True((await context.Checkpoints.SingleAsync()).LastRunSkippedBacklog);
    }

    // -- leases ------------------------------------------------------------------------------

    [Fact]
    public async Task A_free_rule_can_be_claimed() =>
        Assert.True(await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2)));

    [Fact]
    public async Task A_second_node_cannot_claim_a_held_rule()
    {
        // The one thing this exists to prevent: two nodes evaluating one rule at the same moment, which
        // would double every alert and every block it produces.
        Assert.True(await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2)));
        Assert.False(await NewLeases().TryAcquireAsync(1, "node-b", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task The_holder_can_reclaim_its_own_rule()
    {
        // A node resuming its own work after a tick must not be locked out by itself.
        Assert.True(await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2)));
        Assert.True(await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task An_expired_lease_is_claimable_by_anyone()
    {
        // A node that died mid-evaluation must not hold its rules until somebody notices.
        await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2));

        _clock.Advance(TimeSpan.FromMinutes(3));

        Assert.True(await NewLeases().TryAcquireAsync(1, "node-b", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task Releasing_hands_the_rule_straight_to_another_node()
    {
        await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2));
        await NewLeases().ReleaseAsync(1, "node-a");

        Assert.True(await NewLeases().TryAcquireAsync(1, "node-b", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task A_node_cannot_release_a_rule_it_does_not_hold()
    {
        await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2));
        await NewLeases().ReleaseAsync(1, "node-b");

        Assert.False(await NewLeases().TryAcquireAsync(1, "node-c", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task Different_rules_are_leased_independently()
    {
        // Per rule rather than one leader for the engine: a single leader leaves every other node idle and
        // caps the platform's throughput at one machine.
        Assert.True(await NewLeases().TryAcquireAsync(1, "node-a", TimeSpan.FromMinutes(2)));
        Assert.True(await NewLeases().TryAcquireAsync(2, "node-b", TimeSpan.FromMinutes(2)));
    }

    [Fact]
    public async Task Only_one_node_wins_a_contested_first_claim()
    {
        // No lease row exists yet, so every node takes the insert path at once. The primary key decides.
        var claims = await Task.WhenAll(
            Enumerable.Range(0, 6).Select(i => Task.Run(async () =>
            {
                try
                {
                    return await NewLeases().TryAcquireAsync(99, $"node-{i}", TimeSpan.FromMinutes(2));
                }
                catch (DbUpdateException)
                {
                    return false;
                }
            })));

        Assert.Equal(1, claims.Count(won => won));
    }

    // -- helpers -----------------------------------------------------------------------------

    private EfCheckpointStore NewCheckpoints() => new(_database.NewContext(), _clock);

    private EfRuleLeaseStore NewLeases() => new(_database.NewContext(), _clock);

    private static EvaluationOutcome Outcome(
        int ruleId,
        DateTimeOffset checkpoint,
        int windows = 1,
        int alerts = 0,
        long durationMs = 10,
        string? error = null) =>
        new(ruleId, windows, alerts, alerts, 0, 0, 0, 0, checkpoint, false, durationMs, error);

    private sealed class FixedClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }
}
