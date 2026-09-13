using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Persistence;

/// <summary>
/// The guarantees that are database constraints rather than code.
///
/// Deduplication and action idempotency both come down to a unique index. Everything above them — the
/// pipeline's fingerprint, the dispatcher's claim — is arrangement; the index is the mechanism. These
/// tests run against a real relational engine for exactly that reason, and each concurrent writer gets
/// its own <c>DbContext</c>, because a second insert caught by the change tracker proves nothing about a
/// second insert arriving from another node.
/// </summary>
public class StoreTests : IDisposable
{
    private readonly TestDatabase _database = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero));

    public void Dispose() => _database.Dispose();

    // -- deduplication -----------------------------------------------------------------------

    [Fact]
    public async Task An_alert_is_recorded_once()
    {
        var first = await NewAlertStore().TryInsertAsync(Alert("fp-1"));

        Assert.True(first);
        Assert.Single(await AllAlerts());
    }

    [Fact]
    public async Task The_same_fingerprint_from_another_node_is_refused()
    {
        // Two contexts: this is the race the unique index exists to settle. A read-then-write would have
        // both callers believe they were first, and one detection would become two alerts — each with its
        // own dispatch, each blocking the same address.
        Assert.True(await NewAlertStore().TryInsertAsync(Alert("fp-shared")));
        Assert.False(await NewAlertStore().TryInsertAsync(Alert("fp-shared")));

        Assert.Single(await AllAlerts());
    }

    [Fact]
    public async Task Concurrent_inserts_of_one_fingerprint_produce_one_alert()
    {
        var attempts = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(async () =>
            {
                try
                {
                    return await NewAlertStore().TryInsertAsync(Alert("fp-race"));
                }
                catch (DbUpdateException)
                {
                    // SQLite serialises writers by locking rather than by returning a constraint error, so
                    // a loser here may surface as a write failure instead. Either outcome is "not mine".
                    return false;
                }
            }))
            .ToList();

        var results = await Task.WhenAll(attempts);

        Assert.Equal(1, results.Count(won => won));
        Assert.Single(await AllAlerts());
    }

    [Fact]
    public async Task Different_fingerprints_are_separate_alerts()
    {
        await NewAlertStore().TryInsertAsync(Alert("fp-a"));
        await NewAlertStore().TryInsertAsync(Alert("fp-b"));

        Assert.Equal(2, (await AllAlerts()).Count);
    }

    [Fact]
    public async Task A_write_that_breaks_a_different_constraint_is_not_mistaken_for_a_duplicate()
    {
        // Swallowing every DbUpdateException as "already recorded" would turn a genuine failure into
        // silence, and silence is the failure mode this platform cannot have. Here the fingerprints
        // differ and the *alert id* collides — a real fault, and one the store has to let through.
        var first = Alert("fp-one");
        first.AlertId = "collides";
        Assert.True(await NewAlertStore().TryInsertAsync(first));

        var second = Alert("fp-two");
        second.AlertId = "collides";

        await Assert.ThrowsAsync<DbUpdateException>(() => NewAlertStore().TryInsertAsync(second));
        Assert.Single(await AllAlerts());
    }

    // -- action idempotency ------------------------------------------------------------------

    [Fact]
    public async Task An_action_is_claimed_once()
    {
        var alert = await InsertAlert("fp-claim");

        Assert.True(await NewExecutionStore().TryClaimAsync(Execution(alert.Id, "key-1")));
        Assert.False(await NewExecutionStore().TryClaimAsync(Execution(alert.Id, "key-1")));

        Assert.Single(await AllExecutions());
    }

    [Fact]
    public async Task Two_nodes_dispatching_one_alert_block_the_address_once()
    {
        // The end-to-end statement of the guarantee, at the layer that actually enforces it.
        var alert = await InsertAlert("fp-two-nodes");

        var claims = await Task.WhenAll(
            Enumerable.Range(0, 6).Select(_ => Task.Run(async () =>
            {
                try
                {
                    return await NewExecutionStore().TryClaimAsync(Execution(alert.Id, "shared-key"));
                }
                catch (DbUpdateException)
                {
                    return false;
                }
            })));

        Assert.Equal(1, claims.Count(won => won));
    }

    [Fact]
    public async Task Different_actions_on_one_alert_are_claimed_separately()
    {
        // Blocking and notifying are two actions on one alert; sharing a key would let the first silence
        // the second.
        var alert = await InsertAlert("fp-multi");

        Assert.True(await NewExecutionStore().TryClaimAsync(Execution(alert.Id, "key-block", "block_ip")));
        Assert.True(await NewExecutionStore().TryClaimAsync(Execution(alert.Id, "key-sms", "sms")));

        Assert.Equal(2, (await AllExecutions()).Count);
    }

    [Fact]
    public async Task A_claimed_execution_can_be_advanced_through_its_states()
    {
        var alert = await InsertAlert("fp-update");
        var execution = Execution(alert.Id, "key-update");

        await NewExecutionStore().TryClaimAsync(execution);

        execution.Status = ActionExecutionStatus.Success;
        execution.DurationMs = 125;
        execution.FinishedAt = _clock.GetUtcNow().UtcDateTime;
        await NewExecutionStore().UpdateAsync(execution);

        var stored = Assert.Single(await AllExecutions());
        Assert.Equal(ActionExecutionStatus.Success, stored.Status);
        Assert.Equal(125, stored.DurationMs);
    }

    // -- cooldown ----------------------------------------------------------------------------

    [Fact]
    public async Task A_subject_that_has_not_fired_has_no_cooldown() =>
        Assert.Null(await NewCooldownStore().LastFiredAtAsync("rule:1|ip:10.0.0.1"));

    [Fact]
    public async Task A_recorded_subject_is_in_cooldown_until_it_expires()
    {
        const string key = "rule:1|ip:10.0.0.1";
        var now = _clock.GetUtcNow();

        await NewCooldownStore().RecordAsync(key, now, TimeSpan.FromMinutes(30));

        Assert.NotNull(await NewCooldownStore().LastFiredAtAsync(key));

        // An expired row reads as absent rather than waiting for the sweeper, so suppression ends when it
        // should rather than whenever cleanup last ran.
        _clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Null(await NewCooldownStore().LastFiredAtAsync(key));
    }

    [Fact]
    public async Task Cooldown_survives_a_restart()
    {
        // Losing these on a deploy would release every suppressed subject at once — a rolling update
        // turning into a wave of blocks.
        const string key = "rule:1|ip:10.0.0.1";
        await NewCooldownStore().RecordAsync(key, _clock.GetUtcNow(), TimeSpan.FromMinutes(30));

        // A new store over a new context is what the process gets after restarting.
        Assert.NotNull(await NewCooldownStore().LastFiredAtAsync(key));
    }

    [Fact]
    public async Task Recording_the_same_subject_again_moves_the_window_rather_than_failing()
    {
        const string key = "rule:1|ip:10.0.0.1";

        await NewCooldownStore().RecordAsync(key, _clock.GetUtcNow(), TimeSpan.FromMinutes(5));
        _clock.Advance(TimeSpan.FromMinutes(4));
        await NewCooldownStore().RecordAsync(key, _clock.GetUtcNow(), TimeSpan.FromMinutes(5));

        _clock.Advance(TimeSpan.FromMinutes(2)); // Past the first expiry, inside the second.
        Assert.NotNull(await NewCooldownStore().LastFiredAtAsync(key));
    }

    [Fact]
    public async Task Expired_cooldowns_are_swept()
    {
        await NewCooldownStore().RecordAsync("old", _clock.GetUtcNow(), TimeSpan.FromMinutes(1));
        await NewCooldownStore().RecordAsync("fresh", _clock.GetUtcNow(), TimeSpan.FromHours(2));

        _clock.Advance(TimeSpan.FromMinutes(5));

        Assert.Equal(1, await NewCooldownStore().SweepAsync());
        await using var context = _database.NewContext();
        Assert.Single(await context.Cooldowns.ToListAsync());
    }

    // -- action rate caps --------------------------------------------------------------------

    [Fact]
    public async Task Counting_starts_at_one_and_accumulates()
    {
        var store = NewRateStore();
        var window = TimeSpan.FromMinutes(1);

        Assert.Equal(1, await store.IncrementAsync("rule:1", window));
        Assert.Equal(2, await store.IncrementAsync("rule:1", window));
        Assert.Equal(3, await store.IncrementAsync("rule:1", window));
    }

    [Fact]
    public async Task The_count_resets_when_the_window_passes()
    {
        var window = TimeSpan.FromMinutes(1);

        await NewRateStore().IncrementAsync("rule:1", window);
        await NewRateStore().IncrementAsync("rule:1", window);

        _clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(1, await NewRateStore().IncrementAsync("rule:1", window));
    }

    [Fact]
    public async Task Counts_survive_a_restart()
    {
        // A cap that resets on deploy is not a cap: a crash-looping pod would block without limit.
        var window = TimeSpan.FromMinutes(10);

        await NewRateStore().IncrementAsync("rule:7", window);
        await NewRateStore().IncrementAsync("rule:7", window);

        Assert.Equal(2, await NewRateStore().CurrentAsync("rule:7"));
    }

    [Fact]
    public async Task Rules_are_counted_apart()
    {
        var window = TimeSpan.FromMinutes(1);

        await NewRateStore().IncrementAsync("rule:1", window);
        await NewRateStore().IncrementAsync("rule:1", window);
        await NewRateStore().IncrementAsync("rule:2", window);

        Assert.Equal(2, await NewRateStore().CurrentAsync("rule:1"));
        Assert.Equal(1, await NewRateStore().CurrentAsync("rule:2"));
    }

    [Fact]
    public async Task An_expired_counter_reads_as_zero()
    {
        await NewRateStore().IncrementAsync("rule:1", TimeSpan.FromSeconds(30));
        _clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(0, await NewRateStore().CurrentAsync("rule:1"));
    }

    // -- connections -------------------------------------------------------------------------

    [Fact]
    public async Task A_connection_is_found_by_the_name_a_rule_uses()
    {
        await using (var seed = _database.NewContext())
        {
            seed.Connections.Add(new Connection
            {
                Name = "security-api",
                Type = ConnectionType.SecurityApi,
                Endpoint = "https://gateway.internal:5302",
                Enabled = true
            });
            await seed.SaveChangesAsync();
        }

        await using var context = _database.NewContext();
        var found = await new EfConnectionLookup(context).ByNameAsync("security-api");

        Assert.NotNull(found);
        Assert.Equal(ConnectionType.SecurityApi, found.Type);
        Assert.Null(await new EfConnectionLookup(context).ByNameAsync("does-not-exist"));
    }

    [Fact]
    public async Task Two_connections_cannot_share_a_name()
    {
        // Rules refer to a connection by name; two with one name would make that reference ambiguous.
        await using var context = _database.NewContext();

        context.Connections.Add(new Connection { Name = "dup", Type = ConnectionType.Sms, Endpoint = "https://a" });
        context.Connections.Add(new Connection { Name = "dup", Type = ConnectionType.Sms, Endpoint = "https://b" });

        await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
    }

    // -- helpers -----------------------------------------------------------------------------

    private EfAlertStore NewAlertStore() =>
        new(_database.NewContext(), NullLogger<EfAlertStore>.Instance);

    private EfActionExecutionStore NewExecutionStore() =>
        new(_database.NewContext(), NullLogger<EfActionExecutionStore>.Instance);

    private EfCooldownStore NewCooldownStore() => new(_database.NewContext(), _clock);

    private EfActionRateStore NewRateStore() => new(_database.NewContext(), _clock);

    private async Task<List<Alert>> AllAlerts()
    {
        await using var context = _database.NewContext();
        return await context.Alerts.AsNoTracking().ToListAsync();
    }

    private async Task<List<ActionExecution>> AllExecutions()
    {
        await using var context = _database.NewContext();
        return await context.ActionExecutions.AsNoTracking().ToListAsync();
    }

    private async Task<Alert> InsertAlert(string fingerprint)
    {
        var alert = Alert(fingerprint);
        await NewAlertStore().TryInsertAsync(alert);
        return alert;
    }

    private Alert Alert(string fingerprint) => new()
    {
        AlertId = Guid.NewGuid().ToString("n")[..16],
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
        WindowFrom = _clock.GetUtcNow().AddMinutes(-5).UtcDateTime,
        WindowTo = _clock.GetUtcNow().UtcDateTime,
        DetectedAt = _clock.GetUtcNow().UtcDateTime
    };

    private ActionExecution Execution(long alertId, string key, string actionType = "block_ip") => new()
    {
        AlertId = alertId,
        RuleId = 1,
        RuleVersion = 1,
        ActionType = actionType,
        ConnectionName = "security-api",
        IdempotencyKey = key,
        Status = ActionExecutionStatus.Pending,
        Target = "10.10.10.20",
        CreatedAt = _clock.GetUtcNow().UtcDateTime
    };

    private sealed class FixedClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }
}
