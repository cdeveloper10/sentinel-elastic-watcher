using Microsoft.EntityFrameworkCore;
using Sentinel.Application.Engine;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Engine;

/// <summary>
/// An engine saying that it is alive, and what it is enforcing.
///
/// This exists because of the worst failure the console had: it could not tell a running engine from a
/// stopped one. It read the tick interval and the never-act list out of the *API's* configuration, and the
/// API evaluates nothing and blocks nothing — so a crashed engine, an unscheduled pod, or one that could
/// not reach the database looked exactly like a healthy platform with nothing to report.
///
/// For a system whose entire purpose is noticing things, being unable to notice that it has stopped
/// noticing is the failure that matters most.
/// </summary>
public class EngineHeartbeatTests : IDisposable
{
    private readonly TestDatabase _database = new();

    public void Dispose() => _database.Dispose();

    private static EngineHeartbeat Beat(
        string node = "engine-0",
        bool actionsEnabled = true,
        int neverAct = 2,
        int rules = 3) => new(
        node,
        new DateTimeOffset(2026, 9, 10, 9, 0, 0, TimeSpan.Zero),
        "1.0.0",
        Enabled: true,
        TickSeconds: 10,
        MaxConcurrentRules: 4,
        ActionsEnabled: actionsEnabled,
        NeverActEntries: neverAct,
        RulesEvaluated: rules,
        AlertsRaised: 1,
        DurationMs: 42);

    [Fact]
    public async Task A_node_that_reports_appears()
    {
        await using var context = _database.NewContext();
        await new EfEngineNodeStore(context).ReportAsync(Beat());

        await using var reader = _database.NewContext();
        var node = Assert.Single(await reader.EngineNodes.ToListAsync());

        Assert.Equal("engine-0", node.NodeId);
        Assert.Equal(4, node.MaxConcurrentRules);
        Assert.Equal(3, node.LastTickRulesEvaluated);
        Assert.True(node.ActionsEnabled);
    }

    [Fact]
    public async Task Reporting_again_updates_the_row_rather_than_adding_one()
    {
        // A node reports after every tick — every ten seconds by default. Inserting each time would be a
        // row per tick per pod for ever.
        await using var context = _database.NewContext();
        var store = new EfEngineNodeStore(context);

        await store.ReportAsync(Beat(rules: 3));
        await store.ReportAsync(Beat(rules: 7));

        await using var reader = _database.NewContext();
        var node = Assert.Single(await reader.EngineNodes.ToListAsync());

        Assert.Equal(7, node.LastTickRulesEvaluated);
    }

    [Fact]
    public async Task The_start_time_survives_later_reports()
    {
        // How long this process has been up, which is how a crash loop is recognised: a node whose start
        // time keeps moving is restarting.
        await using var context = _database.NewContext();
        var store = new EfEngineNodeStore(context);

        await store.ReportAsync(Beat());
        var started = (await context.EngineNodes.AsNoTracking().SingleAsync()).StartedAt;

        await store.ReportAsync(Beat(rules: 9));

        await using var reader = _database.NewContext();
        Assert.Equal(started, (await reader.EngineNodes.SingleAsync()).StartedAt);
    }

    [Fact]
    public async Task Two_engines_each_get_their_own_row()
    {
        // The point of reporting per node rather than one platform-wide status: two pods can disagree
        // about their configuration, and that disagreement is what somebody needs to see.
        await using var context = _database.NewContext();
        var store = new EfEngineNodeStore(context);

        await store.ReportAsync(Beat("engine-0", actionsEnabled: true, neverAct: 2));
        await store.ReportAsync(Beat("engine-1", actionsEnabled: false, neverAct: 0));

        await using var reader = _database.NewContext();
        var nodes = await reader.EngineNodes.OrderBy(n => n.NodeId).ToListAsync();

        Assert.Equal(2, nodes.Count);
        Assert.True(nodes[0].ActionsEnabled);
        Assert.False(nodes[1].ActionsEnabled);
        Assert.Equal(0, nodes[1].NeverActEntries);
    }

    [Fact]
    public async Task A_node_that_has_been_silent_long_enough_is_swept()
    {
        // A Kubernetes pod is replaced under a new name, so its row would otherwise stay for ever and the
        // list of live engines would fill with ghosts.
        await using var context = _database.NewContext();
        var store = new EfEngineNodeStore(context);

        await store.ReportAsync(Beat("old-pod"));

        var stale = await context.EngineNodes.SingleAsync(n => n.NodeId == "old-pod");
        stale.LastSeenAt = DateTime.UtcNow.AddDays(-3);
        await context.SaveChangesAsync();

        await using var sweeper = _database.NewContext();
        var removed = await new EfEngineNodeStore(sweeper).SweepAsync(TimeSpan.FromDays(1));

        Assert.Equal(1, removed);

        await using var reader = _database.NewContext();
        Assert.Empty(await reader.EngineNodes.ToListAsync());
    }

    [Fact]
    public async Task A_node_that_reported_recently_is_left_alone()
    {
        await using var context = _database.NewContext();
        await new EfEngineNodeStore(context).ReportAsync(Beat("live-pod"));

        await using var sweeper = _database.NewContext();
        Assert.Equal(0, await new EfEngineNodeStore(sweeper).SweepAsync(TimeSpan.FromDays(1)));

        await using var reader = _database.NewContext();
        Assert.Single(await reader.EngineNodes.ToListAsync());
    }
}
