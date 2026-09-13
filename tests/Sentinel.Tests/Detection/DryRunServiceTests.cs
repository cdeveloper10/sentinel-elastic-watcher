using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Detection;

/// <summary>
/// What a rule would have done, without doing any of it.
///
/// The guarantee that nothing executes is structural: <see cref="DryRunService"/> has no dispatcher, no
/// action registry and no path to one. These cases check the behaviour an author relies on — and the last
/// one checks the shape of the class itself, because a guarantee that depends on every future provider
/// honouring a flag is how a platform eventually sends a real message from a test.
/// </summary>
public class DryRunServiceTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 15, 9, 0, 0, TimeSpan.Zero);
    private static readonly TimeRange LastHour = new(Start, Start.AddHours(1));

    private readonly DryRunService _dryRun = new(
        new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]));

    [Fact]
    public async Task It_reports_what_would_have_been_detected()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await Run(source, TestRules.BruteForce());

        Assert.True(result.Succeeded);
        Assert.NotEmpty(result.WouldDetect);
        Assert.Equal("10.10.10.20", result.WouldDetect[0].Subject["source.ip"]);
    }

    [Fact]
    public async Task It_counts_the_actions_that_would_have_run_without_running_them()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var rule = TestRules.BruteForce(actions: [
            new Sentinel.Application.Rules.RuleActionBinding("block_ip", "security-api", new Dictionary<string, string>()),
            new Sentinel.Application.Rules.RuleActionBinding("sms", "security-sms", new Dictionary<string, string>())
        ]);

        var result = await Run(source, rule);

        Assert.Equal(2, result.WouldExecute.Count);
        Assert.All(result.WouldExecute, a => Assert.Equal(result.WouldDetect.Count, a.WouldExecute));
        Assert.Contains(result.WouldExecute, a => a.Type == "block_ip");
    }

    [Fact]
    public async Task Cooldown_is_replayed_so_the_number_shown_is_what_would_really_have_happened()
    {
        // A rule looks alarming without cooldown and reasonable with it. The figure an author needs is how
        // many times it would actually have acted.
        //
        // The address qualifies in every one of the hour's overlapping windows. With a thirty-minute
        // cooldown it fires at the start, is suppressed for thirty minutes, and becomes eligible once
        // more — twice in an hour, not fifty-six times.
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await Run(source, TestRules.BruteForce(cooldownSeconds: 1800));

        Assert.Equal(2, result.WouldDetect.Count);
        Assert.Equal(TimeSpan.FromMinutes(30), result.WouldDetect[1].Window.To - result.WouldDetect[0].Window.To);
        Assert.NotEmpty(result.SuppressedByCooldown);
    }

    [Fact]
    public async Task A_cooldown_covering_the_whole_range_produces_one_detection()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await Run(source, TestRules.BruteForce(cooldownSeconds: 7200));

        Assert.Single(result.WouldDetect);
    }

    [Fact]
    public async Task Without_a_cooldown_every_qualifying_window_is_a_detection()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await Run(source, TestRules.BruteForce(cooldownSeconds: 0));

        Assert.True(result.WouldDetect.Count > 1);
        Assert.Empty(result.SuppressedByCooldown);
    }

    [Fact]
    public async Task It_walks_the_range_on_the_rules_own_schedule()
    {
        // One long window would reproduce a schedule the rule never keeps, and give a number that means
        // nothing.
        var source = new FakeEventSource();

        var result = await Run(source, TestRules.BruteForce(windowSeconds: 300, intervalSeconds: 60));

        Assert.True(result.WindowsEvaluated > 1);
        Assert.All(source.CountCalls, call => Assert.Equal(TimeSpan.FromMinutes(5), call.Window.Duration));
    }

    [Fact]
    public async Task A_long_range_is_capped_and_says_so()
    {
        var source = new FakeEventSource();

        var result = await _dryRun.RunAsync(
            TestRules.BruteForce(), TestConnections.Elasticsearch(), source,
            new TimeRange(Start, Start.AddDays(7)));

        Assert.Equal(DryRunService.MaxWindows, result.WindowsEvaluated);
        Assert.Contains("narrow the range", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_invalid_rule_is_reported_rather_than_evaluated()
    {
        // Dry run is where an author finds out, so the message has to be the validation message.
        var source = new FakeEventSource();

        var result = await Run(source, TestRules.BruteForce(groupBy: []));

        Assert.False(result.Succeeded);
        Assert.Contains("group by", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(source.CountCalls);
    }

    [Fact]
    public async Task An_unreachable_source_is_reported_rather_than_thrown()
    {
        var source = new FakeEventSource { Throws = new HttpRequestException("connection refused") };

        var result = await Run(source, TestRules.BruteForce());

        Assert.False(result.Succeeded);
        Assert.Contains("could not be queried", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_unknown_strategy_is_reported()
    {
        var rule = TestRules.BruteForce() with { StrategyType = "spike" };

        var result = await Run(new FakeEventSource(), rule);

        Assert.False(result.Succeeded);
        Assert.Contains("spike", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_range_that_ends_before_it_begins_is_refused()
    {
        var result = await _dryRun.RunAsync(
            TestRules.BruteForce(), TestConnections.Elasticsearch(), new FakeEventSource(),
            new TimeRange(Start.AddHours(1), Start));

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Truncation_reaches_the_author()
    {
        // "At least this many" is a different answer from "this many", and it is the author's cue that the
        // rule is too broad to act on.
        var source = new FakeEventSource { GroupsTruncated = true }.WithGroup("source.ip", "10.0.0.1", 99);

        var result = await Run(source, TestRules.BruteForce());

        Assert.True(result.Truncated);
        Assert.True(result.MatchedIsLowerBound);
    }

    [Fact]
    public void Nothing_in_a_dry_run_can_reach_an_action_provider()
    {
        // The guarantee is the absence of a path, not a flag somebody has to honour. If a dispatcher or an
        // action registry is ever taken as a dependency here, this fails and the reviewer is asked why.
        var dependencies = typeof(DryRunService)
            .GetConstructors()
            .SelectMany(c => c.GetParameters())
            .Select(p => p.ParameterType.Name)
            .ToList();

        Assert.All(dependencies, name =>
        {
            Assert.DoesNotContain("Dispatch", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Action", name, StringComparison.OrdinalIgnoreCase);
        });

        Assert.Equal(["IDetectionStrategyRegistry"], dependencies);
    }

    private Task<DryRunResult> Run(FakeEventSource source, Sentinel.Application.Rules.RuleDefinition rule) =>
        _dryRun.RunAsync(rule, TestConnections.Elasticsearch(), source, LastHour);
}
