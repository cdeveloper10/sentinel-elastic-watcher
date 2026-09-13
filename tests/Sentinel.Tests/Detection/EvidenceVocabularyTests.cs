using Sentinel.Application.Actions;
using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Detection;

/// <summary>
/// What a strategy says its alerts carry, against what they carry.
///
/// A strategy declares its evidence names so the rule builder can offer them and the API can reject a typo
/// at save time. A declaration that has drifted from the dictionary is worse than none: it would offer an
/// author a placeholder that renders blank, and reject one that would have worked. There is no clever
/// construction preventing the drift — these tests are what prevents it.
/// </summary>
public class EvidenceVocabularyTests
{
    private static readonly TimeRange Window = new(
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero));

    [Fact]
    public async Task The_threshold_strategy_produces_exactly_what_it_declares()
    {
        var strategy = new ThresholdDetectionStrategy();
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await strategy.EvaluateAsync(
            new StrategyRequest(TestRules.BruteForce(threshold: 20), TestConnections.Elasticsearch(), Window),
            source);

        var candidate = Assert.Single(result.Candidates);

        Assert.Equal(
            strategy.EvidenceKeys.Order(),
            candidate.Evidence.Keys.Order());
    }

    [Fact]
    public async Task The_match_strategy_produces_exactly_what_it_declares()
    {
        var strategy = new MatchDetectionStrategy();

        var source = new FakeEventSource()
            .WithDocument(("source.ip", "10.0.0.1"), ("@timestamp", "2026-01-15T10:01:00Z"));

        var result = await strategy.EvaluateAsync(
            new StrategyRequest(
                TestRules.BruteForce(threshold: 1) with { StrategyType = DetectionStrategyType.Match },
                TestConnections.Elasticsearch(),
                Window),
            source);

        var candidate = Assert.Single(result.Candidates);

        Assert.Equal(
            strategy.EvidenceKeys.Order(),
            candidate.Evidence.Keys.Order());
    }

    [Fact]
    public void A_rule_s_vocabulary_is_what_its_own_strategy_and_grouping_provide()
    {
        var registry = new DetectionStrategyRegistry(
            [new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]);

        var rule = TestRules.BruteForce(threshold: 10) with { GroupBy = ["ApiName.keyword"] };

        var paths = RuleVocabulary.For(rule, registry);

        Assert.Contains("event.ApiName.keyword", paths);
        Assert.Contains("evidence.eventCount", paths);
        Assert.Contains("subject", paths);
        Assert.Contains("message", paths);

        // A field the rule does not group by is not offered, because an alert from this rule has no such
        // value — offering it would be the platform promising something the rule cannot deliver.
        Assert.DoesNotContain("event.SourceIP.keyword", paths);
    }

    [Fact]
    public void A_match_rule_is_not_offered_a_count_it_never_produces()
    {
        var registry = new DetectionStrategyRegistry(
            [new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]);

        var rule = TestRules.BruteForce(threshold: 1) with
        {
            StrategyType = DetectionStrategyType.Match,
            GroupBy = []
        };

        var paths = RuleVocabulary.For(rule, registry);

        Assert.Contains("evidence.matchedEvent", paths);
        Assert.DoesNotContain("evidence.eventCount", paths);
        Assert.DoesNotContain("evidence.threshold", paths);
    }
}
