using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Detection;

/// <summary>
/// The two strategies that cover the brief's five.
///
/// The threshold strategy's interesting behaviour is not the comparison — it is what it asks the source
/// for. Pushing the threshold down as a floor is the difference between a query that works on a busy
/// index and one that ships every distinct address back to be filtered in memory.
/// </summary>
public class ThresholdDetectionStrategyTests
{
    private static readonly TimeRange Window = new(
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero));

    private readonly ThresholdDetectionStrategy _strategy = new();

    // -- evaluation --------------------------------------------------------------------------

    [Fact]
    public async Task A_subject_over_the_threshold_becomes_a_candidate()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var result = await Evaluate(source, TestRules.BruteForce(threshold: 20));

        var candidate = Assert.Single(result.Candidates);
        Assert.Equal("10.10.10.20", candidate.Subject["source.ip"]);
        Assert.Equal(31, candidate.EventCount);
    }

    [Fact]
    public async Task The_threshold_is_pushed_into_the_query_rather_than_applied_afterwards()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        await Evaluate(source, TestRules.BruteForce(threshold: 20));

        var call = Assert.Single(source.CountCalls);
        Assert.Equal(20, call.MinCount);
        Assert.Equal(["source.ip"], call.GroupBy);
    }

    [Fact]
    public async Task Exactly_the_threshold_counts_as_reaching_it()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.0.0.1", 20);

        Assert.Single((await Evaluate(source, TestRules.BruteForce(threshold: 20))).Candidates);
    }

    [Fact]
    public async Task The_strategy_still_checks_the_count_it_was_given()
    {
        // The source honoured the floor, but the decision is the strategy's and is not delegated: a source
        // that ignored min_doc_count would otherwise silently lower every rule's threshold to one.
        var source = new FakeEventSource();
        source.Groups.Add(new GroupCount(new Dictionary<string, string> { ["source.ip"] = "10.0.0.1" }, 5));

        var result = await _strategy.EvaluateAsync(
            new StrategyRequest(TestRules.BruteForce(threshold: 20), TestConnections.Elasticsearch(), Window),
            new IgnoresFloorSource(source));

        Assert.Empty(result.Candidates);
    }

    [Fact]
    public async Task Several_subjects_each_become_their_own_candidate()
    {
        var source = new FakeEventSource()
            .WithGroup("source.ip", "10.0.0.1", 44)
            .WithGroup("source.ip", "10.0.0.2", 21);

        Assert.Equal(2, (await Evaluate(source, TestRules.BruteForce(threshold: 20))).Candidates.Count);
    }

    [Fact]
    public async Task Truncation_from_the_source_is_carried_through()
    {
        // "At least four addresses crossed the threshold" is a different answer from "four did", and for a
        // system that blocks addresses the difference is the ones it missed.
        var source = new FakeEventSource { GroupsTruncated = true }.WithGroup("source.ip", "10.0.0.1", 99);

        Assert.True((await Evaluate(source, TestRules.BruteForce())).Truncated);
    }

    [Fact]
    public async Task The_evidence_says_what_was_counted_and_over_what_window()
    {
        var source = new FakeEventSource().WithGroup("source.ip", "10.10.10.20", 31);

        var candidate = Assert.Single((await Evaluate(source, TestRules.BruteForce(threshold: 20))).Candidates);

        Assert.Equal(31L, candidate.Evidence["eventCount"]);
        Assert.Equal(20L, candidate.Evidence["threshold"]);
        Assert.Equal("5m", candidate.Evidence["window"]);
    }

    [Fact]
    public async Task Subjects_returned_by_one_evaluation_are_capped()
    {
        var source = new FakeEventSource();
        for (var i = 0; i < 10; i++)
            source.WithGroup("source.ip", $"10.0.0.{i}", 50);

        await Evaluate(source, TestRules.BruteForce());

        Assert.Equal(ThresholdDetectionStrategy.MaxSubjectsPerEvaluation, source.CountCalls[0].MaxGroups);
    }

    // -- validation --------------------------------------------------------------------------

    [Fact]
    public void A_threshold_rule_without_a_group_by_is_refused()
    {
        // It counts per subject, so with nothing to group by there is no subject to act on.
        var result = _strategy.Validate(TestRules.BruteForce(groupBy: []));

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "groupBy");
    }

    [Fact]
    public void An_interval_longer_than_the_window_is_refused()
    {
        // The gap between them is time nobody ever looks at, in a system whose purpose is not to miss
        // things.
        var result = _strategy.Validate(TestRules.BruteForce(windowSeconds: 60, intervalSeconds: 300));

        Assert.False(result.IsValid);
        var failure = Assert.Single(result.Failures, f => f.Field == "interval");
        Assert.Contains("never be evaluated", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_interval_equal_to_the_window_is_allowed() =>
        Assert.True(_strategy.Validate(TestRules.BruteForce(windowSeconds: 300, intervalSeconds: 300)).IsValid);

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_threshold_below_one_is_refused(long threshold) =>
        Assert.False(_strategy.Validate(TestRules.BruteForce(threshold: threshold)).IsValid);

    [Fact]
    public void Too_many_group_by_fields_are_refused() =>
        Assert.False(_strategy
            .Validate(TestRules.BruteForce(groupBy: ["a", "b", "c", "d"]))
            .IsValid);

    [Fact]
    public void A_window_longer_than_a_day_is_refused() =>
        Assert.False(_strategy.Validate(TestRules.BruteForce(windowSeconds: 90_000)).IsValid);

    [Fact]
    public void The_brute_force_example_from_the_brief_validates() =>
        Assert.True(_strategy.Validate(TestRules.BruteForce()).IsValid);

    private Task<StrategyResult> Evaluate(FakeEventSource source, Sentinel.Application.Rules.RuleDefinition rule) =>
        _strategy.EvaluateAsync(new StrategyRequest(rule, TestConnections.Elasticsearch(), Window), source);

    /// <summary>A source that returns everything regardless of the floor, to prove the strategy still checks.</summary>
    private sealed class IgnoresFloorSource(FakeEventSource inner) : IEventSource
    {
        public string SourceType => inner.SourceType;

        public Task<GroupCountResult> CountByGroupAsync(
            Sentinel.Domain.Connections.Connection connection, IReadOnlyList<string> indexPatterns,
            string queryJson, TimeRange range, string timestampField, IReadOnlyList<string> groupByFields,
            long minCount, int maxGroups, CancellationToken ct = default) =>
            Task.FromResult(new GroupCountResult(inner.Groups, false, 1));

        public Task<SourceProbe> ProbeAsync(Sentinel.Domain.Connections.Connection c, CancellationToken ct = default) =>
            inner.ProbeAsync(c, ct);

        public Task<IReadOnlyList<IndexDescriptor>> ListIndicesAsync(
            Sentinel.Domain.Connections.Connection c, string p, CancellationToken ct = default) =>
            inner.ListIndicesAsync(c, p, ct);

        public Task<FieldCatalog> DescribeFieldsAsync(
            Sentinel.Domain.Connections.Connection c, IReadOnlyList<string> p, CancellationToken ct = default) =>
            inner.DescribeFieldsAsync(c, p, ct);

        public Task<QueryPreview> PreviewAsync(
            Sentinel.Domain.Connections.Connection c, IReadOnlyList<string> p, string q, TimeRange r,
            string t, int s, CancellationToken ct = default) =>
            inner.PreviewAsync(c, p, q, r, t, s, ct);
    }
}

public class MatchDetectionStrategyTests
{
    private static readonly TimeRange Window = new(
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero));

    private readonly MatchDetectionStrategy _strategy = new();

    [Fact]
    public async Task Every_matching_event_is_a_detection()
    {
        var source = new FakeEventSource()
            .WithDocument(("@timestamp", "2026-01-15T10:01:00Z"), ("user.name", "root"))
            .WithDocument(("@timestamp", "2026-01-15T10:02:00Z"), ("user.name", "admin"));

        var result = await Evaluate(source, TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: []));

        Assert.Equal(2, result.Candidates.Count);
        Assert.All(result.Candidates, c => Assert.Equal(1, c.EventCount));
    }

    [Fact]
    public async Task With_a_group_by_a_subject_is_reported_once_however_many_events_it_had()
    {
        // Reporting an address twenty times because twenty of its requests matched is noise, not twenty
        // findings.
        var source = new FakeEventSource()
            .WithDocument(("source.ip", "10.0.0.1"), ("@timestamp", "2026-01-15T10:01:00Z"))
            .WithDocument(("source.ip", "10.0.0.1"), ("@timestamp", "2026-01-15T10:02:00Z"))
            .WithDocument(("source.ip", "10.0.0.2"), ("@timestamp", "2026-01-15T10:03:00Z"));

        var result = await Evaluate(source, TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: ["source.ip"]));

        Assert.Equal(2, result.Candidates.Count);
    }

    [Fact]
    public async Task The_matched_document_is_kept_as_the_evidence()
    {
        // For a match rule the document is the whole finding, so it travels with the detection rather than
        // being fetched again later from an index that may have rolled over.
        var source = new FakeEventSource().WithDocument(
            ("@timestamp", "2026-01-15T10:01:00Z"), ("user.name", "root"), ("event.action", "user_created"));

        var candidate = Assert.Single((await Evaluate(source, TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: []))).Candidates);

        var document = Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(candidate.Evidence["matchedEvent"]);
        Assert.Equal("user_created", document["event.action"]);
    }

    [Fact]
    public async Task More_matches_than_were_retrieved_is_reported_as_truncation()
    {
        var source = new FakeEventSource { TotalMatched = 5_000, TotalIsLowerBound = true }
            .WithDocument(("@timestamp", "2026-01-15T10:01:00Z"));

        Assert.True((await Evaluate(source, TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: []))).Truncated);
    }

    [Fact]
    public async Task The_number_of_documents_one_evaluation_reads_is_bounded()
    {
        var source = new FakeEventSource().WithDocument(("@timestamp", "x"));

        await Evaluate(source, TestRules.BruteForce(strategy: DetectionStrategyType.Match, groupBy: []));

        Assert.Equal(MatchDetectionStrategy.MaxMatchesPerEvaluation, source.PreviewCalls[0].SampleSize);
    }

    [Fact]
    public void A_match_rule_without_a_query_is_refused()
    {
        // It fires on every event it finds, so with no query it would fire on all of them.
        var result = _strategy.Validate(TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: [], query: ""));

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "query");
    }

    [Fact]
    public void A_match_rule_needs_no_group_by() =>
        Assert.True(_strategy.Validate(TestRules.BruteForce(
            strategy: DetectionStrategyType.Match, groupBy: [])).IsValid);

    private Task<StrategyResult> Evaluate(FakeEventSource source, Sentinel.Application.Rules.RuleDefinition rule) =>
        _strategy.EvaluateAsync(new StrategyRequest(rule, TestConnections.Elasticsearch(), Window), source);
}

public class DetectionStrategyRegistryTests
{
    private static readonly IDetectionStrategyRegistry Registry =
        new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]);

    [Theory]
    [InlineData(DetectionStrategyType.Threshold)]
    [InlineData(DetectionStrategyType.Match)]
    [InlineData("THRESHOLD")]
    public void A_registered_strategy_resolves(string type) =>
        Assert.NotNull(Registry.Resolve(type));

    [Fact]
    public void An_unknown_strategy_names_what_is_available()
    {
        // The engine resolves by a string stored months ago; the failure has to say what it can accept.
        var error = Assert.Throws<UnknownStrategyException>(() => Registry.Resolve("spike"));

        Assert.Contains("threshold", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("spike", error.RequestedType);
    }

    [Fact]
    public void Resolution_can_be_attempted_without_throwing()
    {
        Assert.True(Registry.TryResolve(DetectionStrategyType.Match, out _));
        Assert.False(Registry.TryResolve("spike", out _));
        Assert.False(Registry.TryResolve(null, out _));
    }

    [Fact]
    public void An_empty_registry_is_a_composition_error_caught_at_startup() =>
        Assert.Throws<InvalidOperationException>(() => new DetectionStrategyRegistry([]));
}
