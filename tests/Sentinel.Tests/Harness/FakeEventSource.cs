using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Rules;

namespace Sentinel.Tests.Harness;

/// <summary>
/// A source whose answers are set by the test.
///
/// Strategies are judged on what they ask for and what they do with the reply, and both are visible here:
/// the recorded call carries the threshold that was pushed down and the group-by that was requested, which
/// is where the interesting behaviour of the threshold strategy actually lives.
/// </summary>
public sealed class FakeEventSource : IEventSource
{
    public string SourceType => ConnectionType.Elasticsearch;

    public List<GroupCount> Groups { get; } = [];
    public bool GroupsTruncated { get; set; }

    public List<IReadOnlyDictionary<string, object?>> Documents { get; } = [];
    public long TotalMatched { get; set; }
    public bool TotalIsLowerBound { get; set; }

    public Exception? Throws { get; set; }

    /// <summary>Runs when a count is asked for, so a test can interrupt the engine mid-evaluation.</summary>
    public Action? OnQuery { get; set; }

    public List<CountCall> CountCalls { get; } = [];
    public List<PreviewCall> PreviewCalls { get; } = [];

    public sealed record CountCall(
        IReadOnlyList<string> IndexPatterns,
        TimeRange Window,
        IReadOnlyList<string> GroupBy,
        long MinCount,
        int MaxGroups);

    public sealed record PreviewCall(TimeRange Window, int SampleSize);

    public FakeEventSource WithGroup(string field, string value, long count)
    {
        Groups.Add(new GroupCount(new Dictionary<string, string> { [field] = value }, count));
        return this;
    }

    public FakeEventSource WithDocument(params (string Field, object? Value)[] fields)
    {
        Documents.Add(fields.ToDictionary(f => f.Field, f => f.Value, StringComparer.Ordinal));
        TotalMatched = Documents.Count;
        return this;
    }

    public Task<GroupCountResult> CountByGroupAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, string queryJson, TimeRange range,
        string timestampField, IReadOnlyList<string> groupByFields, long minCount, int maxGroups,
        CancellationToken ct = default)
    {
        CountCalls.Add(new CountCall(indexPatterns, range, groupByFields, minCount, maxGroups));
        OnQuery?.Invoke();
        ct.ThrowIfCancellationRequested();

        if (Throws is not null)
            throw Throws;

        // Honour the floor, the way a real source would, so a strategy that leaned on it is not
        // accidentally rewarded by a fake that returns everything.
        var groups = Groups.Where(g => g.Count >= minCount).Take(maxGroups).ToList();

        return Task.FromResult(new GroupCountResult(groups, GroupsTruncated, 7));
    }

    public Task<QueryPreview> PreviewAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, string queryJson, TimeRange range,
        string timestampField, int sampleSize, CancellationToken ct = default)
    {
        PreviewCalls.Add(new PreviewCall(range, sampleSize));

        if (Throws is not null)
            throw Throws;

        var documents = Documents.Take(sampleSize).ToList();

        return Task.FromResult(new QueryPreview(
            Math.Max(TotalMatched, documents.Count), TotalIsLowerBound, documents, 5));
    }

    public Task<SourceProbe> ProbeAsync(Connection connection, CancellationToken ct = default) =>
        Task.FromResult(new SourceProbe(true, "Connected.", "8.13.4", "test"));

    public Task<IReadOnlyList<IndexDescriptor>> ListIndicesAsync(
        Connection connection, string pattern, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<IndexDescriptor>>([]);

    public Task<FieldCatalog> DescribeFieldsAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, CancellationToken ct = default) =>
        Task.FromResult(new FieldCatalog([], []));
}

/// <summary>Rule definitions for tests, defaulting to the brief's brute-force example.</summary>
public static class TestRules
{
    public static RuleDefinition BruteForce(
        string strategy = DetectionStrategyType.Threshold,
        long threshold = 20,
        string[]? groupBy = null,
        int windowSeconds = 300,
        int intervalSeconds = 60,
        int cooldownSeconds = 1800,
        string query = """{"term":{"event.type":"authentication_failed"}}""",
        RuleActionBinding[]? actions = null) => new(
        RuleId: 1,
        Version: 3,
        Name: "Brute Force Detection",
        Description: "More than twenty failed logins from one address in five minutes.",
        Severity: Severity.High,
        ConnectionId: 1,
        IndexPatterns: ["gateway-logs-*"],
        QueryJson: query,
        TimestampField: "@timestamp",
        StrategyType: strategy,
        GroupBy: groupBy ?? ["source.ip"],
        Threshold: threshold,
        Window: TimeSpan.FromSeconds(windowSeconds),
        QueryDelay: TimeSpan.FromSeconds(30),
        Interval: TimeSpan.FromSeconds(intervalSeconds),
        Cooldown: TimeSpan.FromSeconds(cooldownSeconds),
        Actions: actions ?? []);
}
