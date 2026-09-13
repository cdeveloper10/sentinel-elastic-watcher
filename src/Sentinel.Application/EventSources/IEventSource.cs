using Sentinel.Domain.Connections;

namespace Sentinel.Application.EventSources;

/// <summary>
/// Everything the platform needs from a place events are stored.
///
/// The detection engine talks to this and to nothing else, which is the point: the engine's job is
/// "does this condition hold", and it must stay answerable without knowing that the answer currently
/// comes from Elasticsearch. A second source added later implements this interface and the engine is
/// untouched.
///
/// Note what is absent. There is no "run this raw query and give me everything" method: counting is done
/// by <see cref="CountByGroupAsync"/> so the source can aggregate server-side, and document retrieval is
/// bounded everywhere it appears. An engine that pulled documents back to count them in memory would fall
/// over on the first busy index.
/// </summary>
public interface IEventSource
{
    /// <summary>Which <see cref="ConnectionType"/> this implementation serves.</summary>
    string SourceType { get; }

    /// <summary>Is it reachable, and what version is it. Used by the connection test button.</summary>
    Task<SourceProbe> ProbeAsync(Connection connection, CancellationToken ct = default);

    /// <summary>Concrete indices behind a pattern, so the rule builder can show what a pattern resolves to.</summary>
    Task<IReadOnlyList<IndexDescriptor>> ListIndicesAsync(
        Connection connection, string pattern, CancellationToken ct = default);

    /// <summary>
    /// Fields available across the given patterns, flattened. This is what turns the rule builder from a
    /// set of text boxes into something that can offer real field names and refuse impossible group-bys.
    /// </summary>
    Task<FieldCatalog> DescribeFieldsAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, CancellationToken ct = default);

    /// <summary>A bounded sample of what a query matches, for preview and dry run. Never unbounded.</summary>
    Task<QueryPreview> PreviewAsync(
        Connection connection,
        IReadOnlyList<string> indexPatterns,
        string queryJson,
        TimeRange range,
        string timestampField,
        int sampleSize,
        CancellationToken ct = default);

    /// <summary>
    /// Counts matching events per group inside a window, server-side. The detection engine's only
    /// question, and the reason it never needs to see a document to decide.
    /// </summary>
    /// <param name="minCount">
    /// Groups below this are not returned at all. Passing the rule's threshold here is what keeps the query
    /// cheap on a busy index: the source discards the millions of addresses with one failed login each and
    /// returns only the handful that could possibly trigger, instead of shipping every bucket back to be
    /// filtered here.
    /// </param>
    /// <param name="maxGroups">
    /// Ceiling on buckets returned. Reaching it sets <see cref="GroupCountResult.Truncated"/>, which the
    /// engine has to treat as "there were more" rather than as a complete answer.
    /// </param>
    Task<GroupCountResult> CountByGroupAsync(
        Connection connection,
        IReadOnlyList<string> indexPatterns,
        string queryJson,
        TimeRange range,
        string timestampField,
        IReadOnlyList<string> groupByFields,
        long minCount,
        int maxGroups,
        CancellationToken ct = default);
}
