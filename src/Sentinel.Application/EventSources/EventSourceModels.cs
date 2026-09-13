namespace Sentinel.Application.EventSources;

/// <summary>Answer to "is this source reachable, and what is it".</summary>
public sealed record SourceProbe(
    bool Reachable,
    string Message,
    string? Version = null,
    string? ClusterName = null,
    long ElapsedMs = 0);

/// <summary>One concrete index behind a pattern, with enough detail to tell a live index from an archived one.</summary>
public sealed record IndexDescriptor(string Name, long DocumentCount, long SizeBytes, string Health);

/// <summary>
/// A field a rule can refer to, flattened out of the source's mapping.
///
/// <paramref name="Aggregatable"/> is the one the rule builder cares about most: grouping by an analysed
/// text field either fails or silently groups by token, so the UI has to be able to offer only the fields
/// that can actually carry a group-by.
/// </summary>
public sealed record FieldDescriptor(string Path, string Type, bool Aggregatable, bool Searchable)
{
    /// <summary>True for a field that can carry a time window, so the UI can offer a timestamp field.</summary>
    public bool IsTimestamp => Type is "date" or "date_nanos";
}

public sealed record FieldCatalog(IReadOnlyList<FieldDescriptor> Fields, IReadOnlyList<string> IndicesInspected)
{
    public IEnumerable<FieldDescriptor> Groupable => Fields.Where(f => f.Aggregatable);
    public IEnumerable<FieldDescriptor> Timestamps => Fields.Where(f => f.IsTimestamp);
}

/// <summary>A bounded look at what a query matches, for the rule builder to show before anything is saved.</summary>
public sealed record QueryPreview(
    long TotalMatched,
    bool TotalIsLowerBound,
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Samples,
    long ElapsedMs);

/// <summary>
/// The window a detection run asks about. Half-open — <c>[From, To)</c> — so consecutive runs cannot both
/// claim an event that lands exactly on the boundary.
/// </summary>
public sealed record TimeRange(DateTimeOffset From, DateTimeOffset To)
{
    public TimeSpan Duration => To - From;

    public static TimeRange EndingAt(DateTimeOffset end, TimeSpan length) => new(end - length, end);
}

/// <summary>
/// One group, how many events it had, and one of those events.
///
/// The count is all a threshold needs in order to decide. The sample is what a message and a payload need
/// in order to be useful: "AiServices returned 14 HTTP 500s" says that something happened, and the log
/// line that came with it says what — which user, which path, which backend. It costs no extra round trip,
/// because it arrives from the same aggregation as a <c>top_hits</c> sub-aggregation rather than as a
/// second query.
///
/// One event, not all of them, and the name says so wherever it surfaces: a threshold rule fires because
/// of many events and this is the most recent of them.
/// </summary>
public sealed record GroupCount(
    IReadOnlyDictionary<string, string> Key,
    long Count,
    IReadOnlyDictionary<string, string>? Sample = null);

public sealed record GroupCountResult(
    IReadOnlyList<GroupCount> Groups,
    bool Truncated,
    long ElapsedMs);
