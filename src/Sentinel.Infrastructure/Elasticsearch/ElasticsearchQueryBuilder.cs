using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Application.EventSources;

namespace Sentinel.Infrastructure.Elasticsearch;

/// <summary>
/// Builds the two search bodies the platform ever sends, and refuses to build anything else.
///
/// Two properties matter more than the shape of the JSON:
///
/// The author's query is <em>composed</em>, never concatenated. It is parsed into a node and placed as one
/// clause inside a bool filter. A query assembled by string interpolation would let a rule author who can
/// type into the query box add an <c>aggs</c> section, replace the time bound, or reach a different index.
///
/// Every query is bounded. The time range is added by this class, not by the author, so a rule cannot be
/// saved that reads the whole retention period on every evaluation. Counting happens through an
/// aggregation with <c>size: 0</c> — no documents come back to be counted here — and
/// <c>min_doc_count</c> carries the rule's own threshold into the query, so the source discards the groups
/// that could never trigger instead of shipping them.
/// </summary>
public static class ElasticsearchQueryBuilder
{
    /// <summary>Exact hit counts get expensive; past this the total is reported as a lower bound.</summary>
    public const int TrackTotalHitsUpTo = 10_000;

    public static string BuildPreview(
        string? queryJson,
        TimeRange range,
        string timestampField,
        int sampleSize)
    {
        var body = new JsonObject
        {
            ["size"] = Math.Clamp(sampleSize, 0, 100),
            ["track_total_hits"] = TrackTotalHitsUpTo,
            ["query"] = BoundedQuery(queryJson, range, timestampField),
            // Newest first: a preview is read to answer "what is arriving", not "what arrived first".
            ["sort"] = new JsonArray(new JsonObject { [timestampField] = "desc" })
        };

        return body.ToJsonString();
    }

    public static string BuildGroupCount(
        string? queryJson,
        TimeRange range,
        string timestampField,
        IReadOnlyList<string> groupByFields,
        long minCount,
        int maxGroups)
    {
        if (groupByFields.Count == 0)
            throw new ArgumentException("A group count needs at least one field to group by.", nameof(groupByFields));

        var body = new JsonObject
        {
            // No documents. The engine needs counts, and returning hits it would immediately discard is
            // the difference between a query that scales and one that does not.
            ["size"] = 0,
            ["track_total_hits"] = false,
            ["query"] = BoundedQuery(queryJson, range, timestampField),
            ["aggs"] = new JsonObject
            {
                ["groups"] = GroupAggregation(groupByFields, minCount, maxGroups, timestampField)
            }
        };

        return body.ToJsonString();
    }

    /// <summary>Name the sample event comes back under, inside each bucket.</summary>
    public const string SampleAggregation = "sample";

    /// <summary>
    /// One event per group, so an alert can say what happened rather than only that something did.
    ///
    /// A sub-aggregation rather than a second query: counts and samples arrive together, and a rule with
    /// forty qualifying subjects still makes one request. Sorted newest first, because during an incident
    /// the useful line is the latest one. Size 1, because this is an illustration — a rule that wanted
    /// every matching document would be asking the wrong system for it.
    /// </summary>
    private static JsonObject SampleEvent(string timestampField) => new()
    {
        ["top_hits"] = new JsonObject
        {
            ["size"] = 1,
            ["sort"] = new JsonArray
            {
                new JsonObject { [timestampField] = new JsonObject { ["order"] = "desc" } }
            }
        }
    };

    /// <summary>
    /// Single field uses <c>terms</c>; several use <c>multi_terms</c>. Both honour <c>min_doc_count</c>,
    /// which <c>composite</c> does not — and losing that would mean paging through every distinct value in
    /// the window to find the few that matter.
    /// </summary>
    private static JsonObject GroupAggregation(
        IReadOnlyList<string> groupByFields, long minCount, int maxGroups, string timestampField)
    {
        var size = Math.Clamp(maxGroups, 1, 10_000);
        var threshold = Math.Max(1, minCount);
        var samples = new JsonObject { [SampleAggregation] = SampleEvent(timestampField) };

        if (groupByFields.Count == 1)
        {
            return new JsonObject
            {
                ["terms"] = new JsonObject
                {
                    ["field"] = groupByFields[0],
                    ["size"] = size,
                    ["min_doc_count"] = threshold,
                    ["order"] = new JsonObject { ["_count"] = "desc" }
                },
                ["aggs"] = samples
            };
        }

        var terms = new JsonArray();
        foreach (var field in groupByFields)
            terms.Add(new JsonObject { ["field"] = field });

        return new JsonObject
        {
            ["multi_terms"] = new JsonObject
            {
                ["terms"] = terms,
                ["size"] = size,
                ["min_doc_count"] = threshold,
                ["order"] = new JsonObject { ["_count"] = "desc" }
            },
            ["aggs"] = samples
        };
    }

    /// <summary>
    /// The author's query and the platform's time bound, as sibling filters. The range is added here so
    /// that no rule, however it is written, can produce an unbounded read.
    /// </summary>
    private static JsonObject BoundedQuery(string? queryJson, TimeRange range, string timestampField)
    {
        var filters = new JsonArray
        {
            new JsonObject
            {
                ["range"] = new JsonObject
                {
                    [timestampField] = new JsonObject
                    {
                        // Half-open. Two consecutive windows sharing a boundary instant would each count
                        // the event that lands on it, and the same event would trigger twice.
                        ["gte"] = range.From.UtcDateTime.ToString("o"),
                        ["lt"] = range.To.UtcDateTime.ToString("o"),
                        ["format"] = "strict_date_optional_time"
                    }
                }
            }
        };

        if (TryParseQuery(queryJson, out var authored))
            filters.Add(authored);

        return new JsonObject { ["bool"] = new JsonObject { ["filter"] = filters } };
    }

    /// <summary>
    /// An empty or unparseable query means "everything in the window" rather than an error: the time bound
    /// still applies, so the worst case is a broad rule, not an unbounded one. Validation rejects malformed
    /// queries at save time, where the author can see the message.
    /// </summary>
    private static bool TryParseQuery(string? queryJson, out JsonNode parsed)
    {
        parsed = null!;

        if (string.IsNullOrWhiteSpace(queryJson))
            return false;

        try
        {
            var node = JsonNode.Parse(queryJson);
            if (node is not JsonObject obj || obj.Count == 0)
                return false;

            parsed = obj;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether a string is a usable query clause. Called at save time so the author gets the message, and
    /// separately from <see cref="TryParseQuery"/> so that a stored rule cannot fail closed at 03:00
    /// because of a character someone typed months earlier.
    /// </summary>
    public static bool IsValidQuery(string? queryJson, out string error)
    {
        error = "";

        if (string.IsNullOrWhiteSpace(queryJson))
            return true; // "match everything in the window" is a legitimate rule.

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(queryJson);
        }
        catch (JsonException ex)
        {
            error = $"The query is not valid JSON: {ex.Message}";
            return false;
        }

        if (node is not JsonObject obj)
        {
            error = "The query must be a JSON object, for example { \"term\": { \"event.type\": \"authentication_failed\" } }.";
            return false;
        }

        if (obj.Count == 0)
        {
            error = "The query object is empty.";
            return false;
        }

        // These belong to the search body, not to a query clause. Accepting them would let the query box
        // reach past the boundary this class exists to hold.
        foreach (var forbidden in (string[])["aggs", "aggregations", "size", "from", "sort", "_source",
                                             "script_fields", "runtime_mappings", "collapse", "pit"])
        {
            if (obj.ContainsKey(forbidden))
            {
                error = $"'{forbidden}' is part of the search request, not the query. Keep the query to matching clauses.";
                return false;
            }
        }

        return true;
    }
}
