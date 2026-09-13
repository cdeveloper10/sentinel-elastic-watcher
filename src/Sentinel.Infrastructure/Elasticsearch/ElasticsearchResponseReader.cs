using System.Text.Json;
using Sentinel.Application.EventSources;

namespace Sentinel.Infrastructure.Elasticsearch;

/// <summary>
/// Reads the two response shapes the platform asks for.
///
/// The subtle one is truncation. A terms aggregation answers with the buckets it was asked for and a
/// <c>sum_other_doc_count</c> saying how much it left out — and a detection engine that ignored that
/// number would report "4 addresses crossed the threshold" when the real answer was "at least 4". For a
/// system that blocks addresses, quietly missing some is the failure that matters, so truncation is
/// carried out of here as a flag rather than dropped.
/// </summary>
public static class ElasticsearchResponseReader
{
    public static GroupCountResult ReadGroupCounts(string responseJson, IReadOnlyList<string> groupByFields)
    {
        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;

        var took = root.TryGetProperty("took", out var tookElement) && tookElement.TryGetInt64(out var ms) ? ms : 0;

        if (!root.TryGetProperty("aggregations", out var aggregations) ||
            !aggregations.TryGetProperty("groups", out var groups))
            return new GroupCountResult([], Truncated: false, took);

        var truncated = groups.TryGetProperty("sum_other_doc_count", out var other)
                        && other.TryGetInt64(out var otherCount)
                        && otherCount > 0;

        var results = new List<GroupCount>();

        if (groups.TryGetProperty("buckets", out var buckets) && buckets.ValueKind == JsonValueKind.Array)
        {
            foreach (var bucket in buckets.EnumerateArray())
            {
                var count = bucket.TryGetProperty("doc_count", out var docCount) && docCount.TryGetInt64(out var c)
                    ? c
                    : 0;

                results.Add(new GroupCount(ReadKey(bucket, groupByFields), count, ReadSample(bucket)));
            }
        }

        return new GroupCountResult(results, truncated, took);
    }

    /// <summary>
    /// The one event the bucket's <c>top_hits</c> brought back, flattened to the dotted paths a rule uses.
    ///
    /// Null when the sub-aggregation is absent — a source that does not support it, or an older query —
    /// rather than an empty dictionary, so that "no sample was asked for" and "the sample had no fields"
    /// stay different states. A rule referring to <c>sample.*</c> then renders blanks, which is the same
    /// thing that happens to any field an event does not carry.
    /// </summary>
    private static IReadOnlyDictionary<string, string>? ReadSample(JsonElement bucket)
    {
        if (!bucket.TryGetProperty(ElasticsearchQueryBuilder.SampleAggregation, out var sample) ||
            !sample.TryGetProperty("hits", out var outer) ||
            !outer.TryGetProperty("hits", out var hits) ||
            hits.ValueKind != JsonValueKind.Array)
            return null;

        foreach (var hit in hits.EnumerateArray())
        {
            if (!hit.TryGetProperty("_source", out var source) || source.ValueKind != JsonValueKind.Object)
                continue;

            var flat = new Dictionary<string, object?>(StringComparer.Ordinal);
            Flatten(source, "", flat);

            return flat.ToDictionary(
                pair => pair.Key,
                pair => pair.Value?.ToString() ?? "",
                StringComparer.OrdinalIgnoreCase);
        }

        return null;
    }

    /// <summary>
    /// A single-field terms bucket keys on a scalar; multi_terms keys on an array in the order the fields
    /// were requested. Both are turned back into field-name/value pairs so nothing downstream has to
    /// remember which aggregation produced them.
    /// </summary>
    private static IReadOnlyDictionary<string, string> ReadKey(JsonElement bucket, IReadOnlyList<string> groupByFields)
    {
        var key = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!bucket.TryGetProperty("key", out var keyElement))
            return key;

        if (keyElement.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var part in keyElement.EnumerateArray())
            {
                if (index < groupByFields.Count)
                    key[groupByFields[index]] = Scalar(part);
                index++;
            }

            return key;
        }

        if (groupByFields.Count > 0)
            key[groupByFields[0]] = Scalar(keyElement);

        return key;
    }

    public static QueryPreview ReadPreview(string responseJson)
    {
        using var document = JsonDocument.Parse(responseJson);
        var root = document.RootElement;

        var took = root.TryGetProperty("took", out var tookElement) && tookElement.TryGetInt64(out var ms) ? ms : 0;

        long total = 0;
        var isLowerBound = false;

        if (root.TryGetProperty("hits", out var hits))
        {
            if (hits.TryGetProperty("total", out var totalElement))
            {
                if (totalElement.ValueKind == JsonValueKind.Object)
                {
                    total = totalElement.TryGetProperty("value", out var value) && value.TryGetInt64(out var v) ? v : 0;
                    isLowerBound = totalElement.TryGetProperty("relation", out var relation)
                                   && relation.GetString() == "gte";
                }
                else if (totalElement.TryGetInt64(out var legacy))
                {
                    total = legacy;
                }
            }
        }

        var samples = new List<IReadOnlyDictionary<string, object?>>();

        if (hits.ValueKind == JsonValueKind.Object &&
            hits.TryGetProperty("hits", out var hitArray) &&
            hitArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var hit in hitArray.EnumerateArray())
            {
                if (!hit.TryGetProperty("_source", out var source) || source.ValueKind != JsonValueKind.Object)
                    continue;

                var flat = new Dictionary<string, object?>(StringComparer.Ordinal);
                Flatten(source, "", flat);
                samples.Add(flat);
            }
        }

        return new QueryPreview(total, isLowerBound, samples, took);
    }

    /// <summary>
    /// Sample documents are flattened to the same dotted paths a rule refers to, so what the preview shows
    /// and what a rule can group by are the same vocabulary.
    /// </summary>
    private static void Flatten(JsonElement element, string prefix, Dictionary<string, object?> into)
    {
        foreach (var property in element.EnumerateObject())
        {
            var path = prefix.Length == 0 ? property.Name : $"{prefix}.{property.Name}";

            if (property.Value.ValueKind == JsonValueKind.Object)
            {
                Flatten(property.Value, path, into);
                continue;
            }

            into[path] = property.Value.ValueKind switch
            {
                JsonValueKind.Array => property.Value.EnumerateArray().Select(Scalar).ToArray(),
                _ => (object?)Scalar(property.Value)
            };
        }
    }

    private static string Scalar(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString() ?? "",
        JsonValueKind.Null or JsonValueKind.Undefined => "",
        _ => element.ToString()
    };

    /// <summary>
    /// Pulls a usable message out of an Elasticsearch error body. The interesting part is nested a few
    /// levels down, and the alternative — surfacing the whole body — puts index names and query fragments
    /// in front of whoever is reading the error.
    /// </summary>
    public static string ReadError(string responseJson, int statusCode)
    {
        try
        {
            using var document = JsonDocument.Parse(responseJson);

            if (document.RootElement.TryGetProperty("error", out var error))
            {
                if (error.ValueKind == JsonValueKind.String)
                    return error.GetString() ?? $"Elasticsearch returned {statusCode}.";

                var type = error.TryGetProperty("type", out var t) ? t.GetString() : null;
                var reason = error.TryGetProperty("reason", out var r) ? r.GetString() : null;

                if (type is not null || reason is not null)
                {
                    var message = $"{type ?? "error"}: {reason ?? "no reason given"}";
                    var cause = FirstShardFailure(error);

                    // "search_phase_execution_exception: Partial shards failure" is true and useless —
                    // it says some shard refused without saying which, or why. The reason is one level
                    // down in failed_shards, and it usually names both the index and the mapping that
                    // disagrees with the query. Without it an operator has a rule failing thirty times
                    // and nothing to act on.
                    return cause is null ? message : $"{message} — {cause}";
                }
            }
        }
        catch (JsonException)
        {
            // Not JSON — a proxy or a gateway in front of the cluster. The status code is the signal.
        }

        return $"Elasticsearch returned {statusCode}.";
    }

    /// <summary>
    /// The first shard that refused, and why.
    ///
    /// One, not all of them: a pattern spanning three hundred daily indices reports the same mapping
    /// conflict three hundred times, and an error message that repeats itself is one nobody reads. The
    /// first names the index, which is enough to go and look.
    ///
    /// <c>caused_by</c> is followed because the useful sentence is usually there — the shard says "failed
    /// to create query" and the cause underneath says which field and which type.
    /// </summary>
    private static string? FirstShardFailure(JsonElement error)
    {
        // root_cause when Elasticsearch has already grouped them; failed_shards otherwise.
        foreach (var property in new[] { "root_cause", "failed_shards" })
        {
            if (!error.TryGetProperty(property, out var failures) ||
                failures.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var failure in failures.EnumerateArray())
            {
                // A failed_shards entry wraps its detail in "reason"; a root_cause entry is the detail.
                var detail = failure.TryGetProperty("reason", out var nested) &&
                             nested.ValueKind == JsonValueKind.Object
                    ? nested
                    : failure;

                var described = Describe(detail);

                if (described is null)
                    continue;

                // A failed_shards entry carries the index beside the reason; a root_cause entry carries it
                // inside. Parenthesised because ?: binds tighter than ??, and written as two lookups so a
                // present-but-null property falls through rather than ending the search.
                var index = (failure.TryGetProperty("index", out var i) ? i.GetString() : null)
                            ?? (detail.TryGetProperty("index", out var j) ? j.GetString() : null);

                return index is null ? described : $"{described} (index {index})";
            }
        }

        return null;
    }

    private static string? Describe(JsonElement detail)
    {
        var type = detail.TryGetProperty("type", out var t) ? t.GetString() : null;
        var reason = detail.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String
            ? r.GetString()
            : null;

        if (type is null && reason is null)
            return null;

        var described = $"{type ?? "error"}: {reason ?? "no reason given"}";

        // One level of cause. Deeper than that is Lucene talking to itself.
        if (detail.TryGetProperty("caused_by", out var caused) && caused.ValueKind == JsonValueKind.Object)
        {
            var causedReason = caused.TryGetProperty("reason", out var cr) &&
                               cr.ValueKind == JsonValueKind.String
                ? cr.GetString()
                : null;

            if (causedReason is not null)
                described += $" — {causedReason}";
        }

        return described.Length <= 400 ? described : described[..400] + "…";
    }
}
