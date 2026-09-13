using System.Text.Json;
using Sentinel.Application.EventSources;
using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// The two search bodies the platform ever sends.
///
/// Two properties are worth more than the exact JSON: the author's query is composed rather than
/// concatenated, so the query box cannot reach past its clause; and every query carries a time bound this
/// class adds, so no rule can be saved that reads the whole retention period on each evaluation.
/// </summary>
public class ElasticsearchQueryBuilderTests
{
    private static readonly TimeRange Window = new(
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero));

    // -- bounding ---------------------------------------------------------------------------

    [Fact]
    public void Every_query_carries_the_time_bound_the_platform_added()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildPreview(null, Window, "@timestamp", 10));

        var range = body.GetProperty("query").GetProperty("bool").GetProperty("filter")[0].GetProperty("range");
        var timestamp = range.GetProperty("@timestamp");

        Assert.Equal("2026-01-15T10:00:00.0000000Z", timestamp.GetProperty("gte").GetString());
        Assert.Equal("2026-01-15T10:05:00.0000000Z", timestamp.GetProperty("lt").GetString());
    }

    [Fact]
    public void The_window_is_half_open_so_a_boundary_event_is_counted_once()
    {
        // Two consecutive windows sharing an instant would each claim the event landing on it, and the
        // same event would trigger the rule twice.
        var body = Parse(ElasticsearchQueryBuilder.BuildPreview(null, Window, "@timestamp", 10));
        var timestamp = body.GetProperty("query").GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("range").GetProperty("@timestamp");

        Assert.True(timestamp.TryGetProperty("gte", out _));
        Assert.True(timestamp.TryGetProperty("lt", out _));
        Assert.False(timestamp.TryGetProperty("lte", out _));
    }

    [Fact]
    public void An_empty_query_still_gets_the_time_bound()
    {
        // The worst case for a rule with no query is "broad", never "unbounded".
        foreach (var empty in new string?[] { null, "", "   ", "{}", "not json at all" })
        {
            var body = Parse(ElasticsearchQueryBuilder.BuildPreview(empty, Window, "@timestamp", 5));
            var filters = body.GetProperty("query").GetProperty("bool").GetProperty("filter");

            Assert.Equal(1, filters.GetArrayLength());
            Assert.True(filters[0].TryGetProperty("range", out _));
        }
    }

    // -- composition, not concatenation -----------------------------------------------------

    [Fact]
    public void The_authored_query_becomes_one_clause_beside_the_time_bound()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildPreview(
            """{"term":{"event.type":"authentication_failed"}}""", Window, "@timestamp", 5));

        var filters = body.GetProperty("query").GetProperty("bool").GetProperty("filter");

        Assert.Equal(2, filters.GetArrayLength());
        Assert.True(filters[0].TryGetProperty("range", out _));
        Assert.Equal("authentication_failed",
            filters[1].GetProperty("term").GetProperty("event.type").GetString());
    }

    [Fact]
    public void A_query_cannot_smuggle_an_aggregation_past_the_builder()
    {
        // Concatenating strings would let whoever can type in the query box add an aggs section, replace
        // the time bound, or reach a different index.
        var smuggled = """{"term":{"a":"b"}},"aggs":{"evil":{"terms":{"field":"x"}}}""";

        Assert.False(ElasticsearchQueryBuilder.IsValidQuery(smuggled, out _));

        // And even if it were stored somehow, it parses as nothing and is dropped.
        var body = Parse(ElasticsearchQueryBuilder.BuildPreview(smuggled, Window, "@timestamp", 5));
        Assert.Equal(1, body.GetProperty("query").GetProperty("bool").GetProperty("filter").GetArrayLength());
    }

    [Theory]
    [InlineData("aggs")]
    [InlineData("aggregations")]
    [InlineData("size")]
    [InlineData("sort")]
    [InlineData("_source")]
    [InlineData("script_fields")]
    [InlineData("runtime_mappings")]
    public void Search_body_keys_are_refused_inside_a_query_clause(string key)
    {
        Assert.False(ElasticsearchQueryBuilder.IsValidQuery($$$"""{"{{{key}}}": {} }""", out var error));
        Assert.Contains(key, error, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_query_is_valid_because_matching_everything_in_the_window_is_a_real_rule()
    {
        Assert.True(ElasticsearchQueryBuilder.IsValidQuery(null, out _));
        Assert.True(ElasticsearchQueryBuilder.IsValidQuery("", out _));
    }

    [Fact]
    public void A_malformed_query_is_reported_at_save_time_with_a_reason()
    {
        Assert.False(ElasticsearchQueryBuilder.IsValidQuery("{not json", out var error));
        Assert.Contains("valid JSON", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_query_that_is_not_an_object_is_refused()
    {
        Assert.False(ElasticsearchQueryBuilder.IsValidQuery("""["term"]""", out _));
        Assert.False(ElasticsearchQueryBuilder.IsValidQuery("\"just a string\"", out _));
    }

    // -- counting without fetching ----------------------------------------------------------

    [Fact]
    public void A_group_count_asks_for_no_documents()
    {
        // Returning hits the engine would immediately discard is the difference between a query that
        // scales on a busy index and one that does not.
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip"], minCount: 20, maxGroups: 100));

        Assert.Equal(0, body.GetProperty("size").GetInt32());
        Assert.False(body.GetProperty("track_total_hits").GetBoolean());
    }

    [Fact]
    public void The_threshold_travels_into_the_query_as_min_doc_count()
    {
        // This is what keeps the query cheap: the source discards the millions of addresses with one
        // failed login each, instead of shipping every bucket back to be filtered here.
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip"], minCount: 20, maxGroups: 100));

        var terms = body.GetProperty("aggs").GetProperty("groups").GetProperty("terms");

        Assert.Equal("source.ip", terms.GetProperty("field").GetString());
        Assert.Equal(20, terms.GetProperty("min_doc_count").GetInt64());
        Assert.Equal(100, terms.GetProperty("size").GetInt32());
    }

    [Fact]
    public void Grouping_by_several_fields_uses_multi_terms_which_also_honours_the_threshold()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip", "user.id"], minCount: 10, maxGroups: 50));

        var multi = body.GetProperty("aggs").GetProperty("groups").GetProperty("multi_terms");
        var terms = multi.GetProperty("terms");

        Assert.Equal(2, terms.GetArrayLength());
        Assert.Equal("source.ip", terms[0].GetProperty("field").GetString());
        Assert.Equal("user.id", terms[1].GetProperty("field").GetString());
        Assert.Equal(10, multi.GetProperty("min_doc_count").GetInt64());
    }

    [Fact]
    public void A_threshold_below_one_still_asks_for_at_least_one_event()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip"], minCount: 0, maxGroups: 10));

        Assert.Equal(1, body.GetProperty("aggs").GetProperty("groups")
            .GetProperty("terms").GetProperty("min_doc_count").GetInt64());
    }

    [Fact]
    public void Bucket_and_sample_counts_are_capped_however_they_are_asked_for()
    {
        var groups = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip"], 1, maxGroups: 999_999));

        Assert.Equal(10_000, groups.GetProperty("aggs").GetProperty("groups")
            .GetProperty("terms").GetProperty("size").GetInt32());

        var preview = Parse(ElasticsearchQueryBuilder.BuildPreview(null, Window, "@timestamp", 5_000));
        Assert.Equal(100, preview.GetProperty("size").GetInt32());
    }

    [Fact]
    public void Each_group_brings_back_one_of_its_events()
    {
        // What lets a message name the user and the path rather than only say that fourteen errors
        // happened. A sub-aggregation, so counts and samples arrive in one request — a rule with forty
        // qualifying subjects still makes a single round trip.
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip"], minCount: 20, maxGroups: 100));

        var sample = body.GetProperty("aggs").GetProperty("groups")
            .GetProperty("aggs").GetProperty("sample").GetProperty("top_hits");

        Assert.Equal(1, sample.GetProperty("size").GetInt32());
    }

    [Fact]
    public void The_sample_is_the_most_recent_event_in_the_window()
    {
        // During an incident the useful line is the latest one. Sorted by the rule's own timestamp field
        // rather than a hard-coded @timestamp, so an index that names it something else still works.
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "event.ingested", ["source.ip"], minCount: 5, maxGroups: 100));

        var sort = body.GetProperty("aggs").GetProperty("groups")
            .GetProperty("aggs").GetProperty("sample").GetProperty("top_hits").GetProperty("sort");

        Assert.Equal("desc", sort[0].GetProperty("event.ingested").GetProperty("order").GetString());
    }

    [Fact]
    public void Grouping_by_several_fields_brings_back_a_sample_too()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", ["source.ip", "user.id"], minCount: 10, maxGroups: 50));

        Assert.True(body.GetProperty("aggs").GetProperty("groups")
            .GetProperty("aggs").GetProperty("sample").TryGetProperty("top_hits", out _));
    }

    [Fact]
    public void Grouping_by_nothing_is_a_programming_error_rather_than_an_empty_aggregation() =>
        Assert.Throws<ArgumentException>(() => ElasticsearchQueryBuilder.BuildGroupCount(
            null, Window, "@timestamp", [], 1, 10));

    [Fact]
    public void A_preview_bounds_the_hit_count_it_asks_to_be_exact_about()
    {
        var body = Parse(ElasticsearchQueryBuilder.BuildPreview(null, Window, "@timestamp", 10));

        Assert.Equal(ElasticsearchQueryBuilder.TrackTotalHitsUpTo, body.GetProperty("track_total_hits").GetInt32());
    }

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();
}
