using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// Reading the answers back.
///
/// The case that matters most is truncation. A terms aggregation returns the buckets it was asked for and
/// a <c>sum_other_doc_count</c> saying how much it left out; an engine that ignored that would report
/// "4 addresses crossed the threshold" when the truth was "at least 4". For a system that blocks
/// addresses, quietly missing some is the failure worth testing for.
/// </summary>
public class ElasticsearchResponseReaderTests
{
    [Fact]
    public void A_single_field_bucket_becomes_a_named_group()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "took": 12,
          "aggregations": {
            "groups": {
              "sum_other_doc_count": 0,
              "buckets": [
                { "key": "10.10.10.20", "doc_count": 31 },
                { "key": "10.10.10.21", "doc_count": 24 }
              ]
            }
          }
        }
        """, ["source.ip"]);

        Assert.Equal(2, result.Groups.Count);
        Assert.Equal("10.10.10.20", result.Groups[0].Key["source.ip"]);
        Assert.Equal(31, result.Groups[0].Count);
        Assert.False(result.Truncated);
        Assert.Equal(12, result.ElapsedMs);
    }

    [Fact]
    public void A_multi_terms_key_is_paired_back_with_the_fields_that_produced_it()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "aggregations": {
            "groups": { "buckets": [ { "key": ["10.10.10.20", "alice"], "doc_count": 44 } ] }
          }
        }
        """, ["source.ip", "user.id"]);

        var group = Assert.Single(result.Groups);

        Assert.Equal("10.10.10.20", group.Key["source.ip"]);
        Assert.Equal("alice", group.Key["user.id"]);
    }

    [Fact]
    public void Leftover_buckets_are_reported_as_truncation_rather_than_dropped()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "aggregations": {
            "groups": {
              "sum_other_doc_count": 5000,
              "buckets": [ { "key": "10.0.0.1", "doc_count": 99 } ]
            }
          }
        }
        """, ["source.ip"]);

        Assert.True(result.Truncated);
        Assert.Single(result.Groups);
    }

    [Fact]
    public void A_response_with_no_aggregation_is_an_empty_answer_not_a_crash()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""{"took":3,"hits":{"total":{"value":0}}}""", ["source.ip"]);

        Assert.Empty(result.Groups);
        Assert.False(result.Truncated);
    }

    [Fact]
    public void Numeric_group_keys_survive_as_strings()
    {
        // A group key is an identity the platform will act on — an account id, a status code. It is
        // carried as text so nothing downstream has to care what Elasticsearch typed it as.
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        { "aggregations": { "groups": { "buckets": [ { "key": 401, "doc_count": 60 } ] } } }
        """, ["http.response.status_code"]);

        Assert.Equal("401", Assert.Single(result.Groups).Key["http.response.status_code"]);
    }

    // -- preview ----------------------------------------------------------------------------

    [Fact]
    public void A_preview_reports_the_total_and_whether_it_is_exact()
    {
        var exact = ElasticsearchResponseReader.ReadPreview("""
        { "took": 5, "hits": { "total": { "value": 240, "relation": "eq" }, "hits": [] } }
        """);

        var capped = ElasticsearchResponseReader.ReadPreview("""
        { "took": 5, "hits": { "total": { "value": 10000, "relation": "gte" }, "hits": [] } }
        """);

        Assert.Equal(240, exact.TotalMatched);
        Assert.False(exact.TotalIsLowerBound);

        Assert.Equal(10000, capped.TotalMatched);
        Assert.True(capped.TotalIsLowerBound);
    }

    [Fact]
    public void Sample_documents_are_flattened_into_the_paths_a_rule_would_use()
    {
        // What the preview shows and what a rule can group by have to be the same vocabulary, or the
        // author reads one set of names and types another.
        var preview = ElasticsearchResponseReader.ReadPreview("""
        {
          "hits": {
            "total": { "value": 1 },
            "hits": [
              {
                "_source": {
                  "@timestamp": "2026-01-15T10:00:00Z",
                  "event": { "type": "authentication_failed" },
                  "source": { "ip": "10.10.10.20" },
                  "tags": ["auth", "failure"]
                }
              }
            ]
          }
        }
        """);

        var document = Assert.Single(preview.Samples);

        Assert.Equal("authentication_failed", document["event.type"]);
        Assert.Equal("10.10.10.20", document["source.ip"]);
        Assert.Equal(new[] { "auth", "failure" }, Assert.IsType<string[]>(document["tags"]));
    }

    // -- errors -----------------------------------------------------------------------------

    [Fact]
    public void An_elasticsearch_error_is_reduced_to_its_type_and_reason()
    {
        // Surfacing the whole body would put index names and query fragments in front of whoever reads
        // the error.
        var message = ElasticsearchResponseReader.ReadError("""
        {
          "error": {
            "root_cause": [ { "type": "index_not_found_exception", "reason": "no such index [missing]" } ],
            "type": "index_not_found_exception",
            "reason": "no such index [missing]"
          },
          "status": 404
        }
        """, 404);

        Assert.Contains("index_not_found_exception", message, StringComparison.Ordinal);
        Assert.DoesNotContain("root_cause", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_json_body_falls_back_to_the_status_code()
    {
        // A proxy or ingress in front of the cluster answers in HTML; the status is the only signal.
        var message = ElasticsearchResponseReader.ReadError("<html><body>502 Bad Gateway</body></html>", 502);

        Assert.Contains("502", message, StringComparison.Ordinal);
    }
}
