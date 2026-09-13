using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// Saying which shard refused, and why.
///
/// Found by a rule that failed thirty-two times reporting only
/// <c>search_phase_execution_exception: Partial shards failure</c> — true, and useless. It says some shard
/// refused without saying which or why, and the platform had thrown away the part of the response that
/// answers both.
///
/// The cause is one level down in <c>failed_shards</c>, and it usually names the index as well as the
/// mapping that disagrees with the query. That is the difference between an operator who can go and look
/// and one who cannot.
/// </summary>
public class ShardFailureTests
{
    [Fact]
    public void A_partial_shard_failure_says_which_index_and_why()
    {
        // The shape Elasticsearch returns when an index pattern spans indices that map a field
        // differently — which is what a daily index and a changed Logstash pipeline produce.
        var message = ElasticsearchResponseReader.ReadError("""
        {
          "error": {
            "type": "search_phase_execution_exception",
            "reason": "Partial shards failure",
            "phase": "query",
            "grouped": true,
            "failed_shards": [
              {
                "shard": 0,
                "index": "wso2_2026-05-23",
                "reason": {
                  "type": "query_shard_exception",
                  "reason": "failed to create query: For input string: \"n/a\"",
                  "index": "wso2_2026-05-23",
                  "caused_by": {
                    "type": "number_format_exception",
                    "reason": "For input string: \"n/a\""
                  }
                }
              }
            ]
          }
        }
        """, 400);

        Assert.Contains("Partial shards failure", message, StringComparison.Ordinal);
        Assert.Contains("query_shard_exception", message, StringComparison.Ordinal);
        Assert.Contains("wso2_2026-05-23", message, StringComparison.Ordinal);
        Assert.Contains("n/a", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Only_the_first_failure_is_reported()
    {
        // A pattern over three hundred daily indices reports the same conflict three hundred times, and a
        // message that repeats itself is one nobody reads to the end. The first names an index, which is
        // enough to go and look.
        var message = ElasticsearchResponseReader.ReadError("""
        {
          "error": {
            "type": "search_phase_execution_exception",
            "reason": "Partial shards failure",
            "failed_shards": [
              { "index": "a", "reason": { "type": "query_shard_exception", "reason": "first" } },
              { "index": "b", "reason": { "type": "query_shard_exception", "reason": "second" } }
            ]
          }
        }
        """, 400);

        Assert.Contains("first", message, StringComparison.Ordinal);
        Assert.DoesNotContain("second", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_grouped_root_cause_is_read_too()
    {
        // Elasticsearch groups identical failures into root_cause and may then leave failed_shards out.
        var message = ElasticsearchResponseReader.ReadError("""
        {
          "error": {
            "root_cause": [
              {
                "type": "illegal_argument_exception",
                "reason": "Fielddata is disabled on [message] in [wso2_2026-09-12]",
                "index": "wso2_2026-09-12"
              }
            ],
            "type": "search_phase_execution_exception",
            "reason": "all shards failed"
          }
        }
        """, 400);

        Assert.Contains("Fielddata is disabled", message, StringComparison.Ordinal);
        Assert.Contains("wso2_2026-09-12", message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_error_with_no_shard_detail_reads_as_it_always_did()
    {
        // Most errors are not shard failures. Adding the cause must not change what those look like.
        var message = ElasticsearchResponseReader.ReadError("""
        { "error": { "type": "index_not_found_exception", "reason": "no such index [missing]" } }
        """, 404);

        Assert.Equal("index_not_found_exception: no such index [missing]", message);
    }

    [Fact]
    public void A_very_long_cause_is_bounded()
    {
        // The reason is stored on the rule's checkpoint and shown in the console. A Lucene stack trace
        // rendered into a table cell helps nobody.
        var long_ = new string('x', 900);

        var message = ElasticsearchResponseReader.ReadError($$"""
        {
          "error": {
            "type": "search_phase_execution_exception",
            "reason": "Partial shards failure",
            "failed_shards": [
              { "index": "a", "reason": { "type": "query_shard_exception", "reason": "{{long_}}" } }
            ]
          }
        }
        """, 400);

        Assert.True(message.Length < 600, $"the message was {message.Length} characters");
    }

    [Fact]
    public void A_response_that_is_not_JSON_still_gives_the_status()
    {
        // A proxy or an ingress in front of the cluster answering with HTML.
        Assert.Equal("Elasticsearch returned 502.", ElasticsearchResponseReader.ReadError("<html>", 502));
    }
}
