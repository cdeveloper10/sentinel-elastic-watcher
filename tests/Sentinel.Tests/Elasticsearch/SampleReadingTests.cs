using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// Reading the one event each bucket brought back.
///
/// The sample is what turns "fourteen errors" into a message that also names the user and the path. It
/// arrives nested inside the bucket, and the fields are flattened to the same dotted paths a rule groups
/// by, so what the discovery panel shows and what {{sample.*}} resolves are one vocabulary.
/// </summary>
public class SampleReadingTests
{
    [Fact]
    public void The_sample_document_is_flattened_onto_the_group()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "aggregations": {
            "groups": {
              "buckets": [
                {
                  "key": "AiServices:vv1",
                  "doc_count": 14,
                  "sample": {
                    "hits": {
                      "hits": [
                        {
                          "_source": {
                            "@timestamp": "2026-09-09T10:04:51.000Z",
                            "UserID": "clientmvc@carbon.super",
                            "ProviderCode": "500",
                            "log": { "file": { "path": "/var/log/wso2/api.log" } }
                          }
                        }
                      ]
                    }
                  }
                }
              ]
            }
          }
        }
        """, ["ApiName.keyword"]);

        var group = Assert.Single(result.Groups);

        Assert.Equal("clientmvc@carbon.super", group.Sample!["UserID"]);
        Assert.Equal("500", group.Sample["ProviderCode"]);

        // Nested objects become dotted paths, the same shape the rule builder offers for grouping.
        Assert.Equal("/var/log/wso2/api.log", group.Sample["log.file.path"]);
    }

    [Fact]
    public void A_bucket_without_a_sample_reports_none_rather_than_an_empty_one()
    {
        // Null and empty are different states: "this source gave no sample" against "the sample had no
        // fields". The console says so instead of showing a blank panel.
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        { "aggregations": { "groups": { "buckets": [ { "key": "a", "doc_count": 3 } ] } } }
        """, ["ApiName.keyword"]);

        Assert.Null(Assert.Single(result.Groups).Sample);
    }

    [Fact]
    public void A_sample_with_no_hits_reports_none()
    {
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "aggregations": {
            "groups": {
              "buckets": [ { "key": "a", "doc_count": 3, "sample": { "hits": { "hits": [] } } } ]
            }
          }
        }
        """, ["ApiName.keyword"]);

        Assert.Null(Assert.Single(result.Groups).Sample);
    }

    [Fact]
    public void The_count_still_reads_correctly_beside_the_sample()
    {
        // The sample is an addition, not a replacement. A reader that lost the count while gaining the
        // sample would break every threshold rule.
        var result = ElasticsearchResponseReader.ReadGroupCounts("""
        {
          "aggregations": {
            "groups": {
              "sum_other_doc_count": 5,
              "buckets": [
                { "key": "a", "doc_count": 31, "sample": { "hits": { "hits": [ { "_source": { "x": 1 } } ] } } }
              ]
            }
          }
        }
        """, ["ApiName.keyword"]);

        var group = Assert.Single(result.Groups);

        Assert.Equal(31, group.Count);
        Assert.True(result.Truncated);
        Assert.Equal("1", group.Sample!["x"]);
    }
}
