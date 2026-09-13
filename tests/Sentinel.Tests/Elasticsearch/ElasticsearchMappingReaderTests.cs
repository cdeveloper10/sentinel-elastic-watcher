using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// Flattening a mapping into the field list a rule author picks from.
///
/// The judgement that matters is which fields are aggregatable. Grouping by an analysed <c>text</c> field
/// does not fail loudly — Elasticsearch either refuses for want of fielddata, or groups by individual
/// token and produces nonsense — so a rule builder can only avoid offering those if this has already
/// worked out which fields can carry a group-by.
/// </summary>
public class ElasticsearchMappingReaderTests
{
    [Fact]
    public void Nested_objects_become_dotted_paths()
    {
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "gateway-logs-2026.01": {
            "mappings": {
              "properties": {
                "event": { "properties": { "type": { "type": "keyword" }, "outcome": { "type": "keyword" } } },
                "source": { "properties": { "ip": { "type": "ip" } } }
              }
            }
          }
        }
        """);

        var paths = catalog.Fields.Select(f => f.Path).ToList();

        Assert.Contains("event.type", paths);
        Assert.Contains("event.outcome", paths);
        Assert.Contains("source.ip", paths);
        // The container itself is not a value a rule can match on.
        Assert.DoesNotContain("event", paths);
        Assert.DoesNotContain("source", paths);
    }

    [Fact]
    public void A_multi_field_keyword_is_offered_alongside_its_analysed_parent()
    {
        // This is usually the only groupable form of a text field, so losing it would leave the rule
        // builder with nothing to offer for the field the author actually wants.
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "logs": {
            "mappings": {
              "properties": {
                "message": {
                  "type": "text",
                  "fields": { "keyword": { "type": "keyword", "ignore_above": 256 } }
                }
              }
            }
          }
        }
        """);

        var message = Assert.Single(catalog.Fields, f => f.Path == "message");
        var keyword = Assert.Single(catalog.Fields, f => f.Path == "message.keyword");

        Assert.False(message.Aggregatable);
        Assert.True(keyword.Aggregatable);
    }

    [Theory]
    [InlineData("keyword", true)]
    [InlineData("ip", true)]
    [InlineData("long", true)]
    [InlineData("date", true)]
    [InlineData("boolean", true)]
    [InlineData("text", false)]
    [InlineData("match_only_text", false)]
    [InlineData("geo_point", false)]
    public void Only_types_that_can_actually_be_grouped_are_marked_aggregatable(string type, bool expected)
    {
        var catalog = ElasticsearchMappingReader.Read($$"""
        { "logs": { "mappings": { "properties": { "field": { "type": "{{type}}" } } } } }
        """);

        Assert.Equal(expected, Assert.Single(catalog.Fields).Aggregatable);
    }

    [Fact]
    public void Date_fields_are_offered_as_timestamps()
    {
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "logs": {
            "mappings": {
              "properties": {
                "@timestamp": { "type": "date" },
                "event": { "properties": { "ingested": { "type": "date_nanos" } } },
                "source": { "properties": { "ip": { "type": "ip" } } }
              }
            }
          }
        }
        """);

        var timestamps = catalog.Timestamps.Select(f => f.Path).ToList();

        Assert.Equal(["@timestamp", "event.ingested"], timestamps.Order().ToList());
    }

    [Fact]
    public void A_field_explicitly_not_indexed_is_listed_but_not_searchable()
    {
        // It is stored and visible in a document, so hiding it would contradict what the author can see —
        // but a query against it silently matches nothing.
        var catalog = ElasticsearchMappingReader.Read("""
        { "logs": { "mappings": { "properties": { "blob": { "type": "keyword", "index": false } } } } }
        """);

        var field = Assert.Single(catalog.Fields);
        Assert.False(field.Searchable);
    }

    [Fact]
    public void A_nested_field_is_addressable_in_its_own_right_and_its_children_are_too()
    {
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "logs": {
            "mappings": {
              "properties": {
                "related": { "type": "nested", "properties": { "user": { "type": "keyword" } } }
              }
            }
          }
        }
        """);

        var paths = catalog.Fields.Select(f => f.Path).ToList();

        Assert.Contains("related", paths);
        Assert.Contains("related.user", paths);
        Assert.False(Assert.Single(catalog.Fields, f => f.Path == "related").Aggregatable);
    }

    [Fact]
    public void Fields_from_several_indices_are_merged_and_each_index_is_reported()
    {
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "logs-2026.01": { "mappings": { "properties": { "shared": { "type": "keyword" },
                                                          "only_january": { "type": "ip" } } } },
          "logs-2026.02": { "mappings": { "properties": { "shared": { "type": "keyword" },
                                                          "only_february": { "type": "long" } } } }
        }
        """);

        Assert.Equal(3, catalog.Fields.Count);
        Assert.Equal(2, catalog.IndicesInspected.Count);
        Assert.Single(catalog.Fields, f => f.Path == "shared");
    }

    [Fact]
    public void When_two_indices_disagree_on_a_type_the_field_survives()
    {
        // Dropping it would hide a field the author can see in their data; inventing a merged type would
        // be a worse answer than either of the real ones.
        var catalog = ElasticsearchMappingReader.Read("""
        {
          "logs-old": { "mappings": { "properties": { "status": { "type": "keyword" } } } },
          "logs-new": { "mappings": { "properties": { "status": { "type": "long" } } } }
        }
        """);

        Assert.Single(catalog.Fields, f => f.Path == "status");
    }

    [Fact]
    public void An_index_with_no_mappings_at_all_is_not_a_failure()
    {
        var catalog = ElasticsearchMappingReader.Read("""{ "empty-index": { "mappings": {} } }""");

        Assert.Empty(catalog.Fields);
        Assert.Equal(["empty-index"], catalog.IndicesInspected);
    }

    [Fact]
    public void The_field_order_is_stable_between_calls()
    {
        // A field picker that reshuffles between page loads is its own kind of bug.
        const string mapping = """
        {
          "logs": { "mappings": { "properties": { "zebra": { "type": "keyword" },
                                                  "alpha": { "type": "keyword" },
                                                  "mid": { "type": "keyword" } } } }
        }
        """;

        Assert.Equal(
            ElasticsearchMappingReader.Read(mapping).Fields.Select(f => f.Path),
            ElasticsearchMappingReader.Read(mapping).Fields.Select(f => f.Path));

        Assert.Equal(["alpha", "mid", "zebra"], ElasticsearchMappingReader.Read(mapping).Fields.Select(f => f.Path));
    }
}
