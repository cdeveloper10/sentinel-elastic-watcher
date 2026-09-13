using System.Net;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Elasticsearch;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Elasticsearch;

/// <summary>
/// The adapter as a caller meets it: what it puts on the wire, and what it does with the answer.
/// </summary>
public class ElasticsearchEventSourceTests
{
    private static readonly TimeRange Window = new(
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero));

    // -- probe ------------------------------------------------------------------------------

    [Fact]
    public async Task A_reachable_cluster_reports_its_version()
    {
        var cluster = new FakeElasticsearch().Answers("""
        { "cluster_name": "security-logs", "version": { "number": "8.13.4" } }
        """);

        var probe = await TestConnections.Source(cluster).ProbeAsync(TestConnections.Elasticsearch());

        Assert.True(probe.Reachable);
        Assert.Equal("8.13.4", probe.Version);
        Assert.Equal("security-logs", probe.ClusterName);
    }

    [Fact]
    public async Task An_unreachable_cluster_is_reported_rather_than_thrown()
    {
        // This answer is rendered next to a Test button, so it has to be a result the UI can show.
        var cluster = new FakeElasticsearch { Throws = new HttpRequestException("No such host is known.") };

        var probe = await TestConnections.Source(cluster).ProbeAsync(TestConnections.Elasticsearch());

        Assert.False(probe.Reachable);
        Assert.Contains("reach", probe.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task An_endpoint_that_is_not_elasticsearch_says_so()
    {
        var cluster = new FakeElasticsearch().Answers("<html>hello</html>");

        var probe = await TestConnections.Source(cluster).ProbeAsync(TestConnections.Elasticsearch());

        Assert.False(probe.Reachable);
        Assert.Contains("URL", probe.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_timeout_is_named_as_one()
    {
        var cluster = new FakeElasticsearch { Throws = new TaskCanceledException() };

        var probe = await TestConnections.Source(cluster).ProbeAsync(TestConnections.Elasticsearch());

        Assert.False(probe.Reachable);
        Assert.Contains("timeout", probe.Message, StringComparison.OrdinalIgnoreCase);
    }

    // -- authentication ---------------------------------------------------------------------

    [Theory]
    [InlineData(AuthenticationMode.ApiKey, "apiKey", "zvk_abc", "ApiKey", "zvk_abc")]
    [InlineData(AuthenticationMode.Bearer, "token", "jwt-value", "Bearer", "jwt-value")]
    public async Task The_connections_credential_is_applied_at_the_point_of_use(
        string mode, string secretName, string secretValue, string scheme, string expected)
    {
        var cluster = new FakeElasticsearch().Answers("""{"version":{"number":"8.0.0"}}""");
        var source = TestConnections.Source(cluster, new Dictionary<string, string> { [secretName] = secretValue });

        await source.ProbeAsync(TestConnections.Elasticsearch(authenticationMode: mode));

        Assert.Equal(scheme, cluster.LastRequest.Headers.Authorization?.Scheme);
        Assert.Equal(expected, cluster.LastRequest.Headers.Authorization?.Parameter);
    }

    [Fact]
    public async Task Basic_credentials_are_encoded_rather_than_sent_as_typed()
    {
        var cluster = new FakeElasticsearch().Answers("""{"version":{"number":"8.0.0"}}""");
        var source = TestConnections.Source(cluster, new Dictionary<string, string>
        {
            ["username"] = "elastic",
            ["password"] = "changeme"
        });

        await source.ProbeAsync(TestConnections.Elasticsearch(authenticationMode: AuthenticationMode.Basic));

        Assert.Equal("Basic", cluster.LastRequest.Headers.Authorization?.Scheme);
        Assert.Equal("ZWxhc3RpYzpjaGFuZ2VtZQ==", cluster.LastRequest.Headers.Authorization?.Parameter);
    }

    [Fact]
    public async Task A_connection_with_no_authentication_sends_none()
    {
        var cluster = new FakeElasticsearch().Answers("""{"version":{"number":"8.0.0"}}""");

        await TestConnections.Source(cluster).ProbeAsync(TestConnections.Elasticsearch());

        Assert.Null(cluster.LastRequest.Headers.Authorization);
    }

    // -- discovery --------------------------------------------------------------------------

    [Fact]
    public async Task Indices_come_back_with_their_size_and_health()
    {
        var cluster = new FakeElasticsearch().Answers("""
        [
          { "index": "gateway-logs-2026.01.14", "docs.count": "120000", "store.size": "48000000", "health": "green" },
          { "index": "gateway-logs-2026.01.15", "docs.count": "9000", "store.size": "3000000", "health": "yellow" }
        ]
        """);

        var indices = await TestConnections.Source(cluster)
            .ListIndicesAsync(TestConnections.Elasticsearch(), "gateway-logs-*");

        // Newest first: the one being written to is the one an author is looking for.
        Assert.Equal("gateway-logs-2026.01.15", indices[0].Name);
        Assert.Equal(120000, indices[1].DocumentCount);
        Assert.Equal("green", indices[1].Health);
    }

    [Fact]
    public async Task A_pattern_matching_nothing_is_an_answer_not_a_failure()
    {
        var cluster = new FakeElasticsearch().Answers("""{"error":{"type":"index_not_found_exception"}}""", HttpStatusCode.NotFound);

        var indices = await TestConnections.Source(cluster)
            .ListIndicesAsync(TestConnections.Elasticsearch(), "does-not-exist-*");

        Assert.Empty(indices);
    }

    [Fact]
    public async Task Field_discovery_asks_only_for_the_patterns_it_was_given()
    {
        var cluster = new FakeElasticsearch().Answers("""
        { "gateway-logs-2026.01": { "mappings": { "properties": { "source": { "properties": { "ip": { "type": "ip" } } } } } } }
        """);

        var catalog = await TestConnections.Source(cluster).DescribeFieldsAsync(
            TestConnections.Elasticsearch(), ["gateway-logs-*", "gateway-logs-*", " app-* "]);

        var path = cluster.LastRequest.RequestUri!.ToString();

        Assert.Contains("gateway-logs-*", Uri.UnescapeDataString(path), StringComparison.Ordinal);
        Assert.Contains("app-*", Uri.UnescapeDataString(path), StringComparison.Ordinal);
        Assert.Single(catalog.Fields, f => f.Path == "source.ip");
    }

    // -- the queries that matter -------------------------------------------------------------

    [Fact]
    public async Task A_group_count_sends_an_aggregation_and_reads_the_buckets_back()
    {
        var cluster = new FakeElasticsearch().Answers("""
        {
          "took": 8,
          "aggregations": {
            "groups": {
              "sum_other_doc_count": 0,
              "buckets": [ { "key": "10.10.10.20", "doc_count": 31 } ]
            }
          }
        }
        """);

        var result = await TestConnections.Source(cluster).CountByGroupAsync(
            TestConnections.Elasticsearch(),
            ["gateway-logs-*"],
            """{"term":{"event.type":"authentication_failed"}}""",
            Window,
            "@timestamp",
            ["source.ip"],
            minCount: 20,
            maxGroups: 100);

        Assert.Equal("10.10.10.20", Assert.Single(result.Groups).Key["source.ip"]);
        Assert.Equal(31, result.Groups[0].Count);

        // The threshold travels into the query, so the cluster discards what could never trigger.
        Assert.Contains("\"min_doc_count\":20", cluster.LastBody, StringComparison.Ordinal);
        Assert.Contains("\"size\":0", cluster.LastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_search_refuses_partial_results()
    {
        // A detection that silently saw part of the cluster is worse than one that failed and retried,
        // because nothing downstream can tell the two apart.
        var cluster = new FakeElasticsearch().Answers("""{"aggregations":{"groups":{"buckets":[]}}}""");

        await TestConnections.Source(cluster).CountByGroupAsync(
            TestConnections.Elasticsearch(), ["logs-*"], null!, Window, "@timestamp", ["source.ip"], 1, 10);

        Assert.Contains("allow_partial_search_results=false",
            cluster.LastRequest.RequestUri!.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_error_from_the_cluster_carries_its_status_so_retry_can_be_decided()
    {
        var cluster = new FakeElasticsearch().Answers("""{"error":{"type":"search_phase_execution_exception","reason":"all shards failed"}}""",
            HttpStatusCode.ServiceUnavailable);

        var error = await Assert.ThrowsAsync<EventSourceException>(() =>
            TestConnections.Source(cluster).CountByGroupAsync(
                TestConnections.Elasticsearch(), ["logs-*"], null!, Window, "@timestamp", ["source.ip"], 1, 10));

        Assert.Equal(503, error.StatusCode);
        Assert.True(error.IsTransient);
        Assert.Contains("all shards failed", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(400, false)]
    [InlineData(404, false)]
    [InlineData(429, true)]
    [InlineData(500, true)]
    [InlineData(503, true)]
    public void Only_errors_worth_retrying_are_marked_transient(int status, bool transient) =>
        Assert.Equal(transient, new EventSourceException("x", status).IsTransient);

    [Fact]
    public async Task A_search_with_no_index_pattern_is_refused_before_it_reaches_the_cluster()
    {
        var cluster = new FakeElasticsearch();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TestConnections.Source(cluster).CountByGroupAsync(
                TestConnections.Elasticsearch(), [], null!, Window, "@timestamp", ["source.ip"], 1, 10));

        Assert.Empty(cluster.Requests);
    }
}
