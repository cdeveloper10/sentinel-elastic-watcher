using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sentinel.Application.EventSources;
using Sentinel.Application.Security;
using Sentinel.Infrastructure.Http;
using Sentinel.Domain.Connections;

namespace Sentinel.Infrastructure.Elasticsearch;

/// <summary>
/// Elasticsearch, behind the source abstraction.
///
/// Spoken to over its REST API with <c>HttpClient</c> rather than through the official client library.
/// That is a deliberate trade: the library tracks the server's major version closely, and this platform
/// has to read whatever cluster an operator already runs. The four request shapes needed here are stable
/// across 7, 8 and 9, and going over HTTP also means the whole adapter can be tested against a fake
/// handler instead of a mocked client surface.
/// </summary>
public sealed class ElasticsearchEventSource(
    ConnectionHttpClients clients,
    IConnectionSecrets secrets,
    ILogger<ElasticsearchEventSource> logger) : IEventSource
{
    public const string HttpClientName = "elasticsearch";

    public string SourceType => ConnectionType.Elasticsearch;

    public async Task<SourceProbe> ProbeAsync(Connection connection, CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var request = Build(connection, HttpMethod.Get, "/");
            using var response = await SendAsync(connection, request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            stopwatch.Stop();

            if (!response.IsSuccessStatusCode)
                return new SourceProbe(
                    false,
                    ElasticsearchResponseReader.ReadError(body, (int)response.StatusCode),
                    ElapsedMs: stopwatch.ElapsedMilliseconds);

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            var version = root.TryGetProperty("version", out var versionElement)
                          && versionElement.TryGetProperty("number", out var number)
                ? number.GetString()
                : null;

            var cluster = root.TryGetProperty("cluster_name", out var clusterName) ? clusterName.GetString() : null;

            return new SourceProbe(true, "Connected.", version, cluster, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            stopwatch.Stop();

            // The message reaches a UI, so it says what failed without echoing anything about the request.
            logger.LogWarning(ex, "Probe of connection {Connection} failed", connection.Name);
            return new SourceProbe(false, Describe(ex), ElapsedMs: stopwatch.ElapsedMilliseconds);
        }
    }

    public async Task<IReadOnlyList<IndexDescriptor>> ListIndicesAsync(
        Connection connection, string pattern, CancellationToken ct = default)
    {
        var safe = string.IsNullOrWhiteSpace(pattern) ? "*" : pattern.Trim();

        using var request = Build(
            connection,
            HttpMethod.Get,
            $"/_cat/indices/{Uri.EscapeDataString(safe)}?format=json&h=index,docs.count,store.size,health&bytes=b&expand_wildcards=open");

        using var response = await SendAsync(connection, request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        // A pattern matching nothing is a normal answer to "what does this resolve to", not a failure.
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return [];

        EnsureSuccess(response, body);

        using var document = JsonDocument.Parse(body);
        var indices = new List<IndexDescriptor>();

        foreach (var entry in document.RootElement.EnumerateArray())
        {
            indices.Add(new IndexDescriptor(
                entry.TryGetProperty("index", out var name) ? name.GetString() ?? "" : "",
                ReadLong(entry, "docs.count"),
                ReadLong(entry, "store.size"),
                entry.TryGetProperty("health", out var health) ? health.GetString() ?? "unknown" : "unknown"));
        }

        return indices.OrderByDescending(i => i.Name, StringComparer.Ordinal).ToList();
    }

    public async Task<FieldCatalog> DescribeFieldsAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, CancellationToken ct = default)
    {
        var patterns = IndexPatternRules.Normalize(indexPatterns);
        if (patterns.Count == 0)
            return new FieldCatalog([], []);

        var target = Uri.EscapeDataString(string.Join(',', patterns));

        using var request = Build(
            connection, HttpMethod.Get, $"/{target}/_mapping?expand_wildcards=open&ignore_unavailable=true");

        using var response = await SendAsync(connection, request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return new FieldCatalog([], []);

        EnsureSuccess(response, body);

        return ElasticsearchMappingReader.Read(body);
    }

    public async Task<QueryPreview> PreviewAsync(
        Connection connection,
        IReadOnlyList<string> indexPatterns,
        string queryJson,
        TimeRange range,
        string timestampField,
        int sampleSize,
        CancellationToken ct = default)
    {
        var body = ElasticsearchQueryBuilder.BuildPreview(queryJson, range, timestampField, sampleSize);
        var response = await SearchAsync(connection, indexPatterns, body, ct);

        return ElasticsearchResponseReader.ReadPreview(response);
    }

    public async Task<GroupCountResult> CountByGroupAsync(
        Connection connection,
        IReadOnlyList<string> indexPatterns,
        string queryJson,
        TimeRange range,
        string timestampField,
        IReadOnlyList<string> groupByFields,
        long minCount,
        int maxGroups,
        CancellationToken ct = default)
    {
        var body = ElasticsearchQueryBuilder.BuildGroupCount(
            queryJson, range, timestampField, groupByFields, minCount, maxGroups);

        var response = await SearchAsync(connection, indexPatterns, body, ct);

        return ElasticsearchResponseReader.ReadGroupCounts(response, groupByFields);
    }

    private async Task<string> SearchAsync(
        Connection connection, IReadOnlyList<string> indexPatterns, string searchBody, CancellationToken ct)
    {
        var patterns = IndexPatternRules.Normalize(indexPatterns);
        if (patterns.Count == 0)
            throw new InvalidOperationException("A search needs at least one index pattern.");

        var target = Uri.EscapeDataString(string.Join(',', patterns));

        using var request = Build(
            connection,
            HttpMethod.Post,
            // allow_partial_search_results=false: a detection that silently saw part of the cluster is
            // worse than one that failed and retried, because nothing downstream can tell the difference.
            $"/{target}/_search?ignore_unavailable=true&allow_partial_search_results=false");

        request.Content = new StringContent(searchBody, Encoding.UTF8, "application/json");

        using var response = await SendAsync(connection, request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        EnsureSuccess(response, body);
        return body;
    }

    private HttpRequestMessage Build(Connection connection, HttpMethod method, string path)
    {
        var baseAddress = connection.Endpoint.TrimEnd('/');
        var request = new HttpRequestMessage(method, $"{baseAddress}{path}");

        Authenticate(connection, request);
        return request;
    }

    /// <summary>
    /// Applies the connection's credential. Read at the point of use and never held on the entity, so a
    /// connection object that reaches a log or a DTO carries ciphertext at worst.
    /// </summary>
    private void Authenticate(Connection connection, HttpRequestMessage request)
    {
        var credentials = secrets.For(connection);

        switch (connection.AuthenticationMode?.ToLowerInvariant())
        {
            case AuthenticationMode.ApiKey when credentials.TryGetValue("apiKey", out var apiKey):
                request.Headers.Authorization = new AuthenticationHeaderValue("ApiKey", apiKey);
                break;

            case AuthenticationMode.Bearer when credentials.TryGetValue("token", out var token):
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                break;

            case AuthenticationMode.Basic
                when credentials.TryGetValue("username", out var user) &&
                     credentials.TryGetValue("password", out var password):
                var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", encoded);
                break;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        Connection connection, HttpRequestMessage request, CancellationToken ct)
    {
        // Per connection, because how its certificate is verified is the connection's own business —
        // a cluster behind a private CA and one behind a public certificate cannot share a handler.
        using var client = clients.For(connection, HttpClientName, maxConnectionsPerServer: 64);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(connection.TimeoutSeconds, 1, 300)));

        return await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token);
    }

    private static void EnsureSuccess(HttpResponseMessage response, string body)
    {
        if (response.IsSuccessStatusCode)
            return;

        throw new EventSourceException(
            ElasticsearchResponseReader.ReadError(body, (int)response.StatusCode),
            (int)response.StatusCode);
    }

    private static long ReadLong(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
            return 0;

        // _cat returns numbers as strings.
        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt64(out var number) => number,
            JsonValueKind.String when long.TryParse(value.GetString(), out var parsed) => parsed,
            _ => 0
        };
    }

    private static string Describe(Exception ex) => ex switch
    {
        TaskCanceledException => "The cluster did not answer before the connection's timeout.",
        HttpRequestException http => $"Could not reach the cluster: {http.Message}",
        JsonException => "The endpoint answered, but not with Elasticsearch's response format. Check the URL.",
        _ => "The connection attempt failed."
    };
}

/// <summary>Raised when a source answers with an error, carrying the status so callers can decide about retry.</summary>
public sealed class EventSourceException(string message, int statusCode) : Exception(message)
{
    public int StatusCode { get; } = statusCode;

    /// <summary>429 and 5xx are worth another attempt; a 400 will fail identically every time.</summary>
    public bool IsTransient => StatusCode is 429 or >= 500;
}
