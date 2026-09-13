using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Elasticsearch;
using Sentinel.Infrastructure.Http;

namespace Sentinel.Tests.Harness;

/// <summary>
/// A stand-in cluster.
///
/// The adapter speaks Elasticsearch's REST API over <c>HttpClient</c>, which is what makes this possible:
/// the whole thing can be exercised against a recorded handler rather than a mocked client surface, and
/// the requests it actually puts on the wire — paths, query strings, bodies — are inspectable.
/// </summary>
public sealed class FakeElasticsearch : HttpMessageHandler
{
    private readonly Queue<(HttpStatusCode Status, string Body)> _responses = new();

    public List<HttpRequestMessage> Requests { get; } = [];
    public List<string> Bodies { get; } = [];

    /// <summary>Thrown instead of answering, for the connection-failure cases.</summary>
    public Exception? Throws { get; set; }

    public FakeElasticsearch Answers(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        _responses.Enqueue((status, body));
        return this;
    }

    public HttpRequestMessage LastRequest => Requests[^1];
    public string LastBody => Bodies[^1];

    public HttpClient Client() => new(this, disposeHandler: false);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        Bodies.Add(request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken));

        if (Throws is not null)
            throw Throws;

        var (status, body) = _responses.Count > 0
            ? _responses.Dequeue()
            : (HttpStatusCode.OK, "{}");

        return new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
    }
}

/// <summary>Hands every named client the same fake, so the adapter resolves it the way it does in the host.</summary>
public sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
}

/// <summary>Credentials without the encryption layer, for tests that are about the adapter rather than storage.</summary>
public sealed class StubSecrets(Dictionary<string, string>? secrets = null) : IConnectionSecrets
{
    private readonly Dictionary<string, string> _secrets = secrets ?? [];

    public IReadOnlyDictionary<string, string> For(Connection connection) => _secrets;
}

public static class TestConnections
{
    public static Connection Elasticsearch(
        string endpoint = "https://es.internal:9200",
        string authenticationMode = AuthenticationMode.None) => new()
    {
        Id = 1,
        Name = "primary-logs",
        Type = ConnectionType.Elasticsearch,
        Endpoint = endpoint,
        AuthenticationMode = authenticationMode,
        TimeoutSeconds = 30,
        Enabled = true
    };

    public static ElasticsearchEventSource Source(FakeElasticsearch cluster, Dictionary<string, string>? secrets = null) =>
        new(new ConnectionHttpClients(cluster), new StubSecrets(secrets), NullLogger<ElasticsearchEventSource>.Instance);
}
