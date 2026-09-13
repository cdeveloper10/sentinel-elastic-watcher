using System.Text.Json;
using System.Text.Json.Nodes;

// A stand-in for whatever service Sentinel calls.
//
// Exists so a rule's actions can be proved end to end without sending a real message to a real person or
// blocking a real address, and so the contract each action speaks is written down as something that runs
// rather than as prose. Point a connection at it, arm a rule, and read back exactly what was sent.
//
// One program rather than one per service, because from the platform's side they are the same shape: an
// HTTP endpoint, a credential, a JSON body. Run two instances on two ports to model two services — that is
// how the multi-service behaviour is exercised:
//
//   dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9310    # an SMS gateway
//   dotnet run --project samples/ServiceStub -- --urls http://0.0.0.0:9320    # a security API
//
// STUB_NAME labels an instance so its recordings are unmistakable when two are running.
//
// It is a sample. No authentication, everything in memory, and it must not be deployed.
//
//   POST /sms/send             what the Send SMS action calls
//   POST /security/block/ip    what the Block IP action calls
//   POST /security/block/user  what the Block user action calls
//   POST /fail                 answers 500, to exercise retry, backoff and dead-lettering
//   POST /reject               answers 400, to exercise a permanent failure
//   GET  /received             what it has been sent, newest first
//   GET  /received/count       how many, and how many per endpoint
//   POST /received/reset       forget them

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpContextAccessor();
var app = builder.Build();

var name = Environment.GetEnvironmentVariable("STUB_NAME") ?? "service stub";

var received = new List<Received>();
var padlock = new Lock();

// The three endpoints the built-in actions call. Registered from one list because the stub's job is
// identical for all of them: record faithfully, answer the way the real service would.
foreach (var (path, describe) in new (string, Func<JsonNode?, object>)[]
         {
             ("/sms/send", body => new
             {
                 accepted = true,
                 messageId = Guid.NewGuid().ToString("N")[..12],
                 segments = Segments(body)
             }),
             ("/security/block/ip", body => new
             {
                 blocked = true,
                 ip = Field(body, "ip"),
                 expiresInSeconds = Field(body, "duration"),
                 ruleId = Guid.NewGuid().ToString("N")[..8]
             }),
             ("/security/block/user", body => new
             {
                 suspended = true,
                 userId = Field(body, "userId"),
                 expiresInSeconds = Field(body, "duration")
             })
         })
{
    var endpoint = path;
    var answer = describe;

    app.MapPost(endpoint, async (HttpRequest request) =>
    {
        var call = await ReadAsync(request);

        lock (padlock)
            received.Add(call);
        
        app.Logger.LogInformation(
            "[{Name}] {Path} ← {Bytes} bytes, idempotency {Key}\n{Body}",
            name, endpoint, call.Body.Length, call.IdempotencyKey ?? "(none)", call.Body);

        return Results.Ok(answer(call.Parsed));
    });
}

// The two failures worth rehearsing. A platform only ever tested against a service that says yes has
// never exercised its retry, its backoff, or its dead-lettering.
app.MapPost("/fail", async (HttpRequest request) =>
{
    await RecordAsync(request);
    return Results.Json(new { error = "upstream unavailable" }, statusCode: 500);
});

app.MapPost("/reject", async (HttpRequest request) =>
{
    await RecordAsync(request);
    return Results.Json(new { error = "the request is not acceptable" }, statusCode: 400);
});

app.MapGet("/received", () =>
{
    // A copy taken under the lock, reversed afterwards.
    //
    // `Results.Ok(received.AsEnumerable().Reverse())` looks equivalent and is not: Reverse() is lazy, so
    // the lock is released before the serialiser has walked anything, and a POST arriving mid-response
    // mutates the list being enumerated. The write then aborts half-finished, which the caller sees as
    // "The response ended prematurely" — an error that reads like a network fault and is a data race.
    Received[] snapshot;

    lock (padlock)
        snapshot = received.ToArray();

    Array.Reverse(snapshot);
    return Results.Ok(snapshot);
});

app.MapGet("/received/count", () =>
{
    lock (padlock)
        return Results.Ok(new
        {
            name,
            count = received.Count,
            byPath = received.GroupBy(r => r.Path).ToDictionary(g => g.Key, g => g.Count())
        });
});

app.MapPost("/received/reset", () =>
{
    lock (padlock)
        received.Clear();

    return Results.NoContent();
});

app.MapGet("/", () => Results.Ok(new
{
    service = name,
    warning = "A sample. No authentication, in-memory, not for deployment.",
    endpoints = new[]
    {
        "/sms/send", "/security/block/ip", "/security/block/user",
        "/fail", "/reject", "/received", "/received/count", "/received/reset"
    }
}));

await app.RunAsync();

async Task RecordAsync(HttpRequest request)
{
    var call = await ReadAsync(request);

    lock (padlock)
        received.Add(call);
}

/// <summary>The body is kept as text as well as parsed, so a malformed one is still inspectable.</summary>
static async Task<Received> ReadAsync(HttpRequest request)
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();

    JsonNode? parsed;

    try
    {
        parsed = JsonNode.Parse(body);
    }
    catch (JsonException)
    {
        parsed = null;
    }

    return new Received(
        DateTimeOffset.UtcNow,
        request.Path,
        request.Headers["Idempotency-Key"].FirstOrDefault(),

        // Whether a credential arrived, never which one. A sample that echoed the key back would be a
        // sample that teaches people to log credentials.
        Credential(request),
        body,
        parsed);
}

/// <summary>
/// How the platform proved who it was. Each authentication mode on the connection puts the credential in a
/// different place, and "the service saw no credential" is the first thing to check when a real one starts
/// answering 401.
/// </summary>
static string Credential(HttpRequest request)
{
    if (request.Headers["X-API-KEY"].FirstOrDefault() is not null)
        return "api_key";

    var authorization = request.Headers.Authorization.FirstOrDefault();

    return authorization switch
    {
        null => "none",
        _ when authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) => "bearer",
        _ when authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) => "basic",
        _ => "other"
    };
}

static string? Field(JsonNode? body, string name) =>
    body is JsonObject o && o.TryGetPropertyValue(name, out var value) ? value?.ToString() : null;

/// <summary>What a real gateway charges for: 160 GSM characters, or 70 once anything is non-Latin.</summary>
static int Segments(JsonNode? body)
{
    var text = Field(body, "text") ?? Field(body, "message") ?? "";
    var limit = text.Any(c => c > 127) ? 70 : 160;

    return Math.Max(1, (int)Math.Ceiling(text.Length / (double)limit));
}

/// <summary>
/// One call, as the service saw it. The idempotency key is recorded because it is how a duplicate is
/// recognised: the platform sends the same key when it retries, and a real service is expected to collapse
/// on it rather than act twice.
/// </summary>
internal sealed record Received(
    DateTimeOffset At,
    string Path,
    string? IdempotencyKey,
    string Credential,
    string Body,
    JsonNode? Parsed);
