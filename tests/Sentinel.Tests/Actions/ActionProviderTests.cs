using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// The three response actions, judged on what they put on the wire and how they read the answer.
/// </summary>
public class ActionProviderTests
{
    private static ActionContext Context(
        string ip = "10.10.10.20",
        string user = "alice",
        Dictionary<string, string>? settings = null) => new(
        AlertId: "a1b2c3",
        AlertRowId: 1,
        RuleId: 7,
        RuleVersion: 3,
        RuleName: "Brute Force Detection",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero),
        Event: new Dictionary<string, string> { ["source.ip"] = ip, ["user.id"] = user },
        Evidence: new Dictionary<string, string> { ["eventCount"] = "31" },
        Settings: settings ?? new Dictionary<string, string>());

    private static Connection SecurityApi(bool enabled = true) => new()
    {
        Name = "security-api",
        Type = ConnectionType.SecurityApi,
        Endpoint = "https://gateway.internal:5302",
        AuthenticationMode = AuthenticationMode.ApiKey,
        TimeoutSeconds = 30,
        Enabled = enabled
    };

    private static BlockIpActionProvider BlockIp(FakeElasticsearch http, Dictionary<string, string>? secrets = null) =>
        new(new ConnectionHttpClients(http), new StubSecrets(secrets), NullLogger<BlockIpActionProvider>.Instance);

    private static BlockUserActionProvider BlockUser(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<BlockUserActionProvider>.Instance);

    private static SmsActionProvider Sms(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<SmsActionProvider>.Instance);

    // -- block ip ----------------------------------------------------------------------------

    [Fact]
    public async Task Blocking_an_address_sends_the_payload_the_brief_specifies()
    {
        var http = new FakeElasticsearch().Answers("""{"blocked":true}""");

        var outcome = await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "idem-1");

        Assert.True(outcome.Succeeded);

        var body = JsonNode.Parse(http.LastBody)!.AsObject();
        Assert.Equal("10.10.10.20", body["ip"]!.GetValue<string>());
        Assert.Equal(1800, body["duration"]!.GetValue<int>());
        Assert.Equal("Brute Force Detection", body["reason"]!.GetValue<string>());
        Assert.Equal("a1b2c3", body["alertId"]!.GetValue<string>());
    }

    [Fact]
    public async Task The_idempotency_key_travels_as_a_header()
    {
        // So that a retry the platform makes and a retry the network makes collapse into one operation on
        // the far side.
        var http = new FakeElasticsearch().Answers("{}");

        await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "idem-abc");

        Assert.Equal("idem-abc",
            http.LastRequest.Headers.GetValues(HttpActionProvider.IdempotencyHeader).Single());
    }

    [Fact]
    public async Task An_address_carrying_json_punctuation_stays_a_value()
    {
        // The value came out of a log line somebody else wrote. Templated into a JSON string it would add
        // a field; assembled into an object it cannot.
        var http = new FakeElasticsearch().Answers("{}");

        await BlockIp(http).ExecuteAsync(Context(ip: """10.0.0.1","admin":true,"x":"""), SecurityApi(), "k");

        var body = JsonNode.Parse(http.LastBody)!.AsObject();

        Assert.False(body.ContainsKey("admin"));
        Assert.Contains("admin", body["ip"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task How_long_to_block_for_is_the_rule_s_to_set()
    {
        // A decision about this rule's findings: a brute-force rule and a scanner rule can reasonably
        // block for different lengths through the same security API.
        var http = new FakeElasticsearch().Answers("{}");
        var settings = new Dictionary<string, string> { ["durationSeconds"] = "3600" };

        await BlockIp(http).ExecuteAsync(Context(settings: settings), SecurityApi(), "k");

        Assert.Equal(3600, JsonNode.Parse(http.LastBody)!["duration"]!.GetValue<int>());
    }

    [Fact]
    public async Task Where_to_send_it_is_the_connection_s()
    {
        // A description of the service, not of the rule. One security API answers in the same place
        // however many rules point at it.
        var http = new FakeElasticsearch().Answers("{}");

        var api = SecurityApi();
        api.ConfigurationJson = """{ "paths": { "block_ip": "/api/deny/ip", "block_user": "/api/deny/user" } }""";

        await BlockIp(http).ExecuteAsync(Context(), api, "k");
        Assert.EndsWith("/api/deny/ip", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);

        await BlockUser(http.Answers("{}")).ExecuteAsync(Context(), api, "k");
        Assert.EndsWith("/api/deny/user", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task One_connection_serves_two_actions_at_two_endpoints()
    {
        // Why the paths are keyed by action type rather than being one value on the connection: a security
        // API is a single service that legitimately answers in two places.
        var http = new FakeElasticsearch().Answers("{}");

        await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "k");
        Assert.EndsWith("/security/block/ip", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);

        await BlockUser(http.Answers("{}")).ExecuteAsync(Context(), SecurityApi(), "k");
        Assert.EndsWith("/security/block/user", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_alert_with_no_address_fails_permanently_rather_than_retrying()
    {
        // Retrying would not conjure the field; the rule needs to group by it.
        var http = new FakeElasticsearch();

        var outcome = await BlockIp(http).ExecuteAsync(
            Context(settings: new Dictionary<string, string> { ["targetField"] = "event.absent" }),
            SecurityApi(), "k");

        Assert.False(outcome.Succeeded);
        Assert.False(outcome.Retryable);
        Assert.Equal("NO_TARGET", outcome.ErrorCode);
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task The_connections_credential_is_applied()
    {
        var http = new FakeElasticsearch().Answers("{}");

        await BlockIp(http, new Dictionary<string, string> { ["apiKey"] = "zvk_secret" })
            .ExecuteAsync(Context(), SecurityApi(), "k");

        Assert.Equal("zvk_secret", http.LastRequest.Headers.GetValues("X-API-KEY").Single());
    }

    // -- error classification ------------------------------------------------------------------

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests, true, "RATE_LIMITED")]
    [InlineData(HttpStatusCode.ServiceUnavailable, true, "UPSTREAM_ERROR")]
    [InlineData(HttpStatusCode.InternalServerError, true, "UPSTREAM_ERROR")]
    [InlineData(HttpStatusCode.BadRequest, false, "HTTP_400")]
    [InlineData(HttpStatusCode.Unauthorized, false, "UNAUTHORIZED")]
    [InlineData(HttpStatusCode.UnprocessableEntity, false, "REJECTED")]
    public async Task Only_failures_worth_another_attempt_are_marked_retryable(
        HttpStatusCode status, bool retryable, string code)
    {
        var http = new FakeElasticsearch().Answers("""{"error":"nope"}""", status);

        var outcome = await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "k");

        Assert.False(outcome.Succeeded);
        Assert.Equal(retryable, outcome.Retryable);
        Assert.Equal(code, outcome.ErrorCode);
    }

    [Fact]
    public async Task An_unreachable_system_is_transient()
    {
        var http = new FakeElasticsearch { Throws = new HttpRequestException("connection refused") };

        var outcome = await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "k");

        Assert.True(outcome.Retryable);
        Assert.Equal("UNREACHABLE", outcome.ErrorCode);
    }

    [Fact]
    public async Task An_error_body_is_bounded_before_it_is_stored()
    {
        // The whole body would put whatever the far side echoed — headers, tokens, internal addresses —
        // into a record shown in the UI and kept for audit.
        var http = new FakeElasticsearch().Answers(new string('x', 5_000), HttpStatusCode.BadRequest);

        var outcome = await BlockIp(http).ExecuteAsync(Context(), SecurityApi(), "k");

        Assert.True(outcome.ErrorMessage!.Length < 400);
    }

    // -- block user ---------------------------------------------------------------------------

    [Fact]
    public async Task Suspending_an_account_sends_the_account_not_the_address()
    {
        var http = new FakeElasticsearch().Answers("{}");

        await BlockUser(http).ExecuteAsync(Context(), SecurityApi(), "k");

        var body = JsonNode.Parse(http.LastBody)!.AsObject();
        Assert.Equal("alice", body["userId"]!.GetValue<string>());
        Assert.False(body.ContainsKey("ip"));
    }

    // -- sms ----------------------------------------------------------------------------------

    [Fact]
    public async Task A_message_is_rendered_from_the_alert()
    {
        var http = new FakeElasticsearch().Answers("{}");

        await Sms(http).ExecuteAsync(Context(), new Connection
        {
            Name = "security-sms", Type = ConnectionType.Sms,
            Endpoint = "https://sms.internal", TimeoutSeconds = 30
        }, "k");

        var message = JsonNode.Parse(http.LastBody)!["message"]!.GetValue<string>();

        Assert.Contains("Brute Force Detection", message, StringComparison.Ordinal);
        Assert.Contains("10.10.10.20", message, StringComparison.Ordinal);
        Assert.Contains("HIGH", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_custom_message_template_is_used()
    {
        var http = new FakeElasticsearch().Answers("{}");
        var settings = new Dictionary<string, string> { ["template"] = "{{event.source.ip}} did {{evidence.eventCount}}" };

        await Sms(http).ExecuteAsync(Context(settings: settings), new Connection
        {
            Name = "sms", Type = ConnectionType.Sms, Endpoint = "https://sms.internal", TimeoutSeconds = 30
        }, "k");

        Assert.Equal("10.10.10.20 did 31", JsonNode.Parse(http.LastBody)!["message"]!.GetValue<string>());
    }

    [Fact]
    public async Task Recipients_are_kept_out_of_the_stored_summary()
    {
        // An execution record is read by more people than are entitled to the security team's numbers.
        var http = new FakeElasticsearch().Answers("{}");
        var settings = new Dictionary<string, string> { ["recipients"] = "+989120000000,+989120000001" };

        var outcome = await Sms(http).ExecuteAsync(Context(settings: settings), new Connection
        {
            Name = "sms", Type = ConnectionType.Sms, Endpoint = "https://sms.internal", TimeoutSeconds = 30
        }, "k");

        Assert.Contains("989120000000", http.LastBody, StringComparison.Ordinal);
        Assert.DoesNotContain("989120000000", outcome.RequestSummary!, StringComparison.Ordinal);
    }

    // -- descriptors --------------------------------------------------------------------------

    [Fact]
    public void Each_provider_describes_the_form_the_ui_should_render()
    {
        // Otherwise a new provider means a frontend release, and the frontend accumulates knowledge of
        // every action the backend can perform.
        var descriptor = BlockIp(new FakeElasticsearch()).Describe();

        Assert.Equal(ConnectionType.SecurityApi, descriptor.RequiredConnectionType);
        Assert.Contains(descriptor.Settings, s => s.Key == "targetField" && s.Required);
        Assert.Contains(descriptor.Settings, s => s.Key == "durationSeconds");
    }

    [Fact]
    public void Blocking_is_disruptive_and_messaging_is_not()
    {
        // Which is what decides whether the safety rails and rate caps apply.
        Assert.True(BlockIp(new FakeElasticsearch()).Describe().IsDisruptive);
        Assert.True(BlockUser(new FakeElasticsearch()).Describe().IsDisruptive);
        Assert.False(Sms(new FakeElasticsearch()).Describe().IsDisruptive);
    }

    [Fact]
    public void Sending_a_message_is_not_idempotent_by_nature_and_says_so()
    {
        // Which is why the dispatcher claims a key before the first attempt rather than trusting the
        // gateway to collapse a repeat.
        Assert.False(Sms(new FakeElasticsearch()).Describe().IsIdempotentByNature);
        Assert.True(BlockIp(new FakeElasticsearch()).Describe().IsIdempotentByNature);
    }

    [Theory]
    [InlineData("30", false)]
    [InlineData("60", true)]
    [InlineData("1800", true)]
    [InlineData("604800", true)]
    [InlineData("604801", false)]
    [InlineData("not-a-number", false)]
    public void A_block_duration_outside_what_a_machine_should_decide_is_refused(string duration, bool valid)
    {
        // Not a policy about attackers — a policy about mistakes. An indefinite automated block is one
        // nobody remembers to lift.
        var result = BlockIp(new FakeElasticsearch())
            .Validate(
                new Dictionary<string, string> { ["durationSeconds"] = duration },
                ["event.source.ip"]);

        Assert.Equal(valid, result.IsValid);
    }
}
