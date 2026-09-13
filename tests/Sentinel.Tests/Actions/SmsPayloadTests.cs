using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// What a rule actually sends to its SMS gateway.
///
/// Two settings, two jobs: <c>template</c> is the sentence a person reads, <c>payload</c> is the document
/// the gateway parses. A rule that says nothing about the payload gets the platform's default body; a rule
/// that describes one is in charge of every field, because the whole point is that two rules pointed at
/// one gateway can send different things.
/// </summary>
public class SmsPayloadTests
{
    private static ActionContext Context(Dictionary<string, string>? settings = null) => new(
        AlertId: "a1b2c3",
        AlertRowId: 4,
        RuleId: 7,
        RuleVersion: 2,
        RuleName: "Backend errors by API",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 9, 9, 10, 5, 0, TimeSpan.Zero),
        Event: new Dictionary<string, string> { ["ApiName.keyword"] = "AiServices:vv1" },
        Evidence: new Dictionary<string, string> { ["eventCount"] = "12", ["threshold"] = "10" },
        Settings: settings ?? new Dictionary<string, string>());

    private static Connection Gateway() => new()
    {
        Name = "sms-gateway",
        Type = ConnectionType.Sms,
        Endpoint = "https://sms.internal",
        AuthenticationMode = AuthenticationMode.None,
        TimeoutSeconds = 30,
        Enabled = true
    };

    private static SmsActionProvider Sms(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<SmsActionProvider>.Instance);

    private static readonly string[] Vocabulary =
    [
        "subject", "alert.id", "alert.severity", "alert.timestamp",
        "rule.id", "rule.name", "rule.version",
        "evidence.eventCount", "evidence.threshold",
        "event.ApiName.keyword"
    ];

    // -- the default body ----------------------------------------------------------------------

    [Fact]
    public async Task A_rule_that_configures_nothing_still_sends_something_usable()
    {
        var http = new FakeElasticsearch().Answers("{}");

        await Sms(http).ExecuteAsync(Context(), Gateway(), "k");

        var body = JsonNode.Parse(http.LastBody)!.AsObject();

        Assert.Equal("a1b2c3", body["alertId"]!.GetValue<string>());
        Assert.Equal("HIGH", body["severity"]!.GetValue<string>());
        Assert.Contains("Backend errors by API", body["message"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_default_message_names_the_subject_whatever_the_rule_groups_by()
    {
        // The default used to name event.source.ip, which is blank on every rule that groups by anything
        // else — and on this estate the field is called ApiName.keyword. {{subject}} is whatever this rule
        // is about, so the default is right for a rule the platform has never seen.
        var http = new FakeElasticsearch().Answers("{}");

        await Sms(http).ExecuteAsync(Context(), Gateway(), "k");

        var message = JsonNode.Parse(http.LastBody)!["message"]!.GetValue<string>();
        Assert.Contains("AiServices:vv1", message, StringComparison.Ordinal);
    }

    // -- the rule's own body -------------------------------------------------------------------

    [Fact]
    public async Task A_configured_payload_replaces_the_default_entirely()
    {
        // Replaces rather than extends. A gateway that takes {"to","text"} must not also receive
        // "alertId" and "severity" it never asked for and may reject.
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["payload"] = """{ "to": "+989121234567", "text": "{{message}}" }"""
        };

        await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        var body = JsonNode.Parse(http.LastBody)!.AsObject();

        Assert.Equal(2, body.Count);
        Assert.False(body.ContainsKey("alertId"));
        Assert.False(body.ContainsKey("severity"));
    }

    [Fact]
    public async Task The_message_the_rule_wrote_is_available_to_the_payload()
    {
        // What makes the two settings compose. Without it the sentence would have to be written twice —
        // once for the operator to read and once inside the payload — and the copies would drift.
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["template"] = "{{rule.name}} fired {{evidence.eventCount}} times",
            ["payload"] = """{ "text": "{{message}}" }"""
        };

        await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        Assert.Equal(
            "Backend errors by API fired 12 times",
            JsonNode.Parse(http.LastBody)!["text"]!.GetValue<string>());
    }

    [Fact]
    public async Task Two_rules_through_one_gateway_send_different_documents()
    {
        // Stated because it is the requirement, not an implementation detail: the payload belongs to the
        // rule, so the connection being shared changes nothing about what each one sends.
        var first = new FakeElasticsearch().Answers("{}");
        var second = new FakeElasticsearch().Answers("{}");

        await Sms(first).ExecuteAsync(
            Context(new Dictionary<string, string> { ["payload"] = """{ "team": "payments" }""" }),
            Gateway(), "k1");

        await Sms(second).ExecuteAsync(
            Context(new Dictionary<string, string> { ["payload"] = """{ "squad": "platform", "page": true }""" }),
            Gateway(), "k2");

        Assert.Equal("payments", JsonNode.Parse(first.LastBody)!["team"]!.GetValue<string>());
        Assert.True(JsonNode.Parse(second.LastBody)!["page"]!.GetValue<bool>());
    }

    [Fact]
    public async Task The_endpoint_path_belongs_to_the_connection_not_to_the_rule()
    {
        // It describes the service. Every rule pointing at this gateway calls the same endpoint on it, and
        // the day the gateway moves, the change is to the connection rather than to each rule that had
        // written the path down for itself.
        var http = new FakeElasticsearch().Answers("{}");

        var gateway = Gateway();
        gateway.ConfigurationJson = """{ "paths": { "sms": "/api/v2/messages" } }""";

        await Sms(http).ExecuteAsync(Context(), gateway, "k");

        Assert.EndsWith("/api/v2/messages", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_connection_that_says_nothing_gets_the_conventional_path()
    {
        var http = new FakeElasticsearch().Answers("{}");

        await Sms(http).ExecuteAsync(Context(), Gateway(), "k");

        Assert.EndsWith("/sms/send", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_path_left_over_in_a_rule_no_longer_decides_anything()
    {
        // Rule versions are immutable, so versions saved while the path was an action setting still carry
        // one. It is ignored rather than honoured: two rules through one connection reaching two different
        // endpoints is the confusion this change exists to remove.
        var http = new FakeElasticsearch().Answers("{}");

        await Sms(http).ExecuteAsync(
            Context(new Dictionary<string, string> { ["path"] = "/old/route" }), Gateway(), "k");

        Assert.EndsWith("/sms/send", http.LastRequest.RequestUri!.AbsolutePath, StringComparison.Ordinal);
    }

    // -- what the execution record may show ----------------------------------------------------

    [Fact]
    public async Task Phone_numbers_do_not_reach_the_stored_summary()
    {
        // Once the payload is the author's to shape, the platform cannot know which field holds a number,
        // so the common names are redacted by default. An execution record is read by more people than are
        // entitled to the security team's phone numbers.
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["payload"] = """{ "to": "+989121234567", "text": "hello" }"""
        };

        var outcome = await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        Assert.DoesNotContain("989121234567", outcome.RequestSummary!, StringComparison.Ordinal);
        Assert.Contains("***", outcome.RequestSummary!, StringComparison.Ordinal);

        // Redacted in the record, not in the request: the gateway still needs the number.
        Assert.Contains("989121234567", http.LastBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_author_can_name_another_field_to_hide()
    {
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["payload"] = """{ "recipientRef": "R-99812", "text": "hello" }""",
            ["redact"] = "recipientRef"
        };

        var outcome = await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        Assert.DoesNotContain("R-99812", outcome.RequestSummary!, StringComparison.Ordinal);
    }

    // -- what an author is told at save time ---------------------------------------------------

    [Fact]
    public void A_payload_that_is_not_JSON_is_refused_at_save_time()
    {
        var result = Sms(new FakeElasticsearch()).Validate(
            new Dictionary<string, string> { ["payload"] = "{ to: 0912 }" }, Vocabulary);

        Assert.False(result.IsValid);
        Assert.Equal("payload", result.Failures[0].Field);
    }

    [Fact]
    public void A_message_naming_a_field_this_rule_never_produces_is_refused()
    {
        // This is the failure that used to be silent. The rule saves, arms, raises alerts, and every SMS
        // has a blank where the address should be — discovered during the incident it was meant to help.
        var result = Sms(new FakeElasticsearch()).Validate(
            new Dictionary<string, string> { ["template"] = "IP: {{evidence.sourceAddress}}" }, Vocabulary);

        Assert.False(result.IsValid);
        Assert.Contains("evidence.sourceAddress", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_message_placeholder_is_usable_in_a_payload_but_not_in_the_message_itself()
    {
        var provider = Sms(new FakeElasticsearch());

        Assert.True(provider.Validate(
            new Dictionary<string, string> { ["payload"] = """{ "text": "{{message}}" }""" }, Vocabulary).IsValid);

        // A message that referred to itself would be asking to be rendered from its own output.
        Assert.False(provider.Validate(
            new Dictionary<string, string> { ["template"] = "{{message}}" }, Vocabulary).IsValid);
    }

    [Fact]
    public void Both_settings_are_reported_together()
    {
        // One save, one list of everything wrong with the form. Reporting the first failure only means an
        // author fixes a field, saves, and is told about the next one.
        var result = Sms(new FakeElasticsearch()).Validate(
            new Dictionary<string, string>
            {
                ["template"] = "{{nope.one}}",
                ["payload"] = "not json"
            },
            Vocabulary);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "template");
        Assert.Contains(result.Failures, f => f.Field == "payload");
    }

    [Fact]
    public void A_rule_that_configures_nothing_is_valid()
    {
        Assert.True(Sms(new FakeElasticsearch())
            .Validate(new Dictionary<string, string>(), Vocabulary).IsValid);
    }
}
