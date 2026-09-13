using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// The log line reaching the message and the payload.
///
/// "AiServices returned 14 HTTP 500s" says that something happened. Which user, which path, which backend
/// — that is in the events themselves, and until an alert carried one of them the only way to find out was
/// to go and look. <c>sample.*</c> is one of the events behind the alert.
///
/// One event, not all of them, and named so the author knows: a threshold rule fired because of fourteen
/// and this is the most recent. Kept apart from <c>event.*</c>, which is the subject the rule grouped by
/// and is true of every event in the group.
/// </summary>
public class SampleEventTests
{
    private static ActionContext Context(
        Dictionary<string, string>? settings = null,
        Dictionary<string, string>? sample = null) => new(
        AlertId: "a1b2c3",
        AlertRowId: 4,
        RuleId: 7,
        RuleVersion: 2,
        RuleName: "Backend 500s by API",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 9, 9, 10, 5, 0, TimeSpan.Zero),
        Event: new Dictionary<string, string> { ["ApiName.keyword"] = "AiServices:vv1" },
        Evidence: new Dictionary<string, string> { ["eventCount"] = "14", ["threshold"] = "10" },
        Settings: settings ?? new Dictionary<string, string>())
    {
        Sample = sample ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["@timestamp"] = "2026-09-09T10:04:51.000Z",
            ["UserID"] = "clientmvc@carbon.super",
            ["SourceIP"] = "192.168.8.41",
            ["URIPath"] = "/AiServices/v1/api/query",
            ["ProviderCode"] = "500",
            ["message"] = "Response Code: 500 | backend timeout"
        }
    };

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

    // -- resolving -----------------------------------------------------------------------------

    [Fact]
    public void A_field_of_the_log_line_resolves()
    {
        Assert.True(Context().TryResolve("sample.UserID", out var user));
        Assert.Equal("clientmvc@carbon.super", user);
    }

    [Fact]
    public void Field_names_are_matched_however_they_are_capitalised()
    {
        // Elasticsearch mappings are not consistent about case, and an author copying a field name out of
        // the discovery panel should not have to match it exactly to get a value.
        Assert.True(Context().TryResolve("sample.userid", out var user));
        Assert.Equal("clientmvc@carbon.super", user);
    }

    [Fact]
    public void The_subject_and_the_sample_stay_separate()
    {
        // They are true of different things. The subject is what the rule grouped by, so it holds for all
        // fourteen events; a sample field holds for one. Merging them would let an author write a message
        // that reads as though it described every one of them.
        var context = Context();

        Assert.True(context.TryResolve("event.ApiName.keyword", out _));
        Assert.False(context.TryResolve("event.UserID", out _));
        Assert.False(context.TryResolve("sample.ApiName.keyword", out _));
    }

    [Fact]
    public void An_alert_with_no_sample_renders_a_blank_rather_than_failing()
    {
        // A source that cannot provide one, or a rule whose window produced none. The message still has to
        // go out — an address still needs blocking whether or not the line behind it was retrieved.
        var context = Context(sample: []);

        Assert.False(context.TryResolve("sample.UserID", out _));
        Assert.Equal("User: ", TemplateRenderer.Render("User: {{sample.UserID}}", context).Text);
    }

    [Fact]
    public void The_sample_is_offered_alongside_everything_else()
    {
        var paths = Context().AvailablePaths();

        Assert.Contains("sample.UserID", paths);
        Assert.Contains("sample.message", paths);
        Assert.Contains("event.ApiName.keyword", paths);
    }

    // -- in a message --------------------------------------------------------------------------

    [Fact]
    public async Task A_message_can_name_the_user_and_the_path_from_the_log()
    {
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["template"] =
                "{{event.ApiName.keyword}}: {{evidence.eventCount}} errors. " +
                "Last was {{sample.UserID}} on {{sample.URIPath}}."
        };

        await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        Assert.Equal(
            "AiServices:vv1: 14 errors. Last was clientmvc@carbon.super on /AiServices/v1/api/query.",
            JsonNode.Parse(http.LastBody)!["message"]!.GetValue<string>());
    }

    // -- in a payload --------------------------------------------------------------------------

    [Fact]
    public async Task A_payload_can_carry_the_whole_log_line()
    {
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["payload"] = """
                {
                  "text": "{{message}}",
                  "event": {
                    "at": "{{sample.@timestamp}}",
                    "user": "{{sample.UserID}}",
                    "sourceIp": "{{sample.SourceIP}}",
                    "path": "{{sample.URIPath}}",
                    "raw": "{{sample.message}}"
                  }
                }
                """
        };

        await Sms(http).ExecuteAsync(Context(settings), Gateway(), "k");

        var body = JsonNode.Parse(http.LastBody)!["event"]!;

        Assert.Equal("clientmvc@carbon.super", body["user"]!.GetValue<string>());
        Assert.Equal("192.168.8.41", body["sourceIp"]!.GetValue<string>());
        Assert.Equal("Response Code: 500 | backend timeout", body["raw"]!.GetValue<string>());
    }

    [Fact]
    public async Task A_log_line_containing_JSON_still_cannot_add_a_field()
    {
        // The sample is the most attacker-influenced value in the whole platform: it is a raw log line,
        // and whoever caused the errors chose part of what is in it.
        var http = new FakeElasticsearch().Answers("{}");

        var settings = new Dictionary<string, string>
        {
            ["payload"] = """{ "raw": "{{sample.message}}" }"""
        };

        var sample = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["message"] = """evil","escalate":true,"x":"""
        };

        await Sms(http).ExecuteAsync(Context(settings, sample), Gateway(), "k");

        var body = JsonNode.Parse(http.LastBody)!.AsObject();

        Assert.Single(body);
        Assert.False(body.ContainsKey("escalate"));
    }

    // -- what an author is told at save time ---------------------------------------------------

    [Fact]
    public void A_sample_field_is_accepted_without_the_platform_pretending_to_know_the_mapping()
    {
        // Which fields a sample carries depends on the document that arrives, and two documents in one
        // index need not agree. Refusing an unrecognised sample field would refuse rules that work.
        var vocabulary = new[] { "subject", "alert.id", "rule.name", "evidence.eventCount", "sample.*" };

        var result = Sms(new FakeElasticsearch()).Validate(
            new Dictionary<string, string> { ["template"] = "{{sample.AnythingAtAll}}" },
            vocabulary);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void An_evidence_typo_is_still_refused_beside_it()
    {
        // The leniency is scoped to the prefixes that genuinely cannot be enumerated. Everything else is
        // still checked, so relaxing one does not quietly relax the rest.
        var vocabulary = new[] { "subject", "alert.id", "rule.name", "evidence.eventCount", "sample.*" };

        var result = Sms(new FakeElasticsearch()).Validate(
            new Dictionary<string, string> { ["template"] = "{{sample.Anything}} {{evidence.eventCounts}}" },
            vocabulary);

        Assert.False(result.IsValid);
        Assert.Contains("evidence.eventCounts", result.Failures[0].Message, StringComparison.Ordinal);
    }
}
