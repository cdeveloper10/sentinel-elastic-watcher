using System.Text.Json.Nodes;
using Sentinel.Application.Actions;

namespace Sentinel.Tests.Actions;

/// <summary>
/// The body a rule sends to its own web service.
///
/// The property these exist for is the ordering: the author's JSON is parsed into a document before any
/// value is looked at, so a value can land in a leaf and nowhere else. Rendering placeholders into JSON
/// text and parsing the result is the injection this replaces, and the values in question came out of log
/// lines somebody else was able to write.
/// </summary>
public class PayloadTemplateTests
{
    private static ActionContext Context(
        string? apiName = "AiServices:vv1",
        Dictionary<string, string>? evidence = null) => new(
        AlertId: "a1b2c3",
        AlertRowId: 4,
        RuleId: 7,
        RuleVersion: 2,
        RuleName: "Backend errors by API",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 9, 9, 10, 5, 0, TimeSpan.Zero),
        Event: new Dictionary<string, string> { ["ApiName.keyword"] = apiName ?? "" },
        Evidence: evidence ?? new Dictionary<string, string> { ["eventCount"] = "12", ["threshold"] = "10" },
        Settings: new Dictionary<string, string>());

    private static readonly string[] Vocabulary =
    [
        "subject", "message",
        "alert.id", "alert.severity", "alert.timestamp",
        "rule.id", "rule.name", "rule.version",
        "evidence.eventCount", "evidence.threshold",
        "event.ApiName.keyword"
    ];

    // -- what the author asked for arrives ----------------------------------------------------

    [Fact]
    public void Placeholders_are_filled_and_the_field_names_are_the_author_s()
    {
        // The point of the whole feature: the gateway's own field names, not the platform's.
        var shape = PayloadTemplate.TryParse("""
            { "mobile": "+989121234567", "text": "{{rule.name}} on {{event.ApiName.keyword}}" }
            """)!;

        var body = PayloadTemplate.Render(shape, Context(), out _);

        Assert.Equal("+989121234567", body["mobile"]!.GetValue<string>());
        Assert.Equal("Backend errors by API on AiServices:vv1", body["text"]!.GetValue<string>());
    }

    [Fact]
    public void Nested_objects_and_arrays_survive_with_their_leaves_rendered()
    {
        var shape = PayloadTemplate.TryParse("""
            {
              "message": { "body": "{{rule.name}}", "tags": ["sentinel", "{{alert.severity}}"] }
            }
            """)!;

        var body = PayloadTemplate.Render(shape, Context(), out _);

        Assert.Equal("Backend errors by API", body["message"]!["body"]!.GetValue<string>());
        Assert.Equal("HIGH", body["message"]!["tags"]![1]!.GetValue<string>());
    }

    [Fact]
    public void A_literal_keeps_the_type_the_author_wrote()
    {
        // The only way a payload carries something that is not a string, and it is the author's own
        // literal — nothing is inferred from a rendered value.
        var shape = PayloadTemplate.TryParse("""
            { "priority": 2, "unicode": true, "callback": null, "hits": "{{evidence.eventCount}}" }
            """)!;

        var body = PayloadTemplate.Render(shape, Context(), out _);

        Assert.Equal(2, body["priority"]!.GetValue<int>());
        Assert.True(body["unicode"]!.GetValue<bool>());
        Assert.Null(body["callback"]);

        // Deliberately a string. Guessing would turn an account id of "0071" into 71.
        Assert.Equal("12", body["hits"]!.GetValue<string>());
    }

    [Fact]
    public void A_field_nothing_provides_goes_out_empty_and_is_reported()
    {
        // Empty rather than the literal "{{event.user.id}}", for the same reason a message does it: a
        // gateway receiving a placeholder is worse than one receiving a blank. The caller is told, so the
        // execution record can say the alert was thin.
        var shape = PayloadTemplate.TryParse("""{ "user": "{{event.user.id}}" }""")!;

        var body = PayloadTemplate.Render(shape, Context(), out var missing);

        Assert.Equal("", body["user"]!.GetValue<string>());
        Assert.Contains("event.user.id", missing);
    }

    // -- the property that matters -------------------------------------------------------------

    [Fact]
    public void A_value_containing_JSON_cannot_add_a_field()
    {
        // The attack the design exists to refuse. This API name is what an attacker would have to get into
        // a log line; the document was already parsed, so it can only ever be a string.
        var shape = PayloadTemplate.TryParse("""{ "api": "{{event.ApiName.keyword}}" }""")!;

        var body = PayloadTemplate.Render(shape, Context(apiName: """evil","admin":true,"x":"""), out _);

        Assert.Single(body);
        Assert.False(body.ContainsKey("admin"));
        Assert.Equal("""evil","admin":true,"x":""", body["api"]!.GetValue<string>());
    }

    [Fact]
    public void A_value_containing_a_quote_does_not_break_the_document()
    {
        var shape = PayloadTemplate.TryParse("""{ "api": "{{event.ApiName.keyword}}" }""")!;

        var body = PayloadTemplate.Render(shape, Context(apiName: "say \"hello\""), out _);

        // Round-trips, which is the whole claim: the serialiser escaped it because it was a value.
        var reparsed = JsonNode.Parse(body.ToJsonString())!.AsObject();
        Assert.Equal("say \"hello\"", reparsed["api"]!.GetValue<string>());
    }

    [Fact]
    public void A_value_cannot_introduce_a_placeholder_that_is_then_resolved()
    {
        // One pass, not a loop. A log line containing "{{alert.id}}" is text, not an instruction.
        var shape = PayloadTemplate.TryParse("""{ "api": "{{event.ApiName.keyword}}" }""")!;

        var body = PayloadTemplate.Render(shape, Context(apiName: "{{alert.id}}"), out _);

        Assert.Equal("{{alert.id}}", body["api"]!.GetValue<string>());
    }

    // -- what an author is told at save time ---------------------------------------------------

    [Fact]
    public void An_empty_payload_is_allowed_and_means_the_default_body()
    {
        Assert.True(PayloadTemplate.Validate("", "payload", Vocabulary, out var shape).IsValid);
        Assert.Null(shape);
    }

    [Fact]
    public void Text_that_is_not_JSON_is_refused_with_the_reason()
    {
        var result = PayloadTemplate.Validate("{ mobile: 0912 }", "payload", Vocabulary, out _);

        Assert.False(result.IsValid);
        Assert.Contains("not valid JSON", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("[1, 2, 3]")]
    [InlineData("\"just a string\"")]
    [InlineData("42")]
    public void A_body_that_is_not_an_object_is_refused(string template)
    {
        Assert.False(PayloadTemplate.Validate(template, "payload", Vocabulary, out _).IsValid);
    }

    [Fact]
    public void A_placeholder_this_rule_never_produces_is_refused_before_it_is_saved()
    {
        // The reason validation happens against the rule rather than against a general idea of an alert:
        // evidence.eventCount exists on a threshold rule and this typo does not exist anywhere.
        var result = PayloadTemplate.Validate(
            """{ "hits": "{{evidence.eventCounts}}" }""", "payload", Vocabulary, out _);

        Assert.False(result.IsValid);
        Assert.Contains("evidence.eventCounts", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_payload_carrying_more_than_an_alert_is_refused()
    {
        var many = string.Join(",", Enumerable.Range(0, PayloadTemplate.MaxLeaves + 5).Select(i => $"\"f{i}\":1"));

        var result = PayloadTemplate.Validate("{" + many + "}", "payload", Vocabulary, out _);

        Assert.False(result.IsValid);
        Assert.Contains("values", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_payload_longer_than_the_cap_is_refused()
    {
        var huge = $$"""{ "text": "{{new string('x', PayloadTemplate.MaxLength)}}" }""";

        Assert.False(PayloadTemplate.Validate(huge, "payload", Vocabulary, out _).IsValid);
    }

    [Fact]
    public void A_valid_payload_hands_back_the_shape_so_the_caller_need_not_parse_twice()
    {
        var result = PayloadTemplate.Validate(
            """{ "text": "{{message}}" }""", "payload", Vocabulary, out var shape);

        Assert.True(result.IsValid);
        Assert.NotNull(shape);
    }
}
