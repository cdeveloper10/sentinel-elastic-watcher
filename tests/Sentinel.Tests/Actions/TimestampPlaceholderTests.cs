using Sentinel.Application.Actions;

namespace Sentinel.Tests.Actions;

/// <summary>
/// The field name every Elasticsearch document has.
///
/// <c>@timestamp</c> is what Elasticsearch and ECS call it, and the placeholder pattern did not allow
/// <c>@</c> — so <c>{{sample.@timestamp}}</c> was not recognised as a placeholder at all and the literal
/// braces travelled to the gateway inside the JSON body. Found by reading what a real receiver was sent,
/// not by any test: everything up to the wire was working, and the value was simply never substituted.
///
/// It is worth its own file because the failure is silent in the worst way. A field that resolves to
/// nothing renders a blank, which reads as missing data; a field that is not recognised as a field renders
/// as instructions to a machine that has no idea what to do with them.
/// </summary>
public class TimestampPlaceholderTests
{
    private static ActionContext Context() => new(
        AlertId: "a1",
        AlertRowId: 1,
        RuleId: 1,
        RuleVersion: 1,
        RuleName: "Backend 500s by API",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 9, 10, 2, 57, 0, TimeSpan.Zero),
        Event: new Dictionary<string, string> { ["ApiName.keyword"] = "MIDoctors" },
        Evidence: new Dictionary<string, string> { ["eventCount"] = "14" },
        Settings: new Dictionary<string, string>())
    {
        Sample = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["@timestamp"] = "2026-09-10T02:57:18.000Z",
            ["@version"] = "1",
            ["UserID"] = "doctor1@carbon.super"
        }
    };

    [Fact]
    public void The_timestamp_of_the_log_line_resolves()
    {
        var result = TemplateRenderer.Render("at {{sample.@timestamp}}", Context());

        Assert.Equal("at 2026-09-10T02:57:18.000Z", result.Text);
        Assert.False(result.HadMissing);
    }

    [Fact]
    public void Other_at_prefixed_fields_resolve_too()
    {
        // @version is the other one Logstash writes into every document.
        Assert.Equal("1", TemplateRenderer.Render("{{sample.@version}}", Context()).Text);
    }

    [Fact]
    public void A_value_that_itself_contains_an_at_sign_is_unaffected()
    {
        // The character is legal in a path and ordinary inside a value; widening one must not disturb the
        // other.
        Assert.Equal("doctor1@carbon.super", TemplateRenderer.Render("{{sample.UserID}}", Context()).Text);
    }

    [Fact]
    public void An_at_prefixed_field_is_reported_as_a_path_rather_than_ignored()
    {
        // The heart of it. Before, PathsIn saw no placeholder here at all, so validation could not warn
        // about it and rendering could not replace it.
        Assert.Contains("sample.@timestamp", TemplateRenderer.PathsIn("{{sample.@timestamp}}"));
    }

    [Fact]
    public void An_at_prefixed_field_that_is_absent_still_renders_a_blank()
    {
        // Recognised as a path and simply not present: a blank, never the literal braces.
        var result = TemplateRenderer.Render("at {{sample.@ingested}}", Context());

        Assert.Equal("at ", result.Text);
        Assert.Contains("sample.@ingested", result.MissingPaths);
    }

    [Fact]
    public void A_path_still_cannot_contain_a_brace()
    {
        // The set stays closed. A path is a lookup key, not an expression, and one able to swallow
        // structure would be a way into the document being built.
        Assert.Empty(TemplateRenderer.PathsIn("{{sample.{evil}}}"));
    }
}
