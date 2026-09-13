using System.Text.Json;
using Sentinel.Application.Rules;

namespace Sentinel.Tests.Rules;

/// <summary>
/// The JSON a rule version keeps its actions in.
///
/// Found by reopening a saved rule in the console: not one action setting appeared, and the connection
/// list offered gateways of the wrong type. The column was written with
/// <c>JsonSerializer.Serialize(actions)</c> and no options, which is PascalCase, while everything else the
/// API emits — and therefore everything the console reads — is camelCase. The console looked for
/// <c>type</c>, found <c>Type</c>, could not resolve the provider and rendered an empty form.
///
/// The engine never noticed, because it reads the same column case-insensitively. That is why the defect
/// survived: the half of the system with tests could not see it.
/// </summary>
public class StoredActionBindingTests
{
    private static readonly JsonSerializerOptions StoredJson =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static readonly RuleActionBinding[] Actions =
    [
        new("sms", "sms-gateway", new Dictionary<string, string>
        {
            ["template"] = "{{rule.name}} fired",
            ["payload"] = """{ "text": "{{message}}" }"""
        })
    ];

    [Fact]
    public void Actions_are_stored_under_the_names_the_console_reads()
    {
        var json = JsonSerializer.Serialize(Actions, StoredJson);

        Assert.Contains("\"type\"", json, StringComparison.Ordinal);
        Assert.Contains("\"connection\"", json, StringComparison.Ordinal);
        Assert.Contains("\"settings\"", json, StringComparison.Ordinal);

        Assert.DoesNotContain("\"Type\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Connection\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Settings\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Setting_keys_keep_the_spelling_the_provider_published()
    {
        // The naming policy must not reach inside the settings dictionary. Those keys are the provider's
        // schema — "payload", "targetField", "durationSeconds" — and renaming them would leave every
        // provider unable to find its own settings.
        var json = JsonSerializer.Serialize(Actions, StoredJson);

        Assert.Contains("\"template\"", json, StringComparison.Ordinal);
        Assert.Contains("\"payload\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void A_version_written_before_the_fix_still_evaluates()
    {
        // Versions are immutable history: the PascalCase rows already stored are stored for ever, and an
        // armed rule pointing at one has to keep working.
        const string legacy = """
            [{"Type":"sms","Connection":"sms-gateway","Settings":{"template":"{{rule.name}} fired"}}]
            """;

        var actions = RuleDefinitionMapper.ReadActions(legacy);

        var action = Assert.Single(actions);
        Assert.Equal("sms", action.Type);
        Assert.Equal("sms-gateway", action.Connection);
        Assert.Equal("{{rule.name}} fired", action.Settings["template"]);
    }

    [Fact]
    public void A_version_written_after_the_fix_evaluates_the_same_way()
    {
        var actions = RuleDefinitionMapper.ReadActions(JsonSerializer.Serialize(Actions, StoredJson));

        var action = Assert.Single(actions);
        Assert.Equal("sms", action.Type);
        Assert.Equal("sms-gateway", action.Connection);
        Assert.Equal("""{ "text": "{{message}}" }""", action.Settings["payload"]);
    }

    [Fact]
    public void A_rule_with_no_actions_reads_back_as_none_rather_than_failing()
    {
        Assert.Empty(RuleDefinitionMapper.ReadActions("[]"));
        Assert.Empty(RuleDefinitionMapper.ReadActions(""));
        Assert.Empty(RuleDefinitionMapper.ReadActions("not json"));
    }
}
