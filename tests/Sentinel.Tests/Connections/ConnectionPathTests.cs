using Sentinel.Application.Connections;
using Sentinel.Domain.Connections;

namespace Sentinel.Tests.Connections;

/// <summary>
/// Which endpoint an action calls, and whose decision that is.
///
/// It is the connection's. The path describes the service: every rule pointing at one gateway calls the
/// same endpoint on it, and the day the gateway moves, the change belongs to the service rather than to
/// each rule that had separately written the path down. A rule says "send this to this connection" and
/// nothing about the URL — the same reason it carries neither the host nor the credential.
/// </summary>
public class ConnectionPathTests
{
    private static Connection Gateway(string? configuration = null) => new()
    {
        Name = "sms-gateway",
        Type = ConnectionType.Sms,
        Endpoint = "https://sms.internal",
        TimeoutSeconds = 30,
        Enabled = true,
        ConfigurationJson = configuration ?? "{}"
    };

    // -- reading ------------------------------------------------------------------------------

    [Fact]
    public void A_connection_that_says_nothing_leaves_the_action_its_default()
    {
        // A service using the conventional endpoints needs no configuration at all.
        Assert.Equal("/sms/send", ConnectionPaths.For(Gateway(), "sms", "/sms/send"));
    }

    [Fact]
    public void A_configured_path_wins()
    {
        var connection = Gateway("""{ "paths": { "sms": "/api/v2/messages" } }""");

        Assert.Equal("/api/v2/messages", ConnectionPaths.For(connection, "sms", "/sms/send"));
    }

    [Fact]
    public void One_connection_can_answer_two_actions_in_two_places()
    {
        // Why this is keyed by action type rather than being one value: a security API is a single service
        // that blocks an address at one endpoint and suspends an account at another.
        var api = Gateway("""
            { "paths": { "block_ip": "/api/deny/ip", "block_user": "/api/suspend" } }
            """);

        Assert.Equal("/api/deny/ip", ConnectionPaths.For(api, "block_ip", "/security/block/ip"));
        Assert.Equal("/api/suspend", ConnectionPaths.For(api, "block_user", "/security/block/user"));
    }

    [Fact]
    public void An_action_the_connection_does_not_mention_still_gets_its_default()
    {
        var api = Gateway("""{ "paths": { "block_ip": "/api/deny/ip" } }""");

        Assert.Equal("/security/block/user", ConnectionPaths.For(api, "block_user", "/security/block/user"));
    }

    [Fact]
    public void A_missing_leading_slash_is_supplied()
    {
        // "sms/send" against "https://sms.internal" would otherwise become "https://sms.internalsms/send",
        // which is a different host and a request that leaves the estate.
        var connection = Gateway("""{ "paths": { "sms": "sms/send" } }""");

        Assert.Equal("/sms/send", ConnectionPaths.For(connection, "sms", "/fallback"));
    }

    [Fact]
    public void Unreadable_configuration_falls_back_rather_than_failing()
    {
        // Whether the document is well formed is settled when it is saved. At the moment an alert needs
        // sending, a malformed configuration must not be the reason nobody is told.
        Assert.Equal("/sms/send", ConnectionPaths.For(Gateway("not json"), "sms", "/sms/send"));
        Assert.Equal("/sms/send", ConnectionPaths.For(Gateway("""{ "paths": 3 }"""), "sms", "/sms/send"));
    }

    // -- writing ------------------------------------------------------------------------------

    [Fact]
    public void Writing_paths_leaves_the_rest_of_the_configuration_alone()
    {
        // The configuration document belongs to the connection. A setting stored beside the paths has to
        // survive somebody editing a path.
        var written = ConnectionPaths.Write(
            """{ "region": "eu-west", "paths": { "sms": "/old" } }""",
            new Dictionary<string, string> { ["sms"] = "/new" });

        Assert.Contains("eu-west", written, StringComparison.Ordinal);
        Assert.Equal("/new", ConnectionPaths.Read(written)["sms"]);
    }

    [Fact]
    public void Clearing_every_path_removes_the_property_rather_than_leaving_an_empty_one()
    {
        var written = ConnectionPaths.Write(
            """{ "paths": { "sms": "/old" } }""",
            new Dictionary<string, string> { ["sms"] = "" });

        Assert.DoesNotContain("paths", written, StringComparison.Ordinal);
    }

    // -- what an author is told at save time ---------------------------------------------------

    [Fact]
    public void A_full_address_is_refused()
    {
        // This is the one that matters. A connection's endpoint is checked against the outbound policy
        // when it is saved; a path allowed to carry a scheme and host would route around that check and
        // send the platform's credential somewhere nobody validated.
        var result = ConnectionPaths.Validate("""{ "paths": { "sms": "https://elsewhere.example/send" } }""");

        Assert.False(result.IsValid);
        Assert.Contains("not a full address", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_protocol_relative_address_is_refused_too()
    {
        Assert.False(ConnectionPaths.Validate("""{ "paths": { "sms": "//elsewhere.example/send" } }""").IsValid);
    }

    [Fact]
    public void Configuration_that_is_not_JSON_is_refused()
    {
        var result = ConnectionPaths.Validate("{ paths: broken");

        Assert.False(result.IsValid);
        Assert.Contains("not valid JSON", result.Failures[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_path_that_is_not_text_is_refused()
    {
        Assert.False(ConnectionPaths.Validate("""{ "paths": { "sms": 42 } }""").IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("""{ "region": "eu-west" }""")]
    [InlineData("""{ "paths": { "sms": "/sms/send" } }""")]
    public void Configuration_without_a_problem_is_accepted(string configuration)
    {
        Assert.True(ConnectionPaths.Validate(configuration).IsValid);
    }
}
