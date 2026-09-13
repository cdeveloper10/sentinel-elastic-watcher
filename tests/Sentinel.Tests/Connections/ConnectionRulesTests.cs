using Sentinel.Application.Connections;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;

namespace Sentinel.Tests.Connections;

/// <summary>
/// What has to hold before an endpoint and a credential are stored together. These run before anything is
/// written, so a rejected connection never becomes a stored address the platform later dials.
/// </summary>
public class ConnectionRulesTests
{
    private static readonly OutboundAddressSettings Addresses = new();

    [Fact]
    public void A_complete_definition_is_accepted() =>
        Assert.True(Validate().IsValid);

    [Theory]
    [InlineData("Security-API")]      // uppercase
    [InlineData("s")]                 // too short
    [InlineData("-leading-hyphen")]
    [InlineData("has spaces")]
    [InlineData("has_underscore")]
    public void A_name_that_is_not_a_stable_handle_is_refused(string name)
    {
        // Rules refer to this string, so it has to be unambiguous and stable across environments.
        var result = Validate(name: name);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "name");
    }

    [Fact]
    public void An_unknown_connection_type_is_refused()
    {
        var result = Validate(type: "kafka");

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "type");
    }

    [Fact]
    public void The_endpoint_goes_through_the_outbound_address_policy()
    {
        var result = Validate(endpoint: "http://169.254.169.254/");

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "endpoint");
    }

    [Fact]
    public void An_authentication_mode_missing_its_secrets_says_which_ones()
    {
        // Named rather than counted, so the form can point at the field the author has not filled in.
        var result = Validate(authenticationMode: AuthenticationMode.Basic, secrets: ["username"]);

        Assert.False(result.IsValid);
        var failure = Assert.Single(result.Failures, f => f.Field == "secrets");
        Assert.Contains("password", failure.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("username", failure.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Authentication_that_needs_no_secret_is_accepted_without_one() =>
        Assert.True(Validate(authenticationMode: AuthenticationMode.None, secrets: []).IsValid);

    [Theory]
    [InlineData(AuthenticationMode.ApiKey, "apiKey")]
    [InlineData(AuthenticationMode.Bearer, "token")]
    public void Each_mode_knows_what_it_needs(string mode, string secret) =>
        Assert.True(Validate(authenticationMode: mode, secrets: [secret]).IsValid);

    [Fact]
    public void Secret_names_are_matched_without_regard_to_case() =>
        Assert.True(Validate(authenticationMode: AuthenticationMode.ApiKey, secrets: ["APIKEY"]).IsValid);

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(301)]
    public void A_timeout_outside_the_workable_range_is_refused(int seconds)
    {
        var result = Validate(timeoutSeconds: seconds);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Field == "timeoutSeconds");
    }

    [Fact]
    public void Every_problem_is_reported_at_once()
    {
        // A form that reveals one error per submission is a form somebody gives up on.
        var result = Validate(name: "BAD", type: "kafka", endpoint: "not-a-url", timeoutSeconds: 0);

        Assert.False(result.IsValid);
        Assert.True(result.Failures.Count >= 4, $"Expected four problems, got {result.Failures.Count}.");
    }

    private static ValidationResult Validate(
        string name = "security-api",
        string type = ConnectionType.SecurityApi,
        string endpoint = "https://gateway.internal:5302",
        string authenticationMode = AuthenticationMode.ApiKey,
        int timeoutSeconds = 30,
        string[]? secrets = null) =>
        ConnectionRules.Validate(
            name, type, endpoint, authenticationMode, timeoutSeconds, secrets ?? ["apiKey"], Addresses);
}
