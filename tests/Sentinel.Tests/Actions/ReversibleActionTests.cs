using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Http;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Actions;

/// <summary>
/// Taking back something the platform did.
///
/// The gap this closes: the platform could block an address on its own and had no way to unblock one.
/// Expiry was handed to the gateway as a duration and never verified — a promise made by a system this one
/// does not control, on a schedule nobody here can shorten. The occasions an automated block is wrong are
/// exactly the occasions somebody needs it lifted within the minute.
/// </summary>
public class ReversibleActionTests
{
    private static Connection SecurityApi(string? configurationJson = null) => new()
    {
        Id = 1,
        Name = "gateway",
        Type = ConnectionType.SecurityApi,
        Endpoint = "https://gateway.internal",
        AuthenticationMode = AuthenticationMode.None,
        TimeoutSeconds = 10,
        Enabled = true,
        ConfigurationJson = configurationJson ?? "{}"
    };

    private static BlockIpActionProvider BlockIp(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<BlockIpActionProvider>.Instance);

    private static BlockUserActionProvider BlockUser(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<BlockUserActionProvider>.Instance);

    private static SmsActionProvider Sms(FakeElasticsearch http) =>
        new(new ConnectionHttpClients(http), new StubSecrets(), NullLogger<SmsActionProvider>.Instance);

    [Fact]
    public async Task Reversing_a_block_calls_the_undo_endpoint_with_the_recorded_target()
    {
        var http = new FakeElasticsearch();

        var outcome = await BlockIp(http).ReverseAsync("10.5.5.5", SecurityApi(), "alert-1:block_ip:reverse");

        Assert.True(outcome.Succeeded);
        Assert.Equal("/security/unblock/ip", http.LastRequest.RequestUri!.AbsolutePath);
        Assert.Equal("10.5.5.5", JsonNode.Parse(http.LastBody)!["ip"]!.GetValue<string>());
    }

    [Fact]
    public async Task The_undo_endpoint_can_be_configured_on_the_connection()
    {
        // Same reasoning as the block path: where a service undoes something is a property of that
        // service, not of the forty rules that might have caused it.
        var http = new FakeElasticsearch();

        var connection = SecurityApi("""{"paths":{"block_ip.reverse":"/firewall/v2/allow"}}""");

        await BlockIp(http).ReverseAsync("10.5.5.5", connection, "key");

        Assert.Equal("/firewall/v2/allow", http.LastRequest.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task Suspending_an_account_is_reversible_too()
    {
        var http = new FakeElasticsearch();

        var outcome = await BlockUser(http).ReverseAsync("ali.sharafi", SecurityApi(), "key");

        Assert.True(outcome.Succeeded);
        Assert.Equal("/security/unblock/user", http.LastRequest.RequestUri!.AbsolutePath);
        Assert.Equal("ali.sharafi", JsonNode.Parse(http.LastBody)!["userId"]!.GetValue<string>());
    }

    [Fact]
    public async Task The_reversal_carries_its_own_idempotency_key()
    {
        // Its own, derived from the original: two people pressing the button at once send one unblock,
        // and a gateway that collapses repeats does not mistake this for the block it undoes.
        var http = new FakeElasticsearch();

        await BlockIp(http).ReverseAsync("10.5.5.5", SecurityApi(), "alert-9:block_ip:reverse");

        Assert.Equal(
            "alert-9:block_ip:reverse",
            http.LastRequest.Headers.GetValues(HttpActionProvider.IdempotencyHeader).Single());
    }

    [Fact]
    public async Task An_execution_with_no_target_is_refused_rather_than_sent()
    {
        // A blank target would become an unblock request for "", which a gateway may read as "all of them".
        var http = new FakeElasticsearch();

        var outcome = await BlockIp(http).ReverseAsync("", SecurityApi(), "key");

        Assert.False(outcome.Succeeded);
        Assert.Equal("NO_TARGET", outcome.ErrorCode);
        Assert.Empty(http.Requests);
    }

    [Fact]
    public async Task A_gateway_that_refuses_the_undo_says_so_rather_than_reporting_success()
    {
        var http = new FakeElasticsearch().Answers("nope", HttpStatusCode.InternalServerError);

        var outcome = await BlockIp(http).ReverseAsync("10.5.5.5", SecurityApi(), "key");

        Assert.False(outcome.Succeeded);
    }

    [Fact]
    public void Sending_a_message_is_not_reversible()
    {
        // The distinction the interface exists to make. An address can be unblocked; a message that
        // reached somebody's phone cannot be unsent, and offering the button would be a lie.
        // Asserted through the type rather than with `is`: the compiler already knows this one cannot be
        // reversible and warns that the runtime check is pointless, which is a stronger guarantee than
        // the test was asking for.
        Assert.DoesNotContain(typeof(IReversibleAction), typeof(SmsActionProvider).GetInterfaces());

        Assert.False(Sms(new FakeElasticsearch()).Describe().IsReversible);
    }

    [Fact]
    public void What_a_provider_claims_matches_what_it_implements()
    {
        // The descriptor drives the console's button. A provider whose descriptor says it can be undone
        // while the type cannot is a button that fails at the moment somebody most needs it, so the two
        // are checked against each other rather than trusted to be edited together.
        var http = new FakeElasticsearch();

        IActionProvider[] providers = [BlockIp(http), BlockUser(http), Sms(http)];

        foreach (var provider in providers)
            Assert.Equal(provider is IReversibleAction, provider.Describe().IsReversible);
    }

    [Fact]
    public void An_action_that_did_not_happen_is_not_in_effect()
    {
        // What the console offers the button on: only something that succeeded and has not been lifted is
        // still changing the estate.
        Assert.True(new ActionExecution { Status = ActionExecutionStatus.Success }.IsInEffect);

        Assert.False(new ActionExecution { Status = ActionExecutionStatus.Failed }.IsInEffect);
        Assert.False(new ActionExecution { Status = ActionExecutionStatus.Skipped }.IsInEffect);

        Assert.False(new ActionExecution
        {
            Status = ActionExecutionStatus.Success,
            ReversedAt = DateTime.UtcNow
        }.IsInEffect);
    }
}
