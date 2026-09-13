using System.Net;
using Sentinel.Application.Security;

namespace Sentinel.Tests.Security;

/// <summary>
/// Where the platform will and will not send a request.
///
/// Every outbound call this system makes is aimed by a URL somebody typed into a web form, while the
/// process itself sits inside the network holding credentials. That is a server-side request forgery
/// surface by construction, so these are the cases that decide whether the connection form can be turned
/// into a way to read things its author could not reach directly.
/// </summary>
public class OutboundAddressPolicyTests
{
    private static readonly OutboundAddressSettings Default = new();

    [Theory]
    [InlineData("https://es.internal:9200")]
    [InlineData("http://elasticsearch.prod.svc.cluster.local:9200")]
    [InlineData("https://api.example.com/security")]
    public void An_ordinary_endpoint_is_allowed(string endpoint) =>
        Assert.True(OutboundAddressPolicy.Evaluate(endpoint, Default).Allowed);

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://internal:70")]
    [InlineData("ftp://files.internal")]
    [InlineData("jar:http://x/!/")]
    public void Only_http_and_https_are_spoken(string endpoint)
    {
        var decision = OutboundAddressPolicy.Evaluate(endpoint, Default);

        Assert.False(decision.Allowed);
        Assert.Contains("http", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("https://169.254.169.254")]
    [InlineData("http://metadata.google.internal/computeMetadata/v1/")]
    public void Instance_metadata_is_never_reachable(string endpoint)
    {
        // Worth credentials on most deployments and reachable from nearly all of them, so this one is not
        // subject to any allow flag.
        var permissive = new OutboundAddressSettings { AllowLoopback = true, AllowPrivateNetworks = true };

        Assert.False(OutboundAddressPolicy.Evaluate(endpoint, permissive).Allowed);
    }

    [Fact]
    public void Metadata_stays_blocked_even_when_explicitly_allowlisted()
    {
        var settings = new OutboundAddressSettings { AllowedHosts = ["169.254.169.254"] };

        Assert.False(OutboundAddressPolicy.Evaluate("http://169.254.169.254/", settings).Allowed);
    }

    [Fact]
    public void Loopback_is_refused_by_default()
    {
        var decision = OutboundAddressPolicy.Evaluate("http://127.0.0.1:9200", Default);

        Assert.False(decision.Allowed);
        Assert.Contains("itself", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Loopback_is_allowed_when_someone_opts_in_for_local_work() =>
        Assert.True(OutboundAddressPolicy
            .Evaluate("http://127.0.0.1:9200", new OutboundAddressSettings { AllowLoopback = true })
            .Allowed);

    [Fact]
    public void Private_networks_are_allowed_because_backends_live_there() =>
        Assert.True(OutboundAddressPolicy.Evaluate("http://10.20.30.40:9200", Default).Allowed);

    [Fact]
    public void Private_networks_can_be_refused_for_an_internet_only_deployment()
    {
        var settings = new OutboundAddressSettings { AllowPrivateNetworks = false };

        Assert.False(OutboundAddressPolicy.Evaluate("http://192.168.1.10", settings).Allowed);
        Assert.False(OutboundAddressPolicy.Evaluate("http://172.16.0.1", settings).Allowed);
        Assert.True(OutboundAddressPolicy.Evaluate("http://172.32.0.1", settings).Allowed);
    }

    [Fact]
    public void Credentials_in_the_url_are_refused()
    {
        // They would end up in logs, in the audit trail and on screen — the three places the connection's
        // secret store exists to keep them out of.
        var decision = OutboundAddressPolicy.Evaluate("https://user:pass@es.internal:9200", Default);

        Assert.False(decision.Allowed);
        Assert.Contains("secret", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-url")]
    [InlineData("es.internal:9200")]
    public void Something_that_is_not_an_absolute_url_is_refused(string endpoint) =>
        Assert.False(OutboundAddressPolicy.Evaluate(endpoint, Default).Allowed);

    // -- the resolved-address half ----------------------------------------------------------

    [Fact]
    public void A_hostname_passes_the_first_check_and_is_judged_again_on_its_address()
    {
        // The name says nothing; this is what makes DNS rebinding survivable. The literal check passes,
        // and the address it resolves to gets its own verdict at call time.
        Assert.True(OutboundAddressPolicy.Evaluate("http://harmless.example.com", Default).Allowed);

        var resolved = OutboundAddressPolicy.EvaluateAddress(IPAddress.Parse("169.254.169.254"), Default);
        Assert.False(resolved.Allowed);
    }

    [Theory]
    [InlineData("169.254.10.1")]
    [InlineData("fe80::1")]
    public void Link_local_addresses_are_refused(string address) =>
        Assert.False(OutboundAddressPolicy
            .EvaluateAddress(IPAddress.Parse(address), new OutboundAddressSettings { AllowPrivateNetworks = true })
            .Allowed);

    [Fact]
    public void Ipv6_unique_local_counts_as_private()
    {
        var permissive = new OutboundAddressSettings { AllowPrivateNetworks = true };
        var strict = new OutboundAddressSettings { AllowPrivateNetworks = false };

        Assert.True(OutboundAddressPolicy.EvaluateAddress(IPAddress.Parse("fd00::1"), permissive).Allowed);
        Assert.False(OutboundAddressPolicy.EvaluateAddress(IPAddress.Parse("fd00::1"), strict).Allowed);
    }

    [Fact]
    public void A_public_address_is_allowed() =>
        Assert.True(OutboundAddressPolicy
            .EvaluateAddress(IPAddress.Parse("93.184.216.34"), new OutboundAddressSettings { AllowPrivateNetworks = false })
            .Allowed);
}
