using System.Net;
using System.Net.Sockets;

namespace Sentinel.Application.Security;

public sealed record AddressDecision(bool Allowed, string Reason)
{
    public static AddressDecision Allow() => new(true, "");
    public static AddressDecision Deny(string reason) => new(false, reason);
}

public sealed class OutboundAddressSettings
{
    /// <summary>Backends usually sit on private networks, so these are permitted by default.</summary>
    public bool AllowPrivateNetworks { get; set; } = true;

    /// <summary>Loopback is only ever the platform itself, so it is refused unless someone opts in for local work.</summary>
    public bool AllowLoopback { get; set; }

    /// <summary>Hosts admitted regardless of the rules below, for the deployment that genuinely needs one.</summary>
    public List<string> AllowedHosts { get; set; } = [];
}

/// <summary>
/// Where the platform is willing to send a request.
///
/// Every outbound call this system makes is aimed by configuration someone entered in a web form — the
/// Elasticsearch endpoint, the security API, the SMS gateway. That is a server-side request forgery
/// surface by construction: the platform holds credentials and sits inside the network, so an endpoint
/// pointed at a metadata service or a neighbouring admin port turns the connection form into a way to read
/// things the author could not reach directly.
///
/// This decides on the literal address. A hostname still has to be resolved and its addresses checked
/// again before the request goes out, because a name that looks external can resolve to 169.254.169.254.
/// </summary>
public static class OutboundAddressPolicy
{
    /// <summary>Cloud instance metadata. Reachable from almost every deployment and worth credentials on most.</summary>
    private static readonly HashSet<string> AlwaysBlockedAddresses = new(StringComparer.OrdinalIgnoreCase)
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "metadata.google.internal"
    };

    public static AddressDecision Evaluate(string? endpoint, OutboundAddressSettings settings)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
            return AddressDecision.Deny("An endpoint is required.");

        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
            return AddressDecision.Deny("The endpoint must be an absolute URL, for example https://es.internal:9200.");

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return AddressDecision.Deny($"Scheme '{uri.Scheme}' is not allowed. Use http or https.");

        if (!string.IsNullOrEmpty(uri.UserInfo))
            return AddressDecision.Deny("Credentials belong in the connection's secrets, not in its URL.");

        if (AlwaysBlockedAddresses.Contains(uri.Host))
            return AddressDecision.Deny($"'{uri.Host}' is an instance metadata address and is never allowed.");

        if (settings.AllowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
            return AddressDecision.Allow();

        return IPAddress.TryParse(uri.Host, out var literal)
            ? EvaluateAddress(literal, settings)
            : AddressDecision.Allow(); // A name: resolved and re-checked at call time.
    }

    /// <summary>
    /// The second half of the check, run against the addresses a hostname actually resolved to. Splitting
    /// it this way is what closes DNS rebinding: the name was fine, the address it produced may not be.
    /// </summary>
    public static AddressDecision EvaluateAddress(IPAddress address, OutboundAddressSettings settings)
    {
        if (AlwaysBlockedAddresses.Contains(address.ToString()))
            return AddressDecision.Deny($"{address} is an instance metadata address and is never allowed.");

        if (IPAddress.IsLoopback(address))
            return settings.AllowLoopback
                ? AddressDecision.Allow()
                : AddressDecision.Deny($"{address} is a loopback address, which would point the platform at itself.");

        if (IsLinkLocal(address))
            return AddressDecision.Deny($"{address} is link-local.");

        if (IsPrivate(address))
            return settings.AllowPrivateNetworks
                ? AddressDecision.Allow()
                : AddressDecision.Deny($"{address} is on a private network and private networks are not allowed.");

        return AddressDecision.Allow();
    }

    private static bool IsLinkLocal(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6LinkLocal;

        var octets = address.GetAddressBytes();
        return octets[0] == 169 && octets[1] == 254;
    }

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6SiteLocal)
                return true;

            // Unique local addresses, fc00::/7.
            var v6 = address.GetAddressBytes();
            return (v6[0] & 0xFE) == 0xFC;
        }

        var octets = address.GetAddressBytes();
        return octets[0] switch
        {
            10 => true,
            127 => true,
            172 => octets[1] >= 16 && octets[1] <= 31,
            192 => octets[1] == 168,
            _ => false
        };
    }
}
