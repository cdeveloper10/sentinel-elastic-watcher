using System.Net;
using System.Net.Sockets;
using Sentinel.Application.Actions;

namespace Sentinel.Application.Enrichment;

/// <summary>
/// What can be said about an address without asking anybody.
///
/// Worth having on its own, and worth having first: it needs no inventory, no credential and no network
/// call, so every deployment gets something the moment enrichment exists rather than after somebody has
/// populated a table.
///
/// The fact that earns its place is <c>protected</c>. The never-act list is consulted by the dispatcher
/// at the moment it refuses to block, which is after the message has already gone out saying an address
/// was blocked — the platform knew and said nothing. Here it is known while the alert is being written,
/// so a rule's own message can say "this address is protected and will not be blocked" instead of the
/// action being quietly withheld later.
/// </summary>
public sealed class NetworkEnrichment(ActionSafetySettings safety) : IEnrichment
{
    public string Name => "network";

    public EnrichmentDescriptor Describe() => new(
        Name,
        "Address",
        "Classifies the address an alert is about, and says whether the never-act list protects it.",
        ["address", "scope", "family", "protected"]);

    public Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default)
    {
        var value = request.SubjectValue("source.ip", "client.ip", "ip", "SourceIP", "sourceIp");

        if (string.IsNullOrWhiteSpace(value))
            return Task.FromResult(EnrichmentResult.Nothing);

        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["address"] = value
        };

        if (!IPAddress.TryParse(value, out var address))
        {
            // The rule grouped by something that is not an address — a service name, an account. Saying
            // so is more useful than returning nothing, because a message reading "scope: " would
            // otherwise look like a failed lookup.
            facts["scope"] = "not-an-address";
            facts["protected"] = ActionSafetyPolicy.IsProtectedAddress(safety, value) ? "true" : "false";

            return Task.FromResult(EnrichmentResult.From(facts));
        }

        facts["family"] = address.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4";
        facts["scope"] = Scope(address);
        facts["protected"] = ActionSafetyPolicy.IsProtectedAddress(safety, value) ? "true" : "false";

        return Task.FromResult(EnrichmentResult.From(facts));
    }

    private static string Scope(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return "loopback";

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal) return "link-local";
            if (address.IsIPv6SiteLocal) return "private";

            var v6 = address.GetAddressBytes();
            return (v6[0] & 0xFE) == 0xFC ? "private" : "public";
        }

        var octets = address.GetAddressBytes();

        return octets[0] switch
        {
            10 => "private",
            127 => "loopback",
            169 when octets[1] == 254 => "link-local",
            172 when octets[1] >= 16 && octets[1] <= 31 => "private",
            192 when octets[1] == 168 => "private",
            _ => "public"
        };
    }
}
