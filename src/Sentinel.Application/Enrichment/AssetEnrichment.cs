using System.Net;
using Sentinel.Domain.Platform;

namespace Sentinel.Application.Enrichment;

/// <summary>Where the asset inventory is kept. Read-only from the enrichment's side.</summary>
public interface IAssetLookup
{
    /// <summary>
    /// Everything that could match, for the enrichment to choose between.
    ///
    /// The whole inventory rather than a query per subject: it is small — the estate's notable machines
    /// and accounts, not every host — and this runs inside the path that records an alert, where a round
    /// trip per candidate would be paid on every detection. A deployment whose inventory outgrows that has
    /// a different problem than this interface.
    /// </summary>
    Task<IReadOnlyList<Asset>> AllAsync(CancellationToken ct = default);
}

/// <summary>
/// What the estate knows about the thing an alert is about.
///
/// This is the enrichment the platform most needed. "Block 10.5.5.5" is a different decision depending on
/// whether that address belongs to a laptop or a domain controller, and until now nothing in the platform
/// could tell the difference — the never-act list was an operator writing down the answer by hand, one
/// address at a time, with no way to say why.
///
/// An exact match beats a range. Two rows can both apply — <c>10.0.0.0/8</c> for the estate and
/// <c>10.5.5.5</c> for the controller inside it — and the specific one is the one that was written to say
/// something the general one does not.
/// </summary>
public sealed class AssetEnrichment(IAssetLookup assets) : IEnrichment
{
    public string Name => "asset";

    public EnrichmentDescriptor Describe() => new(
        Name,
        "Asset",
        "What the inventory says about the address or account the alert is about, and raises the alert's " +
        "severity when it is something that matters.",
        ["name", "criticality", "owner", "environment", "matched"]);

    public async Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default)
    {
        var value = request.SubjectValue(
            "source.ip", "client.ip", "ip", "SourceIP", "sourceIp",
            "user.id", "user.name", "userId", "UserID");

        if (string.IsNullOrWhiteSpace(value))
            return EnrichmentResult.Nothing;

        var inventory = await assets.AllAsync(ct);

        if (inventory.Count == 0)
            return EnrichmentResult.Nothing;

        var match = Match(inventory, value);

        if (match is null)
            return EnrichmentResult.Nothing;

        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = match.Name,
            ["criticality"] = match.Criticality,

            // What actually matched, so somebody reading the alert can tell an exact entry from a /8 that
            // happens to contain the address — the difference between "this is the controller" and "this
            // is somewhere in the estate".
            ["matched"] = match.Identifier
        };

        if (!string.IsNullOrWhiteSpace(match.Owner))
            facts["owner"] = match.Owner;

        if (!string.IsNullOrWhiteSpace(match.Environment))
            facts["environment"] = match.Environment;

        return EnrichmentResult.From(facts, AssetCriticality.SeverityFloor(match.Criticality));
    }

    /// <summary>
    /// The most specific row that applies: an exact identifier first, then the narrowest network
    /// containing the address.
    /// </summary>
    private static Asset? Match(IReadOnlyList<Asset> inventory, string value)
    {
        var exact = inventory.FirstOrDefault(a =>
            a.Kind != AssetKind.Network &&
            a.Identifier.Equals(value, StringComparison.OrdinalIgnoreCase));

        if (exact is not null)
            return exact;

        if (!IPAddress.TryParse(value, out var address))
            return null;

        Asset? best = null;
        var bestPrefix = -1;

        foreach (var asset in inventory)
        {
            if (asset.Kind != AssetKind.Network)
                continue;

            if (!TryContains(asset.Identifier, address, out var prefix))
                continue;

            // Longer prefix wins: /24 is a statement about a subnet, /8 about the estate, and the former
            // was written by somebody who wanted to say something more precise.
            if (prefix > bestPrefix)
            {
                best = asset;
                bestPrefix = prefix;
            }
        }

        return best;
    }

    private static bool TryContains(string entry, IPAddress address, out int prefix)
    {
        prefix = -1;

        var trimmed = entry?.Trim();

        if (string.IsNullOrEmpty(trimmed))
            return false;

        if (!IPNetwork.TryParse(trimmed, out var network))
            return false;

        if (!network.Contains(address))
            return false;

        prefix = network.PrefixLength;
        return true;
    }
}
