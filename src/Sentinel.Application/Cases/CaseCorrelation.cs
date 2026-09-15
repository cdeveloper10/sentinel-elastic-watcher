using Sentinel.Domain.Alerts;

namespace Sentinel.Application.Cases;

/// <summary>What an alert is about, for the purpose of deciding which investigation it belongs to.</summary>
public sealed record CaseEntity(string Key, string Label);

/// <summary>
/// Deciding when two alerts are about the same thing.
///
/// This is the whole of case grouping, and it is short on purpose. Anything cleverer — scoring, graphs,
/// transitive association — produces cases whose membership nobody can explain, and a case an analyst
/// cannot explain is one they stop trusting and then stop using.
///
/// The rule is: the asset if the enrichment found one, otherwise the subject.
///
/// The asset comes first because it is what makes grouping work across rules that see the same machine
/// differently. A brute-force rule identifies an address and a lockout rule identifies an account; both
/// enrich to <c>dc01</c>, so both land in the one investigation about dc01. Without that, they are two
/// unrelated subjects and the analyst is the one who has to notice — which is the work the case was
/// supposed to remove.
/// </summary>
public static class CaseCorrelation
{
    /// <summary>The fact an asset enrichment publishes for what it matched.</summary>
    private const string AssetName = "asset.name";

    public static CaseEntity For(Alert alert, IReadOnlyDictionary<string, string> enrichment)
    {
        if (enrichment.TryGetValue(AssetName, out var asset) && !string.IsNullOrWhiteSpace(asset))
            return new CaseEntity($"asset:{asset.Trim().ToLowerInvariant()}", asset.Trim());

        // The subject as the rule wrote it. Lower-cased for the key because "AiServices" and "aiservices"
        // are the same host, and kept as written for the label because that is what people recognise.
        var subject = string.IsNullOrWhiteSpace(alert.Subject) ? alert.AlertId : alert.Subject;

        return new CaseEntity($"subject:{subject.Trim().ToLowerInvariant()}", subject.Trim());
    }

    /// <summary>
    /// A title for a case opened by this alert.
    ///
    /// Named after the entity rather than the rule, because the case will very likely go on to hold alerts
    /// from other rules — and a case called "Brute force detection" that contains four other kinds of
    /// alert is worse than no title.
    /// </summary>
    public static string Title(CaseEntity entity) => entity.Label;
}
