using Sentinel.Domain.Rules;

namespace Sentinel.Application.Enrichment;

/// <summary>What an enrichment is given: the alert about to be recorded, before it is recorded.</summary>
public sealed record EnrichmentRequest(
    int RuleId,
    string RuleName,
    string Severity,

    /// <summary>What the alert is about — the fields the rule grouped by.</summary>
    IReadOnlyDictionary<string, string> Subject,

    /// <summary>One of the events behind it, where the source could provide one.</summary>
    IReadOnlyDictionary<string, string>? Sample)
{
    /// <summary>
    /// The first of these the subject carries, which is how an enrichment finds the thing it knows about
    /// without the rule having had to name its fields the way the enrichment expects.
    /// </summary>
    public string? SubjectValue(params string[] fields)
    {
        foreach (var field in fields)
        {
            if (Subject.TryGetValue(field, out var value) && !string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }

        // A rule grouped by one field has exactly one value, and insisting on the name would mean an
        // enrichment that works for `source.ip` and not for `SourceIP.keyword` — which is most estates.
        return Subject.Count == 1 ? Subject.Values.First().Trim() : null;
    }
}

/// <summary>
/// What an enrichment found, and whether it thinks the alert is more serious than the rule said.
/// </summary>
public sealed record EnrichmentResult(
    IReadOnlyDictionary<string, string> Facts,

    /// <summary>
    /// A severity this alert should not be below, or null for no opinion.
    ///
    /// A floor rather than a value, and the pipeline only ever raises: an enrichment that could lower
    /// severity would let a stale inventory entry quietly downgrade a real incident, and the failure would
    /// be invisible because the alert still exists and still looks ordinary.
    /// </summary>
    string? SeverityFloor = null)
{
    public static readonly EnrichmentResult Nothing =
        new(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    public static EnrichmentResult From(
        Dictionary<string, string> facts, string? severityFloor = null) =>
        new(facts, Severity.IsKnown(severityFloor) ? severityFloor : null);
}

/// <summary>What the console needs to explain an enrichment without knowing what it is.</summary>
public sealed record EnrichmentDescriptor(
    string Name,
    string DisplayName,
    string Description,

    /// <summary>
    /// The fact names this produces, without the prefix.
    ///
    /// Declared so the rule builder can offer <c>{{enrich.network.scope}}</c> as a chip rather than
    /// leaving an author to discover it from an alert that has already fired. A test asserts the
    /// declaration matches what enrichment actually returns — the same arrangement as a strategy's
    /// evidence keys, and for the same reason: a list maintained by hand drifts.
    /// </summary>
    IReadOnlyList<string> Facts);

/// <summary>
/// Something known about the subject of an alert that the log line does not say.
///
/// This is the step between detecting and responding that the platform did not have. An alert carried the
/// fields the rule grouped by and one sample event, and every decision after that — how serious this is,
/// whether to block — was made from those alone. "Block 10.5.5.5" is a different decision depending on
/// whether that address is a laptop or a domain controller, and nothing in the platform knew which.
///
/// Enrichments run after the alert has survived cooldown and deduplication and before it is written, so
/// their facts are part of the record rather than something bolted on afterwards, and a suppressed
/// candidate costs nothing.
///
/// A provider does not decide anything. It answers with facts; what the platform does with them is the
/// pipeline's business and the rule author's.
/// </summary>
public interface IEnrichment
{
    /// <summary>
    /// Registry key, and the prefix its facts appear under: <c>network</c> produces
    /// <c>{{enrich.network.scope}}</c>.
    /// </summary>
    string Name { get; }

    EnrichmentDescriptor Describe();

    Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default);
}
