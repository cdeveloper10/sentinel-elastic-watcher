using Microsoft.Extensions.Logging;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Enrichment;

/// <summary>Everything the enrichments between them found, and the severity they argue for.</summary>
public sealed record EnrichedAlert(
    IReadOnlyDictionary<string, string> Facts,
    string Severity)
{
    public bool Any => Facts.Count > 0;
}

/// <summary>
/// Runs every registered enrichment over one alert and merges what they answer.
///
/// Three properties matter more than the merging:
///
/// <b>An enrichment that fails cannot stop the alert.</b> These reach inventories, directories and
/// third-party services — things that are down at exactly the moment an incident is happening. An alert
/// that was not recorded because a lookup timed out is the worst possible trade, so a failure is logged,
/// recorded as a fact, and the alert proceeds without it.
///
/// <b>Facts are namespaced by the enrichment that produced them.</b> Two enrichments both answering
/// "owner" is normal, and neither should overwrite the other.
///
/// <b>Severity is only ever raised.</b> An enrichment may say an alert is more serious than the rule
/// assumed — a critical asset, a privileged account. It may not say it is less: a stale inventory entry
/// would then quietly downgrade a real incident, and nothing about the alert would look wrong.
/// </summary>
public sealed class EnrichmentPipeline(
    IEnumerable<IEnrichment> enrichments,
    ILogger<EnrichmentPipeline> logger)
{
    private readonly IReadOnlyList<IEnrichment> _enrichments = enrichments.ToList();

    /// <summary>No enrichments at all, for a caller that has no opinion about the stage.</summary>
    public static readonly EnrichmentPipeline None =
        new([], Microsoft.Extensions.Logging.Abstractions.NullLogger<EnrichmentPipeline>.Instance);

    /// <summary>Beyond this an enrichment is holding up detection rather than informing it.</summary>
    public static readonly TimeSpan PerEnrichmentTimeout = TimeSpan.FromSeconds(5);

    private static readonly IReadOnlyList<string> Order =
        [Severity.Low, Severity.Medium, Severity.High, Severity.Critical];

    public async Task<EnrichedAlert> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default)
    {
        if (_enrichments.Count == 0)
            return new EnrichedAlert(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), request.Severity);

        var facts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var severity = request.Severity;

        foreach (var enrichment in _enrichments)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Bounded per enrichment rather than for all of them together, so one slow lookup cannot
                // consume the budget of the ones after it.
                using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
                bounded.CancelAfter(PerEnrichmentTimeout);

                var result = await enrichment.EnrichAsync(request, bounded.Token);

                foreach (var (key, value) in result.Facts)
                    facts[$"{enrichment.Name}.{key}"] = value;

                severity = Raise(severity, result.SeverityFloor);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Recorded as a fact, not only logged. An action whose message reads "owner: " should be
                // distinguishable from one where nobody was asked, and the person reading the alert is
                // not reading the engine's log.
                facts[$"{enrichment.Name}.error"] = Describe(ex);

                logger.LogWarning(
                    ex, "Enrichment {Name} failed for rule {RuleId}; the alert proceeds without it",
                    enrichment.Name, request.RuleId);
            }
        }

        return new EnrichedAlert(facts, severity);
    }

    /// <summary>The higher of the two. An unknown or absent floor changes nothing.</summary>
    internal static string Raise(string current, string? floor)
    {
        if (!Severity.IsKnown(floor))
            return current;

        var currentRank = Rank(current);
        var flooredRank = Rank(floor!);

        return flooredRank > currentRank ? Order[flooredRank] : current;
    }

    private static int Rank(string severity)
    {
        for (var i = 0; i < Order.Count; i++)
        {
            if (Order[i].Equals(severity, StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return 0;
    }

    private static string Describe(Exception ex) =>
        ex is OperationCanceledException
            ? $"did not answer within {PerEnrichmentTimeout.TotalSeconds:0} seconds"
            : ex.Message.Length > 200 ? ex.Message[..200] : ex.Message;

    /// <summary>What is registered, for the console and for the rule builder's placeholder list.</summary>
    public IReadOnlyList<EnrichmentDescriptor> Describe() =>
        _enrichments.Select(e => e.Describe()).ToList();
}
