using Sentinel.Application.Connections;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Detection;

/// <summary>
/// One thing the rule saw: a subject, how many events it had, and the evidence for saying so.
///
/// Not yet an alert. Cooldown and deduplication still get a say, and a candidate they refuse never becomes
/// one — which is why this type exists separately from the alert rather than being written straight out.
/// </summary>
public sealed record DetectionCandidate(
    IReadOnlyDictionary<string, string> Subject,
    long EventCount,
    TimeRange Window,
    IReadOnlyDictionary<string, object?> Evidence,

    /// <summary>
    /// One of the events behind this candidate, flattened to dotted field paths — reachable from a message
    /// or a payload as <c>sample.*</c>.
    ///
    /// Separate from <see cref="Subject"/> on purpose. The subject is what the rule grouped by and is true
    /// of every event in the group; the sample is one line out of many and its fields are true only of that
    /// line. Merging them would let an author write a message that reads as though it described all of them.
    /// </summary>
    IReadOnlyDictionary<string, string>? Sample = null);

public sealed record StrategyResult(
    IReadOnlyList<DetectionCandidate> Candidates,
    bool Truncated,
    long SourceElapsedMs)
{
    public static readonly StrategyResult Empty = new([], false, 0);
}

public sealed record StrategyRequest(
    RuleDefinition Rule,
    Connection Connection,
    TimeRange Window);

/// <summary>
/// How a rule decides that something happened.
///
/// The brief asked for five of these — match, threshold, frequency, aggregation, time window — but those
/// are not five kinds of decision. Threshold and frequency are one calculation with different window
/// semantics; aggregation is how the grouping is done, not what is decided; and a time window is a
/// parameter every strategy takes. Modelled as five siblings they would share most of their code and
/// differ in none of the interesting places.
///
/// So the pipeline is fixed — query, group, window — and only the <em>predicate</em> varies. Two
/// implementations cover the brief's five, and a third would be added for something genuinely different,
/// such as "a value seen for the first time".
/// </summary>
public interface IDetectionStrategy
{
    /// <summary>Key this strategy is registered and referenced under.</summary>
    string Type { get; }

    /// <summary>
    /// The names this strategy puts in a candidate's evidence — the <c>evidence.*</c> placeholders an
    /// author may use in a message or in a payload.
    ///
    /// Declared by the strategy rather than listed centrally, for the same reason validation is: what
    /// evidence a strategy produces is the strategy's business, and a copy of that list kept anywhere else
    /// goes stale the first time one of them adds a field. This is what lets the API say that
    /// <c>evidence.eventCounts</c> is a typo at save time, instead of sending an empty field at 3 a.m.
    /// </summary>
    IReadOnlyList<string> EvidenceKeys { get; }

    /// <summary>
    /// Whether a rule's settings make sense for this strategy, checked at save time so the author sees the
    /// message instead of the rule failing quietly on its first run.
    /// </summary>
    ValidationResult Validate(RuleDefinition rule);

    /// <summary>
    /// Asks the source what happened in the window and returns what qualifies.
    ///
    /// Takes the source as a parameter rather than holding one: a strategy is stateless and shared, and
    /// which source a rule reads from is the rule's business.
    /// </summary>
    Task<StrategyResult> EvaluateAsync(StrategyRequest request, IEventSource source, CancellationToken ct = default);
}

/// <summary>
/// Strategies by name.
///
/// The registry is what keeps the engine from growing a switch. It resolves a rule's declared strategy and
/// hands back something that can evaluate it; adding a strategy means registering an implementation, and
/// no code that orchestrates evaluation has to change.
/// </summary>
public interface IDetectionStrategyRegistry
{
    IDetectionStrategy Resolve(string type);

    bool TryResolve(string? type, out IDetectionStrategy strategy);

    IReadOnlyCollection<string> Registered { get; }
}

public sealed class DetectionStrategyRegistry : IDetectionStrategyRegistry
{
    private readonly IReadOnlyDictionary<string, IDetectionStrategy> _strategies;

    public DetectionStrategyRegistry(IEnumerable<IDetectionStrategy> strategies)
    {
        _strategies = strategies.ToDictionary(s => s.Type, StringComparer.OrdinalIgnoreCase);

        if (_strategies.Count == 0)
            throw new InvalidOperationException("No detection strategies were registered.");
    }

    public IReadOnlyCollection<string> Registered => _strategies.Keys.ToList();

    public IDetectionStrategy Resolve(string type) =>
        TryResolve(type, out var strategy)
            ? strategy
            : throw new UnknownStrategyException(type, Registered);

    public bool TryResolve(string? type, out IDetectionStrategy strategy)
    {
        if (type is not null && _strategies.TryGetValue(type, out var found))
        {
            strategy = found;
            return true;
        }

        strategy = null!;
        return false;
    }
}

public sealed class UnknownStrategyException(string type, IReadOnlyCollection<string> known)
    : Exception($"No detection strategy is registered for '{type}'. Registered: {string.Join(", ", known)}.")
{
    public string RequestedType { get; } = type;
}
