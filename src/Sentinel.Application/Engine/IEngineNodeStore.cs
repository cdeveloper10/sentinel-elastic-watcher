namespace Sentinel.Application.Engine;

/// <summary>What an engine reports about itself after a tick.</summary>
public sealed record EngineHeartbeat(
    string NodeId,
    DateTimeOffset StartedAt,
    string Version,
    bool Enabled,
    int TickSeconds,
    int MaxConcurrentRules,
    bool ActionsEnabled,
    int NeverActEntries,
    int RulesEvaluated,
    int AlertsRaised,
    long DurationMs);

/// <summary>
/// Where an engine says it is alive and what it is enforcing.
///
/// Exists because the console had no way to know either. It read the engine's tick interval and the
/// never-act list out of the *API's* configuration — and the API neither evaluates rules nor blocks
/// anything, so a stopped engine and a healthy one looked identical, and a never-act list configured on
/// one host and not the other showed as protection that the process doing the blocking had never seen.
/// </summary>
public interface IEngineNodeStore
{
    Task ReportAsync(EngineHeartbeat heartbeat, CancellationToken ct = default);

    /// <summary>Removes nodes that have been silent long enough to be certainly gone.</summary>
    Task<int> SweepAsync(TimeSpan olderThan, CancellationToken ct = default);
}
