namespace Sentinel.Domain.Platform;

/// <summary>
/// An engine process, and what it is actually enforcing.
///
/// Two problems, one row.
///
/// The console could not say whether an engine was running. It showed "engine: enabled, ticking every 10s"
/// read from the API's own configuration — and the API does not evaluate anything. With the engine stopped,
/// crash-looping or unable to reach the database, the console looked exactly the same as with it healthy,
/// while nothing was being detected. For a platform whose entire purpose is to notice things, being unable
/// to notice that it has stopped noticing is the worst failure it has.
///
/// The same applied to the safety rails. <c>neverBlock: 3</c> came from the API's copy of the settings, so
/// a deployment that configured the never-block list on one host and not the other showed a console
/// promising protection that the process doing the blocking had never heard of.
///
/// So the engine writes down who it is and what it is enforcing, and the console reads that instead of
/// guessing from its own configuration.
/// </summary>
public class EngineNode
{
    /// <summary>Which process. Defaults to the machine name, which in Kubernetes is the pod name.</summary>
    public string NodeId { get; set; } = "";

    /// <summary>When it last completed a tick. Staleness is how the console decides it has gone away.</summary>
    public DateTime LastSeenAt { get; set; }

    public DateTime StartedAt { get; set; }

    /// <summary>Build identity, so a half-upgraded deployment is visible rather than puzzling.</summary>
    public string Version { get; set; } = "";

    // -- what this node is enforcing -----------------------------------------------------------

    public bool Enabled { get; set; }
    public int TickSeconds { get; set; }
    public int MaxConcurrentRules { get; set; }

    /// <summary>The kill switch, as this process sees it.</summary>
    public bool ActionsEnabled { get; set; }

    /// <summary>How many entries are on this node's never-act list. Zero when nothing is protected.</summary>
    public int NeverActEntries { get; set; }

    // -- what it last did ----------------------------------------------------------------------

    public int LastTickRulesEvaluated { get; set; }
    public int LastTickAlertsRaised { get; set; }
    public long LastTickDurationMs { get; set; }
}
