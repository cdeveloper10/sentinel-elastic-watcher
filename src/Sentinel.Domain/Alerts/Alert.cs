namespace Sentinel.Domain.Alerts;

/// <summary>
/// Something a rule found. One row per finding, not per event.
///
/// It points at the rule <em>version</em> that produced it, and carries the evidence with it rather than a
/// reference to look up later. Both matter for the same reason: an analyst reads this weeks afterwards,
/// by which time the rule has been tuned twice and the index the events lived in has rolled over. An
/// alert that cannot explain itself without the rest of the estate still being as it was is not evidence.
/// </summary>
public class Alert
{
    public long Id { get; set; }

    /// <summary>Public identifier, safe to quote in a ticket or an SMS.</summary>
    public string AlertId { get; set; } = "";

    /// <summary>
    /// Deterministic identity of the evaluation that produced this. Unique in the store, which is what
    /// makes deduplication a constraint the database enforces rather than a check that can race.
    /// </summary>
    public string Fingerprint { get; set; } = "";

    public int RuleId { get; set; }
    public int RuleVersion { get; set; }
    public string RuleName { get; set; } = "";
    public string Severity { get; set; } = "";

    /// <summary>Readable identity of what was detected, e.g. <c>source.ip=10.10.10.20</c>.</summary>
    public string Subject { get; set; } = "";

    /// <summary>The subject's fields as JSON, so an action can read <c>source.ip</c> without parsing the label.</summary>
    public string SubjectJson { get; set; } = "{}";

    /// <summary>Lifted out of the subject for filtering, when the rule grouped by them.</summary>
    public string? SourceIp { get; set; }
    public string? UserId { get; set; }

    public long EventCount { get; set; }

    /// <summary>Why the rule fired: counts, threshold, window, and for a match rule the document itself.</summary>
    public string EvidenceJson { get; set; } = "{}";

    /// <summary>
    /// One of the events behind the alert, flattened to dotted field paths.
    ///
    /// Stored rather than only handed to the actions, because an SMS reading "see alert 41" is worth little
    /// if alert 41 cannot then show the log line that caused it. Null when the source could not provide one.
    /// </summary>
    public string? SampleJson { get; set; }

    public DateTime WindowFrom { get; set; }
    public DateTime WindowTo { get; set; }
    public DateTime DetectedAt { get; set; }

    /// <summary>One of <see cref="AlertStatus"/>. Separate from action status: an alert can be resolved while an action failed.</summary>
    public string Status { get; set; } = AlertStatus.Detected;

    public string? AcknowledgedBy { get; set; }
    public DateTime? AcknowledgedAt { get; set; }
    public string? ResolvedBy { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public string? ResolutionNote { get; set; }

    /// <summary>
    /// True when the rule fired but its actions were deliberately not run — a dry run never writes alerts,
    /// but a safety rail or a disabled dispatcher can produce one.
    /// </summary>
    public bool ActionsSuppressed { get; set; }

    public string? SuppressionReason { get; set; }

    public ICollection<ActionExecution> Executions { get; set; } = [];
}

public static class AlertStatus
{
    public const string Detected = "DETECTED";
    public const string Acknowledged = "ACKNOWLEDGED";
    public const string Resolved = "RESOLVED";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Detected, Acknowledged, Resolved };

    /// <summary>An alert moves forward only. Reopening one would lose who closed it and when.</summary>
    public static bool CanTransition(string from, string to) => (from.ToUpperInvariant(), to.ToUpperInvariant()) switch
    {
        (Detected, Acknowledged) => true,
        (Detected, Resolved) => true,
        (Acknowledged, Resolved) => true,
        _ => false
    };
}
