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
    /// What the enrichments knew about this alert's subject, keyed <c>&lt;enrichment&gt;.&lt;fact&gt;</c>.
    ///
    /// Stored on the alert rather than looked up when somebody opens it, because it is evidence: what the
    /// inventory said at the moment the platform decided is what explains the decision, and an inventory
    /// edited next week must not change the answer to "why was this treated as critical".
    ///
    /// Null when no enrichment is registered or none had anything to say — those are different from an
    /// empty object and the console says which.
    /// </summary>
    public string? EnrichmentJson { get; set; }

    /// <summary>
    /// The investigation this alert is part of, where grouping is on and found one.
    ///
    /// Nullable because an alert belonging to no case is still a complete alert: grouping can be switched
    /// off, and a failure to file one must never become a failure to record it.
    /// </summary>
    public int? CaseId { get; set; }

    public Case? Case { get; set; }

    /// <summary>
    /// Whether the alert deserved to exist. One of <see cref="AlertDisposition"/>, recorded when it is
    /// resolved.
    ///
    /// The status says somebody looked; this says whether the rule was right, and they are different
    /// questions. Without it "which of my rules are noise" cannot be answered at all — and a platform
    /// nobody can answer that about is one whose alerts are eventually ignored wholesale, which is a
    /// worse failure than any single missed detection.
    ///
    /// Null until an alert is resolved, and on every alert resolved before this existed. A rate computed
    /// over alerts nobody has judged would be a number with no meaning, so those are excluded rather than
    /// assumed either way.
    /// </summary>
    public string? Disposition { get; set; }

    /// <summary>
    /// True when the rule fired but its actions were deliberately not run — a dry run never writes alerts,
    /// but a safety rail or a disabled dispatcher can produce one.
    /// </summary>
    public bool ActionsSuppressed { get; set; }

    public string? SuppressionReason { get; set; }

    public ICollection<ActionExecution> Executions { get; set; } = [];
}

/// <summary>
/// What an alert turned out to be.
///
/// Four values rather than two, because "the rule was wrong" and "the rule was right and the activity was
/// authorised" are different facts and only the first is a defect. A backup job that trips a rule every
/// Sunday night is a benign positive: the detection worked, and what wants fixing is an exception, not the
/// rule's logic. Counting those as false positives would condemn rules that are working.
/// </summary>
public static class AlertDisposition
{
    /// <summary>Real, and worth acting on.</summary>
    public const string TruePositive = "TRUE_POSITIVE";

    /// <summary>The rule matched something it should not have. The only value that counts as a defect.</summary>
    public const string FalsePositive = "FALSE_POSITIVE";

    /// <summary>The rule matched correctly, and the activity was authorised or expected.</summary>
    public const string Benign = "BENIGN";

    /// <summary>The same event, already covered by another alert.</summary>
    public const string Duplicate = "DUPLICATE";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        TruePositive, FalsePositive, Benign, Duplicate
    };

    public static bool IsKnown(string? value) => value is not null && All.Contains(value);

    public static string? Canonical(string? value) =>
        value is null ? null : All.FirstOrDefault(v => v.Equals(value, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Whether this disposition counts against the rule that produced it.
    ///
    /// Only a false positive does. A duplicate is a grouping problem, a benign positive wants an exception,
    /// and neither says the detection logic is wrong.
    /// </summary>
    public static bool IsRuleDefect(string? value) =>
        FalsePositive.Equals(value, StringComparison.OrdinalIgnoreCase);
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
