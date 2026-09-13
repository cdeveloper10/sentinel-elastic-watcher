namespace Sentinel.Domain.Rules;

/// <summary>
/// One immutable definition of a rule. Every meaningful edit writes a new row rather than changing this one.
///
/// This is what the engine reads and what an alert points at. Keeping it immutable is what makes an
/// investigation possible: an analyst looking at a three-week-old alert sees the query, threshold and
/// window that produced it, not the ones somebody has since tuned.
/// </summary>
public class RuleVersion
{
    public int Id { get; set; }

    public int RuleId { get; set; }
    public DetectionRule? Rule { get; set; }

    /// <summary>Increments per rule, starting at 1.</summary>
    public int Version { get; set; }

    // -- what it watches ---------------------------------------------------------------------

    /// <summary>JSON array of index patterns. Validated against <c>IndexPatternRules</c> before it is stored.</summary>
    public string IndexPatternsJson { get; set; } = "[]";

    /// <summary>An Elasticsearch query clause, or empty for "everything in the window".</summary>
    public string QueryJson { get; set; } = "";

    /// <summary>The date field the window is applied to. Rarely anything but <c>@timestamp</c>, but never assumed.</summary>
    public string TimestampField { get; set; } = "@timestamp";

    // -- how it decides ----------------------------------------------------------------------

    /// <summary>One of <see cref="DetectionStrategyType"/>.</summary>
    public string StrategyType { get; set; } = DetectionStrategyType.Threshold;

    /// <summary>JSON array of fields the count is grouped by. The subject of the detection.</summary>
    public string GroupByJson { get; set; } = "[]";

    /// <summary>Events in one group within the window, at or above which the rule fires.</summary>
    public long Threshold { get; set; } = 1;

    /// <summary>Length of the window the count covers.</summary>
    public int WindowSeconds { get; set; } = 300;

    /// <summary>
    /// How far behind real time the engine reads, to let events finish arriving.
    ///
    /// Elasticsearch is not synchronous with the world: a log line written at 10:00:00 may be searchable at
    /// 10:00:20. Querying right up to now would miss it permanently, because the window it belonged to has
    /// already been evaluated and will not be looked at again. This is the single most common way a
    /// detection platform silently stops detecting.
    /// </summary>
    public int QueryDelaySeconds { get; set; } = 30;

    /// <summary>How often the engine evaluates the rule.</summary>
    public int IntervalSeconds { get; set; } = 60;

    /// <summary>
    /// After firing for a subject, how long before that same subject may fire again. Per subject, not per
    /// rule: silencing one address must not silence every other.
    /// </summary>
    public int CooldownSeconds { get; set; } = 1800;

    // -- what it does ------------------------------------------------------------------------

    /// <summary>JSON array of action bindings: type, connection, and per-action settings.</summary>
    public string ActionsJson { get; set; } = "[]";

    // -- provenance --------------------------------------------------------------------------

    public string Severity { get; set; } = Rules.Severity.Medium;
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";

    public DateTime CreatedAt { get; set; }
    public string CreatedBy { get; set; } = "";

    /// <summary>Free text saying what changed and why, shown in the version history.</summary>
    public string ChangeNote { get; set; } = "";

    public TimeSpan Window => TimeSpan.FromSeconds(WindowSeconds);
    public TimeSpan QueryDelay => TimeSpan.FromSeconds(QueryDelaySeconds);
    public TimeSpan Interval => TimeSpan.FromSeconds(IntervalSeconds);
    public TimeSpan Cooldown => TimeSpan.FromSeconds(CooldownSeconds);
}
