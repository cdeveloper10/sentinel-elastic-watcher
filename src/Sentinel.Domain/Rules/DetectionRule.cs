namespace Sentinel.Domain.Rules;

/// <summary>
/// A condition somebody wants watched, and what should happen when it holds.
///
/// The mutable record is the rule; what actually ran is a <see cref="RuleVersion"/>. An alert points at
/// the version, never at this, because "why did this fire?" is asked weeks later about a rule that has
/// been edited three times since. Without that split the answer is whatever the rule says today, which is
/// not the question.
/// </summary>
public class DetectionRule
{
    public int Id { get; set; }

    public string Name { get; set; } = "";
    public string Description { get; set; } = "";

    /// <summary>Whether the engine schedules it. Separate from deletion so a rule can be stood down and kept.</summary>
    public bool Enabled { get; set; }

    /// <summary>One of <see cref="Severity"/>.</summary>
    public string Severity { get; set; } = Rules.Severity.Medium;

    /// <summary>The <see cref="Connections.Connection"/> the events are read from.</summary>
    public int ConnectionId { get; set; }

    /// <summary>Number of the version currently in force, matching a row in <see cref="RuleVersion"/>.</summary>
    public int CurrentVersion { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string CreatedBy { get; set; } = "";
    public string UpdatedBy { get; set; } = "";

    public ICollection<RuleVersion> Versions { get; set; } = [];
}

public static class Severity
{
    public const string Low = "LOW";
    public const string Medium = "MEDIUM";
    public const string High = "HIGH";
    public const string Critical = "CRITICAL";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Low, Medium, High, Critical };

    public static bool IsKnown(string? severity) => severity is not null && All.Contains(severity);
}

public static class DetectionStrategyType
{
    /// <summary>Any matching document is a detection. For conditions where one occurrence is the event.</summary>
    public const string Match = "match";

    /// <summary>
    /// Group, count within a window, fire above a threshold. Covers everything the brief called threshold,
    /// frequency and aggregation: those differ in what they count, not in how the counting works.
    /// </summary>
    public const string Threshold = "threshold";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Match, Threshold };
}
