namespace Sentinel.Domain.Alerts;

/// <summary>
/// One attempt to do something about an alert, and how it went.
///
/// Kept separate from the alert because the two answer different questions and have different lifetimes:
/// an analyst resolves an alert, while an execution is a fact about what the platform did to a live system
/// and is never edited afterwards. It is also the record that makes an automated blocking platform
/// accountable — "which addresses did we block last night, and did any of it fail" is a question the
/// alert table cannot answer.
/// </summary>
public class ActionExecution
{
    public long Id { get; set; }

    public long AlertId { get; set; }
    public Alert? Alert { get; set; }

    public int RuleId { get; set; }
    public int RuleVersion { get; set; }

    /// <summary>Registry key of the provider that ran, e.g. <c>block_ip</c>.</summary>
    public string ActionType { get; set; } = "";

    /// <summary>Name of the connection used. The endpoint and credentials are not recorded.</summary>
    public string ConnectionName { get; set; } = "";

    /// <summary>What was acted on — the address blocked, the account suspended, the number messaged.</summary>
    public string Target { get; set; } = "";

    /// <summary>
    /// Stable key for this alert-and-action pair, sent to the external system where it accepts one.
    ///
    /// The same alert reaching the dispatcher twice — a retry, a restart mid-run, two nodes racing — must
    /// not become two independent blocks. Persisted with a unique constraint so the guarantee survives the
    /// process that made it.
    /// </summary>
    public string IdempotencyKey { get; set; } = "";

    /// <summary>One of <see cref="ActionExecutionStatus"/>.</summary>
    public string Status { get; set; } = ActionExecutionStatus.Pending;

    public DateTime? StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public int DurationMs { get; set; }

    public int RetryCount { get; set; }
    public DateTime? NextAttemptAt { get; set; }

    public string? ErrorCode { get; set; }

    /// <summary>Failure detail, already stripped of anything the connection holds in confidence.</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>What was sent, with secrets removed. The audit answer to "what exactly did we ask for".</summary>
    public string? RequestSummary { get; set; }

    public int? ResponseStatusCode { get; set; }

    public DateTime CreatedAt { get; set; }
}

public static class ActionExecutionStatus
{
    public const string Pending = "PENDING";
    public const string Running = "RUNNING";
    public const string Success = "SUCCESS";
    public const string Failed = "FAILED";
    public const string Retrying = "RETRYING";

    /// <summary>Out of attempts. Kept rather than dropped, because an action that never ran is an incident.</summary>
    public const string DeadLetter = "DEAD_LETTER";

    /// <summary>Not attempted, and why is recorded: a safety rail, a disabled connection, an allowlisted subject.</summary>
    public const string Skipped = "SKIPPED";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Pending, Running, Success, Failed, Retrying, DeadLetter, Skipped
    };

    /// <summary>Statuses that will not change again without someone intervening.</summary>
    public static bool IsTerminal(string status) =>
        status.Equals(Success, StringComparison.OrdinalIgnoreCase) ||
        status.Equals(DeadLetter, StringComparison.OrdinalIgnoreCase) ||
        status.Equals(Skipped, StringComparison.OrdinalIgnoreCase);
}
