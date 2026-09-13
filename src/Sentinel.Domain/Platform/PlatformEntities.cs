namespace Sentinel.Domain.Platform;

/// <summary>
/// How far a rule has been evaluated.
///
/// Persisted rather than held in memory because the alternative — starting from "one window back" after
/// every restart — means a deploy silently skips whatever happened while the process was down. For a
/// platform whose job is not to miss things, that is the difference between a rolling update and an
/// outage nobody notices.
/// </summary>
public class RuleCheckpoint
{
    public int RuleId { get; set; }

    /// <summary>Everything up to this instant has been evaluated. Half-open: the next window starts here.</summary>
    public DateTime EvaluatedTo { get; set; }

    public DateTime UpdatedAt { get; set; }

    /// <summary>Set when a catch-up was capped, so an operator can see coverage was incomplete.</summary>
    public bool LastRunSkippedBacklog { get; set; }

    public DateTime? LastRunAt { get; set; }
    public int LastRunWindows { get; set; }
    public int LastRunAlerts { get; set; }
    public long LastRunDurationMs { get; set; }

    /// <summary>Last failure, kept so "why is this rule quiet?" has an answer in the UI.</summary>
    public string? LastError { get; set; }

    public DateTime? LastErrorAt { get; set; }

    /// <summary>Consecutive failures, used to back a failing rule off rather than hammering a broken cluster.</summary>
    public int ConsecutiveFailures { get; set; }
}

/// <summary>
/// A subject that fired recently, so cooldown survives a restart.
///
/// A row rather than a cache entry: losing these on a deploy would let every subject that was being
/// suppressed fire again at once, which turns a rolling update into an alert storm and, with actions
/// attached, into a wave of blocks.
/// </summary>
public class CooldownEntry
{
    public string Key { get; set; } = "";
    public DateTime FiredAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>
/// Which node currently owns a rule's evaluation.
///
/// Leases expire rather than being released, so a node that dies mid-evaluation does not hold its rules
/// until somebody notices. The row is kept after release so the last owner stays visible.
/// </summary>
public class RuleLease
{
    public int RuleId { get; set; }
    public string Owner { get; set; } = "";
    public DateTime AcquiredAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>
/// Counts disruptive actions inside a window, so the safety caps hold across restarts and across nodes.
/// </summary>
public class ActionRateCounter
{
    public string Key { get; set; } = "";
    public DateTime WindowStart { get; set; }
    public int Count { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>
/// Who did what.
///
/// Separate from the action execution log, which records what the platform did to other systems. This
/// records what people did to the platform: created a rule, armed it, read a secret. For a system that
/// blocks things automatically, "who armed the rule that locked out the finance team" is the question
/// that gets asked, and it cannot be answered from execution records alone.
/// </summary>
public class AuditEntry
{
    public long Id { get; set; }

    public DateTime OccurredAt { get; set; }

    /// <summary>Username, or a system identity such as <c>engine</c> for scheduled work.</summary>
    public string Actor { get; set; } = "";

    /// <summary>One of <see cref="AuditOperation"/>.</summary>
    public string Operation { get; set; } = "";

    public string ResourceType { get; set; } = "";
    public string ResourceId { get; set; } = "";

    /// <summary><c>SUCCESS</c> or <c>DENIED</c> or <c>FAILED</c>. A refused attempt is worth as much as a successful one.</summary>
    public string Result { get; set; } = "SUCCESS";

    public string? SourceIp { get; set; }

    /// <summary>What changed, as JSON. Never contains secret values — only which secret names were set.</summary>
    public string? Changes { get; set; }

    public string? Detail { get; set; }

    /// <summary>Ties platform activity to the request that caused it.</summary>
    public string? CorrelationId { get; set; }
}

public static class AuditOperation
{
    public const string RuleCreated = "RULE_CREATED";
    public const string RuleUpdated = "RULE_UPDATED";
    public const string RuleEnabled = "RULE_ENABLED";
    public const string RuleDisabled = "RULE_DISABLED";
    public const string RuleDeleted = "RULE_DELETED";
    public const string RuleTested = "RULE_DRY_RUN";

    public const string ConnectionCreated = "CONNECTION_CREATED";
    public const string ConnectionUpdated = "CONNECTION_UPDATED";
    public const string ConnectionDeleted = "CONNECTION_DELETED";
    public const string ConnectionTested = "CONNECTION_TESTED";
    public const string ConnectionSecretRead = "CONNECTION_SECRET_READ";

    public const string AlertAcknowledged = "ALERT_ACKNOWLEDGED";
    public const string AlertResolved = "ALERT_RESOLVED";

    public const string ActionExecuted = "ACTION_EXECUTED";
    public const string ActionFailed = "ACTION_FAILED";
    public const string ActionSkipped = "ACTION_SKIPPED";
    public const string IpBlocked = "IP_BLOCKED";
    public const string UserBlocked = "USER_BLOCKED";

    public const string UserLogin = "USER_LOGIN";
    public const string UserLoginFailed = "USER_LOGIN_FAILED";
    public const string UserPermissionChanged = "USER_PERMISSION_CHANGED";

    public const string EngineKillSwitch = "ENGINE_KILL_SWITCH";
    public const string CheckpointReset = "CHECKPOINT_RESET";
}

/// <summary>An operator of the platform.</summary>
public class PlatformUser
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }

    public ICollection<PlatformUserRole> Roles { get; set; } = [];
}

public class PlatformRole
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";

    /// <summary>JSON array of permission names. A small closed set, so a table of its own buys nothing.</summary>
    public string PermissionsJson { get; set; } = "[]";

    /// <summary>Built-in roles cannot be deleted, so a deployment cannot be left with no administrator.</summary>
    public bool IsSystem { get; set; }
}

public class PlatformUserRole
{
    public int UserId { get; set; }
    public PlatformUser? User { get; set; }

    public int RoleId { get; set; }
    public PlatformRole? Role { get; set; }
}
