using Sentinel.Application.Rules;

namespace Sentinel.Api.Endpoints;

/// <summary>
/// The shapes the write endpoints accept.
///
/// Separate from the domain entities on purpose: an entity carries fields a caller must never set — a
/// connection's ciphertext, a rule's version number, an alert's fingerprint — and binding straight onto
/// one is how a request ends up able to set them.
/// </summary>
public sealed record SignInRequest(string Username, string Password);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record CreateUserRequest(
    string Username, string DisplayName, string Password, List<string> Roles);

public sealed record SetUserRolesRequest(List<string> Roles);

public sealed record SetPasswordRequest(string Password);

public sealed record ConnectionRequest(
    string Name,
    string DisplayName,
    string Description,
    string Type,
    string Endpoint,
    string AuthenticationMode,
    int TimeoutSeconds,
    bool Enabled,

    /// <summary>
    /// Credential values, by name. Write-only: no response ever returns them, and omitting the field on an
    /// update leaves whatever is stored alone so that editing a timeout does not require re-entering a key.
    /// </summary>
    Dictionary<string, string>? Secrets,

    string? ConfigurationJson);

public sealed record RuleActionRequest(
    string Type,
    string Connection,
    Dictionary<string, string>? Settings);

public sealed record RuleRequest(
    string Name,
    string Description,
    string Severity,
    int ConnectionId,
    List<string> IndexPatterns,
    string? QueryJson,
    string TimestampField,
    string StrategyType,
    List<string> GroupBy,
    long Threshold,
    int WindowSeconds,
    int QueryDelaySeconds,
    int IntervalSeconds,
    int CooldownSeconds,
    List<RuleActionRequest>? Actions,

    /// <summary>Why this version exists, shown beside it in the version list.</summary>
    string? ChangeNote);

public sealed record DryRunRequest(int LookbackMinutes = 60);

/// <summary>
/// A condition the console is still editing: either builder rows or a hand-written clause.
///
/// Both fields, never one shape trying to be both. When rows are present they are what gets compiled and
/// the raw query is ignored — one source of truth per request, so a console bug cannot show a preview of
/// something other than what a save would store.
/// </summary>
public sealed record ConditionRequest(
    List<ConditionClause>? Conditions,
    string? QueryJson);

public sealed record ConditionPreviewRequest(
    int ConnectionId,
    List<string>? IndexPatterns,
    List<ConditionClause>? Conditions,
    string? QueryJson,
    string? TimestampField,
    List<string>? GroupBy,
    long Threshold,
    int LookbackMinutes = 15);

public sealed record ResolveAlertRequest(string? Note);

public sealed record ResetCheckpointRequest(DateTimeOffset? To);

public sealed record EnginePauseRequest(bool Enabled, string? Reason);
