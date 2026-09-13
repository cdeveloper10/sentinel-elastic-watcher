using System.Text.Json;

namespace Sentinel.Application.Security;

/// <summary>
/// What a person is allowed to do.
///
/// The separation that matters is between authoring a rule and reading a connection's secrets. A rule
/// manager composes what the platform will do; a connection manager holds the credentials it does it
/// with. Collapsing those into one "admin" role means everyone who can write a detection can also read
/// the key that blocks traffic — and the brief calls this out for good reason.
///
/// The second separation is between drafting a rule and arming it. A rule that is saved does nothing; a
/// rule that is enabled starts blocking addresses on a schedule. Those are different decisions and they
/// have different permissions.
/// </summary>
public static class Permission
{
    public const string RulesRead = "rules.read";
    public const string RulesCreate = "rules.create";
    public const string RulesUpdate = "rules.update";
    public const string RulesDelete = "rules.delete";

    /// <summary>Arming and disarming — separate from authoring, because this is what starts real actions.</summary>
    public const string RulesEnable = "rules.enable";

    /// <summary>Rehearsing a rule against real data. Reads events, executes nothing.</summary>
    public const string RulesTest = "rules.test";

    public const string AlertsRead = "alerts.read";
    public const string AlertsAcknowledge = "alerts.acknowledge";
    public const string AlertsResolve = "alerts.resolve";

    public const string ActionsRead = "actions.read";

    /// <summary>Seeing that a connection exists and whether it is healthy.</summary>
    public const string ConnectionsRead = "connections.read";

    /// <summary>Creating connections and setting their credentials. Deliberately not implied by rules.*.</summary>
    public const string ConnectionsManage = "connections.manage";

    public const string AuditRead = "audit.read";
    public const string UsersManage = "users.manage";

    /// <summary>Pausing the engine and resetting checkpoints. Operational rather than editorial.</summary>
    public const string EngineOperate = "engine.operate";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        RulesRead, RulesCreate, RulesUpdate, RulesDelete, RulesEnable, RulesTest,
        AlertsRead, AlertsAcknowledge, AlertsResolve,
        ActionsRead,
        ConnectionsRead, ConnectionsManage,
        AuditRead, UsersManage, EngineOperate
    };

    public static bool IsKnown(string? permission) => permission is not null && All.Contains(permission);
}

/// <summary>
/// The roles a deployment starts with.
///
/// Chosen so that the common shapes exist without anyone having to design a permission set on their first
/// day, and so that the dangerous combinations are not one of the defaults.
/// </summary>
public static class SystemRole
{
    public const string Admin = "Admin";
    public const string SecurityAnalyst = "Security Analyst";
    public const string RuleManager = "Rule Manager";
    public const string ReadOnly = "Read Only";
    public const string Auditor = "Auditor";

    public static IReadOnlyDictionary<string, (string Description, string[] Permissions)> Definitions { get; } =
        new Dictionary<string, (string, string[])>(StringComparer.OrdinalIgnoreCase)
        {
            [Admin] = ("Everything, including credentials and user management.", [.. Permission.All]),

            [SecurityAnalyst] = (
                "Investigates and resolves alerts, and can rehearse a rule against real data.",
                [
                    Permission.RulesRead, Permission.RulesTest,
                    Permission.AlertsRead, Permission.AlertsAcknowledge, Permission.AlertsResolve,
                    Permission.ActionsRead, Permission.ConnectionsRead
                ]),

            [RuleManager] = (
                // Notably absent: connections.manage. Authoring what the platform does must not carry the
                // right to read the credentials it does it with.
                "Writes and arms detection rules. Cannot read connection credentials.",
                [
                    Permission.RulesRead, Permission.RulesCreate, Permission.RulesUpdate,
                    Permission.RulesDelete, Permission.RulesEnable, Permission.RulesTest,
                    Permission.AlertsRead, Permission.ActionsRead, Permission.ConnectionsRead
                ]),

            [ReadOnly] = (
                "Sees rules, alerts and executions. Changes nothing.",
                [Permission.RulesRead, Permission.AlertsRead, Permission.ActionsRead, Permission.ConnectionsRead]),

            [Auditor] = (
                "Reads the audit trail and the record of what was done, and nothing else.",
                [Permission.AuditRead, Permission.AlertsRead, Permission.ActionsRead, Permission.RulesRead])
        };
}

/// <summary>Reads and writes the permission list a role carries.</summary>
public static class RolePermissions
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static IReadOnlyList<string> Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            var permissions = JsonSerializer.Deserialize<List<string>>(json, Options) ?? [];

            // An unknown permission in stored data is dropped rather than honoured: a name that no longer
            // means anything must not silently keep granting whatever it once did.
            return permissions.Where(Permission.IsKnown).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    public static string Write(IEnumerable<string> permissions) =>
        JsonSerializer.Serialize(
            permissions.Where(Permission.IsKnown).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToList());

    /// <summary>Everything the union of these roles allows.</summary>
    public static IReadOnlySet<string> Effective(IEnumerable<string> roleJsonDocuments)
    {
        var effective = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var json in roleJsonDocuments)
            effective.UnionWith(Read(json));

        return effective;
    }
}
