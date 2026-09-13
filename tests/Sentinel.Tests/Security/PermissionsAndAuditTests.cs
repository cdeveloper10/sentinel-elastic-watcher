using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Audit;
using Sentinel.Application.Security;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Security;

/// <summary>
/// Who may do what, and what the record of it may contain.
/// </summary>
public class PermissionsTests
{
    [Fact]
    public void Authoring_a_rule_does_not_carry_the_right_to_read_a_credential()
    {
        // The separation the brief singles out, and the one that is easiest to lose by collapsing roles
        // into a single "admin": a rule manager composes what the platform does, a connection manager
        // holds the key it does it with.
        var ruleManager = SystemRole.Definitions[SystemRole.RuleManager].Permissions;

        Assert.Contains(Permission.RulesCreate, ruleManager);
        Assert.Contains(Permission.RulesEnable, ruleManager);
        Assert.DoesNotContain(Permission.ConnectionsManage, ruleManager);
    }

    [Fact]
    public void An_analyst_can_investigate_and_rehearse_but_not_author()
    {
        var analyst = SystemRole.Definitions[SystemRole.SecurityAnalyst].Permissions;

        Assert.Contains(Permission.AlertsResolve, analyst);
        Assert.Contains(Permission.RulesTest, analyst);
        Assert.DoesNotContain(Permission.RulesCreate, analyst);
        Assert.DoesNotContain(Permission.RulesEnable, analyst);
    }

    [Fact]
    public void Arming_a_rule_is_a_separate_permission_from_writing_one()
    {
        // A saved rule does nothing; an enabled rule starts blocking addresses on a schedule. Different
        // decisions, so different permissions.
        Assert.NotEqual(Permission.RulesCreate, Permission.RulesEnable);
        Assert.Contains(Permission.RulesEnable, Permission.All);
    }

    [Fact]
    public void Read_only_grants_nothing_that_changes_anything()
    {
        var readOnly = SystemRole.Definitions[SystemRole.ReadOnly].Permissions;

        Assert.All(readOnly, p => Assert.EndsWith(".read", p, StringComparison.Ordinal));
    }

    [Fact]
    public void An_auditor_reads_the_trail_without_reading_credentials()
    {
        var auditor = SystemRole.Definitions[SystemRole.Auditor].Permissions;

        Assert.Contains(Permission.AuditRead, auditor);
        Assert.DoesNotContain(Permission.ConnectionsManage, auditor);
        Assert.DoesNotContain(Permission.UsersManage, auditor);
    }

    [Fact]
    public void Admin_holds_every_permission_and_nothing_invented() =>
        Assert.Equal(
            Permission.All.Order(),
            SystemRole.Definitions[SystemRole.Admin].Permissions.Order());

    [Fact]
    public void Every_system_role_names_only_permissions_that_exist()
    {
        // A role granting a name nothing checks is a role that appears to restrict and does not.
        foreach (var (role, definition) in SystemRole.Definitions)
        {
            Assert.All(definition.Permissions,
                p => Assert.True(Permission.IsKnown(p), $"Role '{role}' grants unknown permission '{p}'."));
        }
    }

    [Fact]
    public void A_stored_permission_that_no_longer_exists_is_dropped()
    {
        // A name that stopped meaning anything must not silently keep granting whatever it once did.
        var permissions = RolePermissions.Read("""["rules.read","rules.launch_missiles","alerts.read"]""");

        Assert.Equal(["rules.read", "alerts.read"], permissions);
    }

    [Fact]
    public void Malformed_stored_permissions_grant_nothing()
    {
        // Failing closed: an unreadable permission list must not read as "everything".
        Assert.Empty(RolePermissions.Read("not json"));
        Assert.Empty(RolePermissions.Read(null));
        Assert.Empty(RolePermissions.Read(""));
    }

    [Fact]
    public void Several_roles_combine_into_their_union()
    {
        var effective = RolePermissions.Effective([
            RolePermissions.Write([Permission.RulesRead]),
            RolePermissions.Write([Permission.AlertsResolve, Permission.RulesRead])
        ]);

        Assert.Equal(2, effective.Count);
        Assert.Contains(Permission.AlertsResolve, effective);
    }
}

/// <summary>
/// What reaches the audit trail, and — more importantly — what does not.
/// </summary>
public class AuditTrailTests : IDisposable
{
    private readonly TestDatabase _database = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero));

    public void Dispose() => _database.Dispose();

    [Fact]
    public async Task An_operation_is_recorded_with_its_actor_and_resource()
    {
        await NewTrail().RecordAsync(
            new Actor("alice", "10.0.0.5", "corr-1"),
            AuditOperationNames.RuleEnabled, "rule", "7");

        var entry = Assert.Single(await AllEntries());

        Assert.Equal("alice", entry.Actor);
        Assert.Equal("rule", entry.ResourceType);
        Assert.Equal("7", entry.ResourceId);
        Assert.Equal("10.0.0.5", entry.SourceIp);
        Assert.Equal("corr-1", entry.CorrelationId);
        Assert.Equal("SUCCESS", entry.Result);
    }

    [Fact]
    public async Task A_refused_attempt_is_recorded_too()
    {
        // Worth as much as a successful one: "who tried to arm this and was stopped" is a security
        // question, and an audit trail that only holds successes cannot answer it.
        await NewTrail().RecordAsync(
            new Actor("mallory"), AuditOperationNames.RuleEnabled, "rule", "7", result: "DENIED");

        Assert.Equal("DENIED", (await AllEntries()).Single().Result);
    }

    [Fact]
    public async Task A_credential_never_reaches_the_trail()
    {
        // The rule that is absolute and easy to break by accident. A connection's change set would
        // otherwise carry its API key into a table more people can read than are entitled to the key.
        await NewTrail().RecordAsync(
            Actor.System("test"),
            AuditOperationNames.ConnectionUpdated, "connection", "security-api",
            changes: new
            {
                name = "security-api",
                endpoint = "https://gateway.internal:5302",
                apiKey = "zvk_super_secret_value",
                password = "hunter2"
            });

        var entry = Assert.Single(await AllEntries());

        Assert.DoesNotContain("zvk_super_secret_value", entry.Changes!, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", entry.Changes!, StringComparison.Ordinal);

        // The non-secret detail is still there — an auditor needs to see what changed.
        Assert.Contains("gateway.internal", entry.Changes!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("apiKey")]
    [InlineData("API_KEY")]
    [InlineData("clientSecret")]
    [InlineData("passwordHash")]
    [InlineData("refreshToken")]
    [InlineData("secretCiphertext")]
    [InlineData("authorizationHeader")]
    public void Secret_bearing_field_names_are_recognised_whatever_their_shape(string field) =>
        Assert.True(AuditChanges.IsSensitive(field), $"'{field}' should never be recorded.");

    [Theory]
    [InlineData("endpoint")]
    [InlineData("name")]
    [InlineData("enabled")]
    [InlineData("severity")]
    public void Ordinary_fields_are_recorded(string field) =>
        Assert.False(AuditChanges.IsSensitive(field));

    [Fact]
    public void A_before_and_after_records_only_what_changed()
    {
        var changes = AuditChanges.Describe(
            new Dictionary<string, object?> { ["severity"] = "MEDIUM", ["threshold"] = 20 },
            new Dictionary<string, object?> { ["severity"] = "HIGH", ["threshold"] = 20 });

        Assert.NotNull(changes);
        Assert.Contains("severity", changes, StringComparison.Ordinal);
        Assert.DoesNotContain("threshold", changes, StringComparison.Ordinal);
    }

    [Fact]
    public void A_secret_that_changed_is_recorded_as_having_changed_and_no_more()
    {
        var changes = AuditChanges.Describe(
            new Dictionary<string, object?> { ["apiKey"] = "old-secret" },
            new Dictionary<string, object?> { ["apiKey"] = "new-secret" });

        Assert.NotNull(changes);
        Assert.Contains("apiKey", changes, StringComparison.Ordinal);
        Assert.DoesNotContain("old-secret", changes, StringComparison.Ordinal);
        Assert.DoesNotContain("new-secret", changes, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unchanged_object_produces_no_entry() =>
        Assert.Null(AuditChanges.Describe(
            new Dictionary<string, object?> { ["a"] = 1 },
            new Dictionary<string, object?> { ["a"] = 1 }));

    [Fact]
    public async Task A_trail_failure_does_not_stop_the_platform_acting()
    {
        // The opposite of the usual instinct, and deliberate: a full disk must not stop the platform
        // blocking an address during an incident. The loss is loud — it goes to the log at error level.
        await using var context = _database.NewContext();
        await context.Database.ExecuteSqlRawAsync("DROP TABLE audit_log");

        var trail = new EfAuditTrail(context, _clock, NullLogger<EfAuditTrail>.Instance);

        await trail.RecordAsync(Actor.Engine, AuditOperationNames.ActionExecuted, "alert", "1");
    }

    private EfAuditTrail NewTrail() =>
        new(_database.NewContext(), _clock, NullLogger<EfAuditTrail>.Instance);

    private async Task<List<Domain.Platform.AuditEntry>> AllEntries()
    {
        await using var context = _database.NewContext();
        return await context.AuditEntries.AsNoTracking().ToListAsync();
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>Local aliases so these tests read without a using for the domain constants class.</summary>
internal static class AuditOperationNames
{
    public const string RuleEnabled = Domain.Platform.AuditOperation.RuleEnabled;
    public const string ConnectionUpdated = Domain.Platform.AuditOperation.ConnectionUpdated;
    public const string ActionExecuted = Domain.Platform.AuditOperation.ActionExecuted;
}
