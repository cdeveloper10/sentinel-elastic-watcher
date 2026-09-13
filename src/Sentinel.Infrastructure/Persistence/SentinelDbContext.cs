using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Platform;
using Sentinel.Domain.Rules;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
/// Platform state: rules, versions, alerts, executions, connections, audit and the engine's own bookkeeping.
///
/// Elasticsearch holds the events. This holds everything about what the platform decided and did, because
/// those need guarantees an event store does not offer — chiefly two unique indexes that are not
/// optimisations but the mechanism itself:
///
/// <list type="bullet">
/// <item><c>alerts.fingerprint</c> is what makes deduplication real. Checking for an existing alert and
/// then inserting one races between nodes and across a restart; a unique index makes the second insert
/// fail, which is an answer rather than a race.</item>
/// <item><c>action_executions.idempotency_key</c> is the same argument for blocking. Two nodes processing
/// one alert must not both block an address, and the only place that can be settled is where the write
/// lands.</item>
/// </list>
/// </summary>
public class SentinelDbContext(DbContextOptions<SentinelDbContext> options)
    : DbContext(options), IDataProtectionKeyContext
{
    /// <summary>
    /// The keys that sign and encrypt session cookies.
    ///
    /// Held here rather than on each pod's disk because the API is meant to run as several replicas, and
    /// ASP.NET Core generates a key ring per process by default: two pods would sign cookies with
    /// different keys, and a session would survive exactly as long as the load balancer kept sending that
    /// person back to the same pod. The database is the one thing every replica already shares.
    ///
    /// Nothing else in the platform touches it. <see cref="IDataProtectionKeyContext"/> is the framework's
    /// own contract, implemented here so the table is created and migrated alongside everything else
    /// rather than by a second mechanism nobody remembers to run.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    public DbSet<Connection> Connections => Set<Connection>();
    public DbSet<DetectionRule> Rules => Set<DetectionRule>();
    public DbSet<RuleVersion> RuleVersions => Set<RuleVersion>();
    public DbSet<RuleCheckpoint> Checkpoints => Set<RuleCheckpoint>();
    public DbSet<EngineNode> EngineNodes => Set<EngineNode>();
    public DbSet<RuleLease> RuleLeases => Set<RuleLease>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<ActionExecution> ActionExecutions => Set<ActionExecution>();
    public DbSet<CooldownEntry> Cooldowns => Set<CooldownEntry>();
    public DbSet<ActionRateCounter> ActionRateCounters => Set<ActionRateCounter>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<PlatformUser> Users => Set<PlatformUser>();
    public DbSet<PlatformRole> Roles => Set<PlatformRole>();
    public DbSet<PlatformUserRole> UserRoles => Set<PlatformUserRole>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        ConfigureConnections(model);
        ConfigureRules(model);
        ConfigureAlerts(model);
        ConfigureEngineState(model);
        ConfigureAudit(model);
        ConfigureIdentity(model);
    }

    private static void ConfigureConnections(ModelBuilder model) =>
        model.Entity<Connection>(entity =>
        {
            entity.ToTable("connections");
            entity.HasKey(e => e.Id);

            // Rules refer to a connection by name, so two connections cannot share one.
            entity.HasIndex(e => e.Name).IsUnique();

            entity.Property(e => e.Name).HasMaxLength(64).IsRequired();
            entity.Property(e => e.DisplayName).HasMaxLength(128);
            entity.Property(e => e.Description).HasMaxLength(1024);
            entity.Property(e => e.Type).HasMaxLength(32).IsRequired();
            entity.Property(e => e.Endpoint).HasMaxLength(512).IsRequired();
            entity.Property(e => e.AuthenticationMode).HasMaxLength(32);
            entity.Property(e => e.ConfigurationJson).HasColumnType("text");
            entity.Property(e => e.SecretCiphertext).HasColumnType("text");
            entity.Property(e => e.SecretKeysJson).HasColumnType("text");
            entity.Property(e => e.CreatedBy).HasMaxLength(128);
            entity.Property(e => e.UpdatedBy).HasMaxLength(128);
            entity.Property(e => e.LastProbeMessage).HasMaxLength(1024);
        });

    private static void ConfigureRules(ModelBuilder model)
    {
        model.Entity<DetectionRule>(entity =>
        {
            entity.ToTable("detection_rules");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();

            // The scheduler asks for enabled rules and then reads their checkpoints; when a rule is next
            // due is checkpoint state, not rule state, so that a rule can be edited without disturbing
            // where evaluation had reached.
            entity.HasIndex(e => e.Enabled);

            entity.Property(e => e.Name).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(2048);
            entity.Property(e => e.Severity).HasMaxLength(16).IsRequired();
            entity.Property(e => e.CreatedBy).HasMaxLength(128);
            entity.Property(e => e.UpdatedBy).HasMaxLength(128);
        });

        model.Entity<RuleVersion>(entity =>
        {
            entity.ToTable("rule_versions");
            entity.HasKey(e => e.Id);

            // An alert names the version that produced it, so a version is written once and never edited.
            entity.HasIndex(e => new { e.RuleId, e.Version }).IsUnique();

            entity.Property(e => e.Name).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(2048);
            entity.Property(e => e.Severity).HasMaxLength(16).IsRequired();
            entity.Property(e => e.IndexPatternsJson).HasColumnType("text").IsRequired();
            entity.Property(e => e.QueryJson).HasColumnType("text");
            entity.Property(e => e.TimestampField).HasMaxLength(256).IsRequired();
            entity.Property(e => e.StrategyType).HasMaxLength(32).IsRequired();
            entity.Property(e => e.GroupByJson).HasColumnType("text");
            entity.Property(e => e.ActionsJson).HasColumnType("text");
            entity.Property(e => e.CreatedBy).HasMaxLength(128);
            entity.Property(e => e.ChangeNote).HasMaxLength(1024);

            // Both ends named. RuleVersion.Rule and DetectionRule.Versions are the two halves of one
            // relationship, and leaving either unnamed here makes EF configure an anonymous one over
            // RuleId and then discover the navigations as a *second* — inventing a shadow RuleId1 column
            // that the migration faithfully creates. The model validator warns; nothing fails.
            entity.HasOne(e => e.Rule)
                .WithMany(r => r.Versions)
                .HasForeignKey(e => e.RuleId)
                // A rule cannot be hard-deleted while alerts still point at its versions; the API
                // deactivates instead, so forensic questions stay answerable.
                .OnDelete(DeleteBehavior.Restrict);
        });
    }

    private static void ConfigureAlerts(ModelBuilder model)
    {
        model.Entity<Alert>(entity =>
        {
            entity.ToTable("alerts");
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.AlertId).IsUnique();

            // Deduplication itself. A read-then-write would race between nodes; this makes the second
            // insert fail, which the pipeline reads as "already recorded".
            entity.HasIndex(e => e.Fingerprint).IsUnique();

            entity.HasIndex(e => new { e.RuleId, e.DetectedAt });
            entity.HasIndex(e => new { e.Status, e.DetectedAt });

            entity.Property(e => e.AlertId).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Fingerprint).HasMaxLength(128).IsRequired();
            entity.Property(e => e.RuleName).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Severity).HasMaxLength(16).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(24).IsRequired();
            entity.Property(e => e.Subject).HasMaxLength(512);
            entity.Property(e => e.SubjectJson).HasColumnType("text");
            entity.Property(e => e.EvidenceJson).HasColumnType("text");
            entity.Property(e => e.SourceIp).HasMaxLength(64);
            entity.Property(e => e.UserId).HasMaxLength(256);
            entity.Property(e => e.AcknowledgedBy).HasMaxLength(128);
            entity.Property(e => e.ResolvedBy).HasMaxLength(128);
            entity.Property(e => e.ResolutionNote).HasMaxLength(2048);
            entity.Property(e => e.SuppressionReason).HasMaxLength(512);
        });

        model.Entity<ActionExecution>(entity =>
        {
            entity.ToTable("action_executions");
            entity.HasKey(e => e.Id);

            // The claim. Two nodes processing one alert cannot both block the same address, and a restart
            // mid-dispatch cannot cause a second block on resume.
            entity.HasIndex(e => e.IdempotencyKey).IsUnique();

            entity.HasIndex(e => new { e.AlertId, e.ActionType });
            entity.HasIndex(e => new { e.Status, e.CreatedAt });

            entity.Property(e => e.IdempotencyKey).HasMaxLength(64).IsRequired();
            entity.Property(e => e.ActionType).HasMaxLength(64).IsRequired();
            entity.Property(e => e.ConnectionName).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Status).HasMaxLength(24).IsRequired();
            entity.Property(e => e.Target).HasMaxLength(256);
            entity.Property(e => e.ErrorCode).HasMaxLength(64);
            entity.Property(e => e.ErrorMessage).HasMaxLength(2048);
            entity.Property(e => e.RequestSummary).HasColumnType("text");

            // Both ends named, for the same reason as rule versions: ActionExecution.Alert and
            // Alert.Executions are one relationship, and an unnamed HasOne makes EF find them again as a
            // second one over a shadow AlertId1 column.
            entity.HasOne(e => e.Alert)
                .WithMany(a => a.Executions)
                .HasForeignKey(e => e.AlertId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureEngineState(ModelBuilder model)
    {
        model.Entity<RuleCheckpoint>(entity =>
        {
            entity.ToTable("rule_checkpoints");
            entity.HasKey(e => e.RuleId);
            entity.Property(e => e.LastError).HasMaxLength(2048);
        });

        model.Entity<EngineNode>(entity =>
        {
            entity.ToTable("engine_nodes");

            // Keyed by node, so a pod that restarts under the same name updates its row rather than
            // accumulating one per lifetime. In Kubernetes a replacement pod gets a new name, so old rows
            // linger — deliberately: "this node stopped reporting" is information, and the maintenance
            // sweep removes rows that have been silent long enough to be certainly gone.
            entity.HasKey(e => e.NodeId);

            entity.Property(e => e.NodeId).HasMaxLength(128);
            entity.Property(e => e.Version).HasMaxLength(64);
            entity.HasIndex(e => e.LastSeenAt);
        });

        model.Entity<RuleLease>(entity =>
        {
            entity.ToTable("rule_leases");

            // The primary key is what settles the race between two nodes inserting the first lease for a
            // rule: one insert wins, the other fails, and the loser moves on.
            entity.HasKey(e => e.RuleId);

            entity.Property(e => e.Owner).HasMaxLength(128).IsRequired();
            entity.HasIndex(e => e.ExpiresAt);
        });

        model.Entity<CooldownEntry>(entity =>
        {
            entity.ToTable("cooldowns");
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).HasMaxLength(256);

            // Swept rather than left to grow: one row per subject per rule adds up on a busy estate.
            entity.HasIndex(e => e.ExpiresAt);
        });

        model.Entity<ActionRateCounter>(entity =>
        {
            entity.ToTable("action_rate_counters");
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).HasMaxLength(256);
            entity.HasIndex(e => e.ExpiresAt);
        });
    }

    private static void ConfigureAudit(ModelBuilder model) =>
        model.Entity<AuditEntry>(entity =>
        {
            entity.ToTable("audit_log");
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.OccurredAt);
            entity.HasIndex(e => new { e.ResourceType, e.ResourceId });
            entity.HasIndex(e => e.Actor);

            entity.Property(e => e.Actor).HasMaxLength(128).IsRequired();
            entity.Property(e => e.Operation).HasMaxLength(64).IsRequired();
            entity.Property(e => e.ResourceType).HasMaxLength(64).IsRequired();
            entity.Property(e => e.ResourceId).HasMaxLength(128);
            entity.Property(e => e.Result).HasMaxLength(16).IsRequired();
            entity.Property(e => e.SourceIp).HasMaxLength(64);
            entity.Property(e => e.Changes).HasColumnType("text");
            entity.Property(e => e.Detail).HasMaxLength(2048);
            entity.Property(e => e.CorrelationId).HasMaxLength(64);
        });

    private static void ConfigureIdentity(ModelBuilder model)
    {
        model.Entity<PlatformUser>(entity =>
        {
            entity.ToTable("users");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Username).IsUnique();

            entity.Property(e => e.Username).HasMaxLength(128).IsRequired();
            entity.Property(e => e.DisplayName).HasMaxLength(128);
            entity.Property(e => e.PasswordHash).HasMaxLength(512).IsRequired();
        });

        model.Entity<PlatformRole>(entity =>
        {
            entity.ToTable("roles");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Name).IsUnique();

            entity.Property(e => e.Name).HasMaxLength(64).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(512);
            entity.Property(e => e.PermissionsJson).HasColumnType("text");
        });

        model.Entity<PlatformUserRole>(entity =>
        {
            entity.ToTable("user_roles");
            entity.HasKey(e => new { e.UserId, e.RoleId });

            entity.HasOne(e => e.User).WithMany(u => u.Roles)
                .HasForeignKey(e => e.UserId).OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Role).WithMany()
                .HasForeignKey(e => e.RoleId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}
