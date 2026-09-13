using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Persistence;

/// <summary>
/// A rule and its first version arrive together or not at all.
///
/// Creating a rule needs two writes, because the version carries the rule's generated id. Committing the
/// first alone produces a rule pointing at a version that does not exist — and that rule cannot be
/// evaluated, cannot be rehearsed, and reports only "its version or connection is missing". There is no
/// way to repair it from the console, because every path that would edit it first has to load the version
/// that is not there.
///
/// Found by creating a rule through the console after a failed write left exactly that state behind.
/// </summary>
public class RuleCreationAtomicityTests : IDisposable
{
    private readonly TestDatabase _database = new();

    public void Dispose() => _database.Dispose();

    [Fact]
    public async Task Both_rows_are_visible_when_the_transaction_commits()
    {
        await using var context = _database.NewContext();
        var rule = NewRule();

        await using (var transaction = await context.Database.BeginTransactionAsync())
        {
            context.Rules.Add(rule);
            await context.SaveChangesAsync();

            context.RuleVersions.Add(NewVersion(rule.Id));
            await context.SaveChangesAsync();

            await transaction.CommitAsync();
        }

        await using var reader = _database.NewContext();
        Assert.Single(await reader.Rules.ToListAsync());
        Assert.Single(await reader.RuleVersions.ToListAsync());
    }

    [Fact]
    public async Task Neither_row_survives_when_the_version_cannot_be_written()
    {
        // The exact failure that produced the orphans: the rule commits, the version violates a
        // constraint. Inside a transaction the rule has to go with it.
        await using var context = _database.NewContext();
        var rule = NewRule();

        await using (var transaction = await context.Database.BeginTransactionAsync())
        {
            context.Rules.Add(rule);
            await context.SaveChangesAsync();

            var broken = NewVersion(rule.Id);
            broken.ChangeNote = null!; // Not nullable in the schema.
            context.RuleVersions.Add(broken);

            await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
            await transaction.RollbackAsync();
        }

        await using var reader = _database.NewContext();
        Assert.Empty(await reader.Rules.ToListAsync());
        Assert.Empty(await reader.RuleVersions.ToListAsync());
    }

    [Fact]
    public async Task A_rule_without_a_version_is_the_state_worth_preventing()
    {
        // Stated as a test so the consequence is written down: this row is not merely incomplete, it is
        // unusable, and nothing in the product can mend it.
        await using var context = _database.NewContext();

        context.Rules.Add(NewRule());
        await context.SaveChangesAsync();

        var rule = await context.Rules.SingleAsync();
        var version = await context.RuleVersions
            .FirstOrDefaultAsync(v => v.RuleId == rule.Id && v.Version == rule.CurrentVersion);

        Assert.NotNull(rule);
        Assert.Null(version);
    }

    private static DetectionRule NewRule() => new()
    {
        Name = "WSO2 API abuse by source IP",
        Description = "More than five gateway calls from one address in ten minutes.",
        Severity = Severity.High,
        ConnectionId = 1,
        CurrentVersion = 1,
        Enabled = false,
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow,
        CreatedBy = "admin",
        UpdatedBy = "admin"
    };

    private static RuleVersion NewVersion(int ruleId) => new()
    {
        RuleId = ruleId,
        Version = 1,
        Name = "WSO2 API abuse by source IP",
        Description = "",
        Severity = Severity.High,
        IndexPatternsJson = """["wso2_*"]""",
        QueryJson = """{"exists":{"field":"SourceIP"}}""",
        TimestampField = "@timestamp",
        StrategyType = DetectionStrategyType.Threshold,
        GroupByJson = """["SourceIP.keyword"]""",
        Threshold = 5,
        WindowSeconds = 600,
        QueryDelaySeconds = 30,
        IntervalSeconds = 60,
        CooldownSeconds = 1800,
        ActionsJson = "[]",
        CreatedAt = DateTime.UtcNow,
        CreatedBy = "admin",
        ChangeNote = ""
    };
}
