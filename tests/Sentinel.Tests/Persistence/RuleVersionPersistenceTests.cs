using Microsoft.EntityFrameworkCore;
using Sentinel.Domain.Rules;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Persistence;

/// <summary>
/// Storing a rule version.
///
/// These exist because of a defect that every unit test missed and the first real save found: the API
/// wrote <c>null</c> into <c>ChangeNote</c>, which is a non-nullable column, so creating a rule through
/// the console failed with a constraint violation. The mapping had been exercised only by tests that
/// built entities by hand and always filled every field.
/// </summary>
public class RuleVersionPersistenceTests : IAsyncLifetime, IDisposable
{
    private readonly TestDatabase _database = new();

    /// <summary>
    /// A version belongs to a rule, and the foreign key says so. Seeding the parent is not scaffolding —
    /// an orphaned version is a version no alert could ever cite.
    /// </summary>
    public async Task InitializeAsync()
    {
        await using var context = _database.NewContext();

        context.Rules.Add(new DetectionRule
        {
            Id = 1,
            Name = "WSO2 API abuse by source IP",
            Severity = Severity.High,
            ConnectionId = 1,
            CurrentVersion = 1,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = "admin",
            UpdatedBy = "admin"
        });

        await context.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose() => _database.Dispose();

    [Fact]
    public async Task A_first_version_stores_with_no_change_note()
    {
        // There was nothing before it, so there is nothing to say about what changed. That has to be a
        // storable state rather than a constraint violation.
        await using var context = _database.NewContext();

        context.RuleVersions.Add(Version(changeNote: ""));
        await context.SaveChangesAsync();

        Assert.Equal("", (await context.RuleVersions.SingleAsync()).ChangeNote);
    }

    [Fact]
    public async Task A_later_version_keeps_the_note_that_explains_it()
    {
        await using var context = _database.NewContext();

        context.RuleVersions.Add(Version(version: 2, changeNote: "Raised the threshold after the NAT incident."));
        await context.SaveChangesAsync();

        Assert.Contains("NAT", (await context.RuleVersions.SingleAsync()).ChangeNote, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Two_versions_of_one_rule_coexist()
    {
        // An alert names the version that produced it, so versions accumulate rather than replace.
        await using var context = _database.NewContext();

        context.RuleVersions.Add(Version(version: 1, changeNote: ""));
        context.RuleVersions.Add(Version(version: 2, changeNote: "Widened the window."));
        await context.SaveChangesAsync();

        Assert.Equal(2, await context.RuleVersions.CountAsync());
    }

    [Fact]
    public async Task One_rule_cannot_have_the_same_version_twice()
    {
        // Two rows claiming to be version 3 would make an alert citing version 3 ambiguous, which defeats
        // the reason versions exist.
        await using var context = _database.NewContext();

        context.RuleVersions.Add(Version(version: 3, changeNote: ""));
        await context.SaveChangesAsync();

        context.RuleVersions.Add(Version(version: 3, changeNote: "duplicate"));

        await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
    }

    private static RuleVersion Version(int version = 1, string changeNote = "") => new()
    {
        RuleId = 1,
        Version = version,
        Name = "WSO2 API abuse by source IP",
        Description = "More than five gateway calls from one address in ten minutes.",
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
        ChangeNote = changeNote
    };
}
