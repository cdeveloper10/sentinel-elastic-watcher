using System.Text.Json;
using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Alerts;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Detection;

/// <summary>
/// Turning what a strategy found into what the platform will act on.
///
/// Deduplication and cooldown both run here, and the order matters: cooldown answers more often and more
/// cheaply, but deduplication is what actually holds under concurrency — two nodes evaluating the same
/// window will both pass the cooldown check, and only one insert can win the unique index.
/// </summary>
public class DetectionPipelineTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);

    private static readonly TimeRange Window = new(Now.AddMinutes(-5), Now);

    private readonly InMemoryAlertStore _alerts = new();
    private readonly InMemoryCooldownStore _cooldowns = new();

    private DetectionPipeline Pipeline() =>
        new(_alerts, _cooldowns, new FixedClock(Now));

    [Fact]
    public async Task A_candidate_becomes_an_alert()
    {
        var result = await Pipeline().ProcessAsync(TestRules.BruteForce(), [Candidate("10.10.10.20", 31)]);

        var alert = Assert.Single(result.NewAlerts);

        Assert.Equal("Brute Force Detection", alert.RuleName);
        Assert.Equal(3, alert.RuleVersion);
        Assert.Equal("HIGH", alert.Severity);
        Assert.Equal(31, alert.EventCount);
        Assert.Equal(AlertStatus.Detected, alert.Status);
    }

    [Fact]
    public async Task The_alert_points_at_the_rule_version_that_produced_it()
    {
        // An analyst reads this weeks later, by which time the rule has been tuned twice. Without the
        // version the answer to "why did this fire" is whatever the rule says today.
        var result = await Pipeline().ProcessAsync(TestRules.BruteForce(), [Candidate("10.0.0.1", 25)]);

        Assert.Equal(3, Assert.Single(result.NewAlerts).RuleVersion);
    }

    [Fact]
    public async Task The_subject_is_kept_both_readably_and_as_fields()
    {
        // The label is for a human; the fields are what an action reads to know which address to block.
        var result = await Pipeline().ProcessAsync(TestRules.BruteForce(), [Candidate("10.10.10.20", 31)]);
        var alert = Assert.Single(result.NewAlerts);

        Assert.Equal("source.ip=10.10.10.20", alert.Subject);
        Assert.Equal("10.10.10.20",
            JsonSerializer.Deserialize<Dictionary<string, string>>(alert.SubjectJson)!["source.ip"]);
    }

    [Fact]
    public async Task An_address_and_an_account_are_lifted_out_for_filtering()
    {
        var candidate = new DetectionCandidate(
            new Dictionary<string, string> { ["source.ip"] = "10.0.0.5", ["user.id"] = "alice" },
            12, Window, new Dictionary<string, object?>());

        var alert = Assert.Single((await Pipeline().ProcessAsync(
            TestRules.BruteForce(groupBy: ["source.ip", "user.id"]), [candidate])).NewAlerts);

        Assert.Equal("10.0.0.5", alert.SourceIp);
        Assert.Equal("alice", alert.UserId);
    }

    [Fact]
    public async Task A_rule_grouped_by_something_else_leaves_those_columns_empty()
    {
        var candidate = new DetectionCandidate(
            new Dictionary<string, string> { ["url.path"] = "/api/login" }, 90, Window,
            new Dictionary<string, object?>());

        var alert = Assert.Single((await Pipeline().ProcessAsync(
            TestRules.BruteForce(groupBy: ["url.path"]), [candidate])).NewAlerts);

        Assert.Null(alert.SourceIp);
        Assert.Null(alert.UserId);
    }

    [Fact]
    public async Task The_evidence_travels_with_the_alert()
    {
        // The index the events lived in will have rolled over long before anyone reads this.
        var candidate = new DetectionCandidate(
            new Dictionary<string, string> { ["source.ip"] = "10.0.0.1" }, 31, Window,
            new Dictionary<string, object?> { ["eventCount"] = 31L, ["threshold"] = 20L, ["window"] = "5m" });

        var alert = Assert.Single((await Pipeline().ProcessAsync(TestRules.BruteForce(), [candidate])).NewAlerts);

        Assert.Contains("\"threshold\":20", alert.EvidenceJson, StringComparison.Ordinal);
    }

    // -- deduplication -----------------------------------------------------------------------

    [Fact]
    public async Task The_same_evaluation_processed_twice_produces_one_alert()
    {
        // A retry, a restart mid-run, or two nodes racing. The second insert loses the unique index.
        var rule = TestRules.BruteForce(cooldownSeconds: 0);

        await Pipeline().ProcessAsync(rule, [Candidate("10.10.10.20", 31)]);
        var second = await Pipeline().ProcessAsync(rule, [Candidate("10.10.10.20", 31)]);

        Assert.Single(_alerts.Alerts);
        Assert.Equal(1, second.Duplicates);
        Assert.Empty(second.NewAlerts);
    }

    [Fact]
    public async Task A_duplicate_does_not_extend_the_cooldown()
    {
        // Otherwise a retry loop would keep a subject suppressed indefinitely without ever alerting.
        var rule = TestRules.BruteForce(cooldownSeconds: 0);

        await Pipeline().ProcessAsync(rule, [Candidate("10.0.0.1", 31)]);
        var recordedAfterFirst = _cooldowns.Records.Count;

        await Pipeline().ProcessAsync(rule, [Candidate("10.0.0.1", 31)]);

        Assert.Equal(recordedAfterFirst, _cooldowns.Records.Count);
    }

    [Fact]
    public async Task Different_subjects_in_one_evaluation_each_get_an_alert()
    {
        var result = await Pipeline().ProcessAsync(
            TestRules.BruteForce(), [Candidate("10.0.0.1", 31), Candidate("10.0.0.2", 22)]);

        Assert.Equal(2, result.NewAlerts.Count());
        Assert.Equal(2, _alerts.Alerts.Count);
    }

    // -- cooldown ----------------------------------------------------------------------------

    [Fact]
    public async Task A_subject_in_cooldown_is_suppressed_and_the_reason_is_recorded()
    {
        var rule = TestRules.BruteForce(cooldownSeconds: 1800);
        await Pipeline().ProcessAsync(rule, [Candidate("10.10.10.20", 31)]);

        // A minute later, the same address still qualifies in the next overlapping window.
        var later = new DetectionPipeline(_alerts, _cooldowns, new FixedClock(Now.AddMinutes(1)));
        var result = await later.ProcessAsync(rule, [
            new DetectionCandidate(
                new Dictionary<string, string> { ["source.ip"] = "10.10.10.20" },
                33,
                new TimeRange(Now.AddMinutes(-4), Now.AddMinutes(1)),
                new Dictionary<string, object?>())
        ]);

        Assert.Empty(result.NewAlerts);
        Assert.Equal(1, result.Suppressed);
        Assert.Contains("cooldown", Assert.Single(result.Decisions).Detail!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Cooldown_on_one_subject_does_not_silence_another()
    {
        // Otherwise an attacker shields every other address by tripping the rule once from somewhere
        // expendable.
        var rule = TestRules.BruteForce(cooldownSeconds: 1800);
        await Pipeline().ProcessAsync(rule, [Candidate("10.0.0.1", 31)]);

        var result = await Pipeline().ProcessAsync(rule, [Candidate("10.0.0.2", 31)]);

        Assert.Single(result.NewAlerts);
    }

    [Fact]
    public async Task Cooldown_on_one_rule_does_not_silence_another()
    {
        var first = TestRules.BruteForce(cooldownSeconds: 1800);
        var second = first with { RuleId = 2, Name = "API Abuse" };

        await Pipeline().ProcessAsync(first, [Candidate("10.0.0.1", 31)]);
        var result = await Pipeline().ProcessAsync(second, [Candidate("10.0.0.1", 31)]);

        Assert.Single(result.NewAlerts);
    }

    [Fact]
    public async Task Once_the_cooldown_has_passed_the_subject_may_alert_again()
    {
        var rule = TestRules.BruteForce(cooldownSeconds: 1800);
        await Pipeline().ProcessAsync(rule, [Candidate("10.0.0.1", 31)]);

        var later = Now.AddMinutes(31);
        var afterwards = new DetectionPipeline(_alerts, _cooldowns, new FixedClock(later));

        var result = await afterwards.ProcessAsync(rule, [
            new DetectionCandidate(
                new Dictionary<string, string> { ["source.ip"] = "10.0.0.1" },
                31,
                new TimeRange(later.AddMinutes(-5), later),
                new Dictionary<string, object?>())
        ]);

        Assert.Single(result.NewAlerts);
    }

    [Fact]
    public async Task A_cooldown_record_outlives_the_cooldown_itself()
    {
        // A record that expired between the check and the use would let a suppressed subject through.
        await Pipeline().ProcessAsync(
            TestRules.BruteForce(cooldownSeconds: 1800), [Candidate("10.0.0.1", 31)]);

        Assert.True(Assert.Single(_cooldowns.Records).Retention > TimeSpan.FromSeconds(1800));
    }

    private static DetectionCandidate Candidate(string ip, long count) =>
        new(new Dictionary<string, string> { ["source.ip"] = ip },
            count,
            Window,
            new Dictionary<string, object?> { ["eventCount"] = count });

    // -- doubles -----------------------------------------------------------------------------

    private sealed class InMemoryAlertStore : IAlertStore
    {
        public List<Alert> Alerts { get; } = [];
        private readonly HashSet<string> _fingerprints = new(StringComparer.Ordinal);

        public Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default)
        {
            if (!_fingerprints.Add(alert.Fingerprint))
                return Task.FromResult(false);

            Alerts.Add(alert);
            return Task.FromResult(true);
        }
    }

    private sealed class InMemoryCooldownStore : ICooldownStore
    {
        private readonly Dictionary<string, DateTimeOffset> _lastFired = new(StringComparer.Ordinal);

        public List<(string Key, DateTimeOffset FiredAt, TimeSpan Retention)> Records { get; } = [];

        public Task<DateTimeOffset?> LastFiredAtAsync(string key, CancellationToken ct = default) =>
            Task.FromResult(_lastFired.TryGetValue(key, out var at) ? at : (DateTimeOffset?)null);

        public Task RecordAsync(string key, DateTimeOffset firedAt, TimeSpan retention, CancellationToken ct = default)
        {
            _lastFired[key] = firedAt;
            Records.Add((key, firedAt, retention));
            return Task.CompletedTask;
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
