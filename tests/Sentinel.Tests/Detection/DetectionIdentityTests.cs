using Sentinel.Application.Detection;

namespace Sentinel.Tests.Detection;

/// <summary>
/// Deduplication and cooldown: two of the four mechanisms that keep one condition from becoming a thousand
/// actions, and the two most often mistaken for each other.
///
/// Deduplication answers "have I already recorded this evaluation?" — it guards restarts and retries.
/// Cooldown answers "has this subject fired recently enough that firing again would be noise?" — it guards
/// the overlap that sliding windows create by design.
/// </summary>
public class DetectionIdentityTests
{
    private static readonly DateTimeOffset WindowEnd = new(2026, 1, 15, 10, 5, 0, TimeSpan.Zero);
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private static Dictionary<string, string> Ip(string value = "10.10.10.20") => new() { ["source.ip"] = value };

    // -- fingerprint -------------------------------------------------------------------------

    [Fact]
    public void The_same_evaluation_produces_the_same_fingerprint() =>
        Assert.Equal(
            DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd, Interval),
            DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd, Interval));

    [Fact]
    public void A_restart_mid_run_recognises_the_evaluation_it_already_did()
    {
        // The window end is floored to the interval grid. Without that, a process that came back up a few
        // seconds later would compute a different identity and record a duplicate detection for an event
        // it had already acted on.
        var first = DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd, Interval);
        var afterRestart = DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd.AddSeconds(17), Interval);

        Assert.Equal(first, afterRestart);
    }

    [Fact]
    public void A_later_evaluation_is_a_different_finding() =>
        Assert.NotEqual(
            DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd, Interval),
            DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd.AddMinutes(1), Interval));

    [Fact]
    public void Different_subjects_are_different_findings() =>
        Assert.NotEqual(
            DetectionFingerprint.Compute(1, 3, Ip("10.0.0.1"), WindowEnd, Interval),
            DetectionFingerprint.Compute(1, 3, Ip("10.0.0.2"), WindowEnd, Interval));

    [Fact]
    public void Editing_a_rule_makes_its_findings_distinct()
    {
        // A new version may use a different threshold or query, so its detections are not the old rule's
        // detections even for the same subject in the same window.
        Assert.NotEqual(
            DetectionFingerprint.Compute(1, 3, Ip(), WindowEnd, Interval),
            DetectionFingerprint.Compute(1, 4, Ip(), WindowEnd, Interval));
    }

    [Fact]
    public void Two_rules_watching_the_same_subject_do_not_collide() =>
        Assert.NotEqual(
            DetectionFingerprint.Compute(1, 1, Ip(), WindowEnd, Interval),
            DetectionFingerprint.Compute(2, 1, Ip(), WindowEnd, Interval));

    [Fact]
    public void The_order_group_by_fields_were_written_in_does_not_change_the_identity()
    {
        // Otherwise editing a rule to reorder its group-by would make every existing subject look new.
        var one = new Dictionary<string, string> { ["source.ip"] = "10.0.0.1", ["user.id"] = "alice" };
        var other = new Dictionary<string, string> { ["user.id"] = "alice", ["source.ip"] = "10.0.0.1" };

        Assert.Equal(
            DetectionFingerprint.Compute(1, 1, one, WindowEnd, Interval),
            DetectionFingerprint.Compute(1, 1, other, WindowEnd, Interval));
    }

    [Fact]
    public void A_fingerprint_reveals_nothing_about_the_subject()
    {
        // It travels into logs and API responses, where an address or an account name would be data the
        // reader may not be entitled to.
        var fingerprint = DetectionFingerprint.Compute(1, 3, Ip("203.0.113.55"), WindowEnd, Interval);

        Assert.DoesNotContain("203.0.113.55", fingerprint, StringComparison.Ordinal);
        Assert.Equal(64, fingerprint.Length);
    }

    [Fact]
    public void Bucketing_floors_rather_than_rounds()
    {
        var instant = new DateTimeOffset(2026, 1, 15, 10, 4, 59, TimeSpan.Zero);

        Assert.Equal(
            new DateTimeOffset(2026, 1, 15, 10, 4, 0, TimeSpan.Zero),
            DetectionFingerprint.Bucket(instant, Interval));
    }

    // -- subject key -------------------------------------------------------------------------

    [Fact]
    public void A_subject_reads_as_something_an_operator_can_recognise() =>
        Assert.Equal(
            "source.ip=10.0.0.1,user.id=alice",
            DetectionFingerprint.SubjectKey(new Dictionary<string, string>
            {
                ["user.id"] = "alice",
                ["source.ip"] = "10.0.0.1"
            }));

    [Fact]
    public void An_ungrouped_rule_still_has_a_subject() =>
        Assert.Equal("*", DetectionFingerprint.SubjectKey(new Dictionary<string, string>()));

    // -- cooldown ----------------------------------------------------------------------------

    [Fact]
    public void A_subject_that_just_fired_is_suppressed() =>
        Assert.True(CooldownPolicy.IsSuppressed(WindowEnd, WindowEnd.AddMinutes(5), TimeSpan.FromMinutes(30)));

    [Fact]
    public void Once_the_cooldown_has_passed_it_may_fire_again() =>
        Assert.False(CooldownPolicy.IsSuppressed(WindowEnd, WindowEnd.AddMinutes(31), TimeSpan.FromMinutes(30)));

    [Fact]
    public void The_boundary_instant_is_not_suppressed() =>
        Assert.False(CooldownPolicy.IsSuppressed(WindowEnd, WindowEnd.AddMinutes(30), TimeSpan.FromMinutes(30)));

    [Fact]
    public void A_subject_that_has_never_fired_is_not_suppressed() =>
        Assert.False(CooldownPolicy.IsSuppressed(null, WindowEnd, TimeSpan.FromMinutes(30)));

    [Fact]
    public void A_zero_cooldown_suppresses_nothing() =>
        Assert.False(CooldownPolicy.IsSuppressed(WindowEnd, WindowEnd, TimeSpan.Zero));

    [Fact]
    public void Cooldown_is_keyed_per_subject_so_one_address_cannot_silence_the_rest()
    {
        // Otherwise an attacker shields every other address by tripping the rule once, deliberately, from
        // somewhere expendable.
        Assert.NotEqual(
            CooldownPolicy.Key(1, Ip("10.0.0.1")),
            CooldownPolicy.Key(1, Ip("10.0.0.2")));
    }

    [Fact]
    public void Cooldown_is_keyed_per_rule_so_one_rule_cannot_silence_another() =>
        Assert.NotEqual(CooldownPolicy.Key(1, Ip()), CooldownPolicy.Key(2, Ip()));

    [Fact]
    public void The_time_a_subject_becomes_eligible_again_can_be_shown()
    {
        Assert.Equal(
            WindowEnd.AddMinutes(30),
            CooldownPolicy.SuppressedUntil(WindowEnd, TimeSpan.FromMinutes(30)));

        Assert.Null(CooldownPolicy.SuppressedUntil(null, TimeSpan.FromMinutes(30)));
    }
}
