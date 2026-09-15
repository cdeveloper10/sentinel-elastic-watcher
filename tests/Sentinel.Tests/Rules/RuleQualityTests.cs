using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;

namespace Sentinel.Tests.Rules;

/// <summary>
/// Whether a rule is worth keeping, from what people said its alerts turned out to be.
///
/// This is the number a detection programme is steered by, so the ways it can lie matter more than the
/// arithmetic. Two of them are guarded here: judging one alert out of one does not make a rule 100% wrong,
/// and an alert nobody has closed says nothing about the rule and must not move the rate in either
/// direction.
/// </summary>
public class RuleQualityTests
{
    private static RuleQuality Rule(
        int alerts = 0, int tp = 0, int fp = 0, int benign = 0, int duplicate = 0, bool enabled = true) =>
        new(
            RuleId: 1,
            RuleName: "Brute force",
            Enabled: enabled,
            Alerts: alerts == 0 ? tp + fp + benign + duplicate : alerts,
            Judged: tp + fp + benign + duplicate,
            TruePositives: tp,
            FalsePositives: fp,
            Benign: benign,
            Duplicates: duplicate,
            LastAlertAt: null);

    [Fact]
    public void The_rate_is_over_judged_alerts_not_over_all_of_them()
    {
        // Ninety alerts nobody has looked at sit beside ten that were judged, two of them wrong. The rate
        // is 20% of the ten, not 2% of the hundred — otherwise a rule looks better the more of its alerts
        // are ignored, which is exactly backwards.
        var rule = Rule(alerts: 100, tp: 8, fp: 2);

        Assert.Equal(0.2, rule.FalsePositiveRate, 3);
    }

    [Fact]
    public void A_rule_nobody_has_judged_gets_no_verdict()
    {
        var rule = Rule(alerts: 40);

        Assert.Equal(0, rule.Judged);
        Assert.Equal(RuleVerdict.Unjudged, rule.Verdict);
    }

    [Fact]
    public void One_wrong_alert_out_of_one_is_not_a_failing_rule()
    {
        // The guard that stops a good rule being deleted in its first week. A 100% rate over a single
        // alert is not a rate, it is an anecdote.
        var rule = Rule(fp: 1);

        Assert.Equal(1.0, rule.FalsePositiveRate, 3);
        Assert.Equal(RuleVerdict.Unjudged, rule.Verdict);
        Assert.Contains("Close a few more", rule.Advice);
    }

    [Theory]
    [InlineData(10, 0, RuleVerdict.Healthy)]   // nothing wrong
    [InlineData(9, 1, RuleVerdict.Healthy)]    // 10%
    [InlineData(8, 2, RuleVerdict.Healthy)]    // 20% — at the threshold, not over it
    [InlineData(7, 3, RuleVerdict.Tune)]       // 30%
    [InlineData(5, 5, RuleVerdict.Tune)]       // 50% — at the threshold, not over it
    [InlineData(4, 6, RuleVerdict.Harmful)]    // 60%
    public void The_verdict_follows_the_rate(int tp, int fp, string expected)
    {
        Assert.Equal(expected, Rule(tp: tp, fp: fp).Verdict);
    }

    [Fact]
    public void A_benign_positive_is_not_held_against_the_rule()
    {
        // The distinction the four values exist for. A backup job that trips a rule every Sunday is the
        // detection working; what wants fixing is an exception. Counting these as false would condemn
        // rules that are doing their job.
        var rule = Rule(tp: 2, benign: 8);

        Assert.Equal(0, rule.FalsePositiveRate, 3);
        Assert.Equal(RuleVerdict.Healthy, rule.Verdict);
        Assert.Contains("exception", rule.Advice);
    }

    [Fact]
    public void A_duplicate_is_not_held_against_the_rule_either()
    {
        var rule = Rule(tp: 5, duplicate: 5);

        Assert.Equal(0, rule.FalsePositiveRate, 3);
        Assert.Equal(RuleVerdict.Healthy, rule.Verdict);
    }

    [Fact]
    public void An_armed_rule_that_has_never_fired_is_called_out()
    {
        // Silence reads as peace and is usually a broken log source. Nobody goes looking for a rule that
        // is not complaining, so it has to complain about itself.
        var rule = Rule(alerts: 0, enabled: true);

        Assert.Equal(RuleVerdict.Silent, rule.Verdict);
        Assert.Contains("never fired", rule.Advice);
    }

    [Fact]
    public void A_disarmed_rule_is_not_reported_as_silent()
    {
        // It is not running. Saying it has stopped detecting would be noise on every draft in the estate.
        Assert.NotEqual(RuleVerdict.Silent, Rule(alerts: 0, enabled: false).Verdict);
    }

    [Fact]
    public void The_advice_says_what_to_do_rather_than_only_what_is_wrong()
    {
        Assert.Contains("narrow the condition", Rule(tp: 1, fp: 9).Advice);
        Assert.Contains("Worth an hour", Rule(tp: 6, fp: 4).Advice);
    }

    // -- the dispositions themselves -----------------------------------------

    [Fact]
    public void Only_a_false_positive_counts_as_a_defect()
    {
        Assert.True(AlertDisposition.IsRuleDefect(AlertDisposition.FalsePositive));

        Assert.False(AlertDisposition.IsRuleDefect(AlertDisposition.TruePositive));
        Assert.False(AlertDisposition.IsRuleDefect(AlertDisposition.Benign));
        Assert.False(AlertDisposition.IsRuleDefect(AlertDisposition.Duplicate));
        Assert.False(AlertDisposition.IsRuleDefect(null));
    }

    [Fact]
    public void A_disposition_is_accepted_in_any_casing_and_stored_in_one()
    {
        // The lesson this project has already learned twice: validating case-insensitively while comparing
        // ordinally elsewhere produces a value that is accepted, stored, and then matches nothing.
        Assert.Equal(AlertDisposition.FalsePositive, AlertDisposition.Canonical("false_positive"));
        Assert.Equal(AlertDisposition.TruePositive, AlertDisposition.Canonical("True_Positive"));

        Assert.Null(AlertDisposition.Canonical("probably"));
        Assert.Null(AlertDisposition.Canonical(null));
    }
}
