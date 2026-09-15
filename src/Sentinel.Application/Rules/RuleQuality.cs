namespace Sentinel.Application.Rules;

/// <summary>What the numbers say should happen to a rule.</summary>
public static class RuleVerdict
{
    /// <summary>Nobody has judged enough of its alerts to say anything.</summary>
    public const string Unjudged = "UNJUDGED";

    /// <summary>Firing, and mostly right.</summary>
    public const string Healthy = "HEALTHY";

    /// <summary>Wrong often enough to be worth an hour of somebody's time.</summary>
    public const string Tune = "TUNE";

    /// <summary>Costing more attention than it saves. Until it is fixed, it is doing harm.</summary>
    public const string Harmful = "HARMFUL";

    /// <summary>Armed, and has produced nothing. Usually a broken log source rather than peace.</summary>
    public const string Silent = "SILENT";
}

/// <summary>
/// How a rule has been doing, from the dispositions its alerts were closed with.
///
/// This is the feedback loop the platform did not have. Every other measure of a detection rule — how
/// many alerts, how fast they were acknowledged — describes the volume of work it created, not whether
/// the work was worth doing. Only the people closing the alerts know that, and once they are asked, the
/// answer is a number that can be acted on.
/// </summary>
public sealed record RuleQuality(
    int RuleId,
    string RuleName,
    bool Enabled,
    int Alerts,
    int Judged,
    int TruePositives,
    int FalsePositives,
    int Benign,
    int Duplicates,
    DateTime? LastAlertAt)
{
    /// <summary>
    /// Alerts judged wrong, over alerts judged at all.
    ///
    /// The denominator is deliberately not every alert: an alert nobody has closed says nothing about the
    /// rule, and counting it either way would move this number for a reason that has nothing to do with
    /// the detection.
    /// </summary>
    public double FalsePositiveRate => Judged == 0 ? 0 : (double)FalsePositives / Judged;

    /// <summary>Below this a rule is doing its job.</summary>
    public const double TuneAbove = 0.20;

    /// <summary>Above this it is taking more analyst time than it saves.</summary>
    public const double HarmfulAbove = 0.50;

    /// <summary>
    /// Enough judged alerts for the rate to mean anything.
    ///
    /// One false positive out of one alert is not a 100% failure rate, it is one alert. Reporting it as
    /// the former is how a good rule gets deleted in its first week.
    /// </summary>
    public const int MinimumJudged = 5;

    public string Verdict
    {
        get
        {
            if (Enabled && Alerts == 0)
                return RuleVerdict.Silent;

            if (Judged < MinimumJudged)
                return RuleVerdict.Unjudged;

            return FalsePositiveRate switch
            {
                > HarmfulAbove => RuleVerdict.Harmful,
                > TuneAbove => RuleVerdict.Tune,
                _ => RuleVerdict.Healthy
            };
        }
    }

    /// <summary>A sentence for whoever reads the row, since the verdict alone does not say what to do.</summary>
    public string Advice => Verdict switch
    {
        RuleVerdict.Silent =>
            "Armed and has never fired. That is either a quiet estate or a rule watching an index nothing " +
            "writes to any more — check the condition against live data before assuming the first.",

        RuleVerdict.Unjudged =>
            $"{Judged} of {Alerts} alert(s) judged. Close a few more with a disposition and this becomes " +
            "a number worth acting on.",

        RuleVerdict.Harmful =>
            $"{Percent} of judged alerts were false. At this rate it costs more attention than it saves — " +
            "narrow the condition, raise the threshold, or take it out of service until it is fixed.",

        RuleVerdict.Tune =>
            $"{Percent} of judged alerts were false. Worth an hour: usually one field in the condition, or " +
            "an exception for whatever keeps tripping it.",

        _ => Benign > 0
            ? $"{Percent} false. The {Benign} benign one(s) are authorised activity the rule is right to " +
              "see — an exception suits those better than a change to the condition."
            : $"{Percent} of judged alerts were false."
    };

    private string Percent => $"{FalsePositiveRate:P0}";
}
