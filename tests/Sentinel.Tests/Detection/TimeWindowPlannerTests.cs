using Sentinel.Application.Detection;

namespace Sentinel.Tests.Detection;

/// <summary>
/// The scheduling arithmetic, which is where a detection platform quietly stops detecting.
///
/// Two behaviours carry most of the weight here. Evaluation trails real time by a configured delay,
/// because a log line written at 10:00:00 may not be searchable until 10:00:20 and the window it belonged
/// to is never looked at twice. And windows slide rather than tile, because nineteen failures at 10:04
/// followed by nineteen at 10:06 is not a corner case — it is what a paced attack looks like.
/// </summary>
public class TimeWindowPlannerTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 15, 10, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan Delay = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    // -- the ingest horizon ------------------------------------------------------------------

    [Fact]
    public void Evaluation_stops_short_of_now_by_the_query_delay()
    {
        // Reading up to now would permanently miss anything still in flight, and leave nothing behind to
        // say so.
        var plan = TimeWindowPlanner.Plan(Now, checkpoint: null, Window, Delay, Interval);

        var window = Assert.Single(plan.Windows);

        Assert.Equal(Now - Delay, window.To);
        Assert.Equal(Now - Delay - Window, window.From);
    }

    [Fact]
    public void A_zero_delay_is_honoured_for_a_source_that_is_synchronous()
    {
        var plan = TimeWindowPlanner.Plan(Now, null, Window, TimeSpan.Zero, Interval);

        Assert.Equal(Now, Assert.Single(plan.Windows).To);
    }

    [Fact]
    public void A_negative_delay_is_treated_as_none_rather_than_reading_the_future()
    {
        var plan = TimeWindowPlanner.Plan(Now, null, Window, TimeSpan.FromSeconds(-60), Interval);

        Assert.Equal(Now, Assert.Single(plan.Windows).To);
    }

    // -- the first run -----------------------------------------------------------------------

    [Fact]
    public void A_rule_that_has_never_run_looks_back_one_window_and_no_further()
    {
        // Replaying history on first enable would fire on events an operator has already dealt with — and,
        // with actions attached, would act on them.
        var plan = TimeWindowPlanner.Plan(Now, null, Window, Delay, Interval);

        Assert.Single(plan.Windows);
        Assert.Equal(Window, plan.Windows[0].Duration);
        Assert.Equal(Now - Delay, plan.Checkpoint);
        Assert.False(plan.SkippedBacklog);
    }

    // -- the steady state --------------------------------------------------------------------

    [Fact]
    public void One_interval_since_the_checkpoint_is_one_window()
    {
        var plan = TimeWindowPlanner.Plan(Now, Now - Delay - Interval, Window, Delay, Interval);

        var window = Assert.Single(plan.Windows);
        Assert.Equal(Now - Delay, window.To);
        Assert.Equal(Window, window.Duration);
    }

    [Fact]
    public void Consecutive_windows_overlap_so_a_paced_attack_cannot_slip_between_them()
    {
        // Each evaluation looks back a full window from where it has reached. Tiled buckets would miss a
        // subject that stays just under the threshold inside each bucket while crossing it across the
        // boundary.
        var plan = TimeWindowPlanner.Plan(Now, Now - Delay - TimeSpan.FromMinutes(3), Window, Delay, Interval);

        Assert.Equal(3, plan.Windows.Count);
        Assert.All(plan.Windows, w => Assert.Equal(Window, w.Duration));

        for (var i = 1; i < plan.Windows.Count; i++)
            Assert.True(plan.Windows[i].From < plan.Windows[i - 1].To,
                "Consecutive windows must overlap, not tile.");
    }

    [Fact]
    public void Windows_are_produced_oldest_first()
    {
        // Detections have to be recorded in the order they happened, or a cooldown set by a later window
        // suppresses an earlier one that should have fired first.
        var plan = TimeWindowPlanner.Plan(Now, Now - Delay - TimeSpan.FromMinutes(3), Window, Delay, Interval);

        for (var i = 1; i < plan.Windows.Count; i++)
            Assert.True(plan.Windows[i].To > plan.Windows[i - 1].To);
    }

    [Fact]
    public void Running_again_too_soon_does_nothing()
    {
        var plan = TimeWindowPlanner.Plan(Now, checkpoint: Now - Delay, Window, Delay, Interval);

        Assert.False(plan.HasWork);
        Assert.Equal(Now - Delay, plan.Checkpoint);
        Assert.Contains("horizon", plan.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_checkpoint_ahead_of_the_horizon_does_not_move_backwards()
    {
        // Can happen after a clock correction. Rewinding would re-evaluate windows already acted on.
        var ahead = Now + TimeSpan.FromMinutes(10);

        var plan = TimeWindowPlanner.Plan(Now, ahead, Window, Delay, Interval);

        Assert.False(plan.HasWork);
        Assert.Equal(ahead, plan.Checkpoint);
    }

    // -- catching up -------------------------------------------------------------------------

    [Fact]
    public void An_outage_is_caught_up_on_rather_than_skipped_over()
    {
        var plan = TimeWindowPlanner.Plan(Now, Now - Delay - TimeSpan.FromMinutes(5), Window, Delay, Interval);

        Assert.Equal(5, plan.Windows.Count);
        Assert.False(plan.SkippedBacklog);
    }

    [Fact]
    public void A_long_outage_is_capped_and_says_so()
    {
        // A rule re-enabled after a week must not become ten thousand queries in one tick.
        var plan = TimeWindowPlanner.Plan(
            Now, Now - TimeSpan.FromDays(7), Window, Delay, Interval, maxCatchUpWindows: 12);

        Assert.Equal(12, plan.Windows.Count);
        Assert.True(plan.SkippedBacklog);
        Assert.Contains("Behind by", plan.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_capped_catch_up_evaluates_the_most_recent_time_not_the_oldest()
    {
        // After an outage the question worth answering is what is happening now.
        var plan = TimeWindowPlanner.Plan(
            Now, Now - TimeSpan.FromDays(7), Window, Delay, Interval, maxCatchUpWindows: 3);

        Assert.Equal(Now - Delay, plan.Windows[^1].To);
        Assert.True(plan.Windows[0].To > Now - TimeSpan.FromHours(1));
    }

    [Fact]
    public void The_checkpoint_always_lands_on_the_horizon_so_the_gap_is_not_re_walked()
    {
        var plan = TimeWindowPlanner.Plan(
            Now, Now - TimeSpan.FromDays(7), Window, Delay, Interval, maxCatchUpWindows: 3);

        Assert.Equal(Now - Delay, plan.Checkpoint);
    }

    // -- guards ------------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(-60)]
    public void A_window_that_is_not_positive_is_a_programming_error(int seconds) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TimeWindowPlanner.Plan(Now, null, TimeSpan.FromSeconds(seconds), Delay, Interval));

    [Fact]
    public void An_interval_that_is_not_positive_is_a_programming_error() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TimeWindowPlanner.Plan(Now, null, Window, Delay, TimeSpan.Zero));

    [Fact]
    public void A_max_catch_up_below_one_still_evaluates_something() =>
        Assert.Single(TimeWindowPlanner.Plan(
            Now, Now - TimeSpan.FromHours(1), Window, Delay, Interval, maxCatchUpWindows: 0).Windows);

    // -- operator rewind ----------------------------------------------------------------------

    [Fact]
    public void A_rescan_can_be_asked_for_from_an_earlier_time() =>
        Assert.Equal(
            Now - TimeSpan.FromHours(2),
            TimeWindowPlanner.ResetTo(Now - TimeSpan.FromHours(2), Now, Delay));

    [Fact]
    public void A_rescan_cannot_be_asked_for_from_the_future()
    {
        // Placing the checkpoint past the horizon would make the next window read half-written data.
        Assert.Equal(Now - Delay, TimeWindowPlanner.ResetTo(Now + TimeSpan.FromHours(1), Now, Delay));
    }
}
