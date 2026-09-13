using Sentinel.Application.EventSources;

namespace Sentinel.Tests.EventSources;

/// <summary>
/// A rule's index patterns are the blast radius of every query it will run on a schedule, forever.
/// Both of the mistakes below are one keystroke to make in a form and expensive to find in production.
/// </summary>
public class IndexPatternRulesTests
{
    [Theory]
    [InlineData("gateway-logs-*")]
    [InlineData("logs-2026.01.15")]
    [InlineData("filebeat-*")]
    [InlineData("app_logs-*")]
    public void A_normal_pattern_is_accepted(string pattern) =>
        Assert.True(IndexPatternRules.Validate([pattern]).IsValid);

    [Theory]
    [InlineData("*")]
    [InlineData("_all")]
    [InlineData("**")]
    [InlineData("*:*")]
    public void A_pattern_that_reads_everything_is_refused(string pattern)
    {
        var result = IndexPatternRules.Validate([pattern]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("every index", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_cross_cluster_pattern_is_refused()
    {
        // It would send the query to a cluster nobody configured a connection for, with no endpoint, no
        // credential and no connection test behind it.
        var result = IndexPatternRules.Validate(["remote-cluster:logs-*"]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("cross-cluster", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_system_index_is_refused()
    {
        var result = IndexPatternRules.Validate([".kibana*"]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("system index", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Exclusions_are_allowed_alongside_an_inclusion() =>
        Assert.True(IndexPatternRules.Validate(["gateway-logs-*", "-gateway-logs-archive-*"]).IsValid);

    [Fact]
    public void Exclusions_on_their_own_select_nothing()
    {
        var result = IndexPatternRules.Validate(["-gateway-logs-archive-*"]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("exclude", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void No_patterns_at_all_is_refused() =>
        Assert.False(IndexPatternRules.Validate([]).IsValid);

    [Fact]
    public void Too_many_patterns_are_refused()
    {
        var many = Enumerable.Range(0, IndexPatternRules.MaxPatterns + 1).Select(i => $"logs-{i}-*").ToList();

        Assert.False(IndexPatternRules.Validate(many).IsValid);
    }

    [Theory]
    [InlineData("logs with spaces")]
    [InlineData("logs/nested")]
    [InlineData("logs\\nested")]
    [InlineData("logs,other")]
    public void Characters_an_index_name_cannot_hold_are_refused(string pattern) =>
        Assert.False(IndexPatternRules.Validate([pattern]).IsValid);

    [Fact]
    public void Normalising_trims_deduplicates_and_keeps_order()
    {
        var normalized = IndexPatternRules.Normalize([" gateway-logs-* ", "gateway-logs-*", "", "  ", "app-*"]);

        Assert.Equal(["gateway-logs-*", "app-*"], normalized);
    }
}
