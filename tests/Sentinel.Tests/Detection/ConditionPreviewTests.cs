using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Domain.Connections;
using Sentinel.Tests.Harness;

namespace Sentinel.Tests.Detection;

/// <summary>
/// Answering "would this condition find anything" before a rule exists.
///
/// The behaviour worth protecting here is the one that looks like a bug until you know why: the preview
/// asks the source for every subject with at least one event, where the engine asks only for subjects that
/// already cross the threshold. They want opposite things. The engine is keeping a query cheap on a busy
/// index; an author is trying to find out whether twenty was the right number, and the subject sitting at
/// fourteen is the entire answer.
/// </summary>
public class ConditionPreviewTests
{
    private static readonly Connection Source = new()
    {
        Id = 1,
        Name = "cluster",
        Type = ConnectionType.Elasticsearch,
        Endpoint = "http://es.internal:9200",
        TimeoutSeconds = 10,
        Enabled = true
    };

    private static TimeRange LastHour() =>
        TimeRange.EndingAt(DateTimeOffset.UtcNow, TimeSpan.FromHours(1));

    private static Task<ConditionPreviewResult> Run(
        FakeEventSource source,
        string[]? groupBy = null,
        long threshold = 20) =>
        new ConditionPreviewService().RunAsync(
            Source, source, ["gateway-logs-*"], "", "@timestamp", groupBy ?? [], threshold, LastHour());

    [Fact]
    public async Task Near_misses_are_returned_rather_than_filtered_out()
    {
        // The decision this class exists to make. Pushing the threshold down would leave an author staring
        // at "nothing matched" while a subject sat at fourteen — and the useful thing to tell them is that
        // their condition is fine and their number is too high.
        var source = new FakeEventSource().WithGroup("service.name", "billing", 14);
        source.TotalMatched = 14;

        var result = await Run(source, ["service.name"], threshold: 20);

        var group = Assert.Single(result.Groups);

        Assert.Equal(14, group.Count);
        Assert.False(group.ReachesThreshold);
        Assert.Equal(0, result.WouldTrigger);
        Assert.Equal(1, Assert.Single(source.CountCalls).MinCount);
    }

    [Fact]
    public async Task It_says_plainly_when_nothing_would_have_fired()
    {
        var source = new FakeEventSource().WithGroup("service.name", "billing", 14);
        source.TotalMatched = 14;

        var result = await Run(source, ["service.name"], threshold: 20);

        Assert.Contains("none reach 20", result.Message);
        Assert.Contains("busiest had 14", result.Message);
    }

    [Fact]
    public async Task Subjects_that_cross_the_threshold_are_counted()
    {
        var source = new FakeEventSource()
            .WithGroup("source.ip", "10.0.0.9", 44)
            .WithGroup("source.ip", "10.0.0.4", 21)
            .WithGroup("source.ip", "10.0.0.7", 3);

        source.TotalMatched = 68;

        var result = await Run(source, ["source.ip"], threshold: 20);

        Assert.Equal(2, result.WouldTrigger);
        Assert.Equal(3, result.Groups.Count);

        // Busiest first: an author reads the top of this list and stops.
        Assert.Equal(44, result.Groups[0].Count);
        Assert.Equal(3, result.Groups[^1].Count);
    }

    [Fact]
    public async Task Nothing_matching_is_distinguished_from_a_wrong_group_by()
    {
        // Two states that look identical in a bare count and need different fixes. Saying which is the
        // whole reason this returns a sentence and not only numbers.
        var quiet = await Run(new FakeEventSource(), ["service.name"]);

        Assert.Contains("Nothing in this window matched", quiet.Message);

        var matchedButUngrouped = new FakeEventSource();
        matchedButUngrouped.TotalMatched = 900;

        var wrongField = await Run(matchedButUngrouped, ["srvice.name"]);

        Assert.Contains("none of them carry srvice.name", wrongField.Message);
    }

    [Fact]
    public async Task Without_a_group_by_it_counts_and_says_what_is_missing()
    {
        var source = new FakeEventSource();
        source.TotalMatched = 62;

        var result = await Run(source);

        Assert.Equal(62, result.TotalMatched);
        Assert.Empty(result.Groups);
        Assert.Contains("Add a group-by", result.Message);

        // Not asked for at all, rather than asked for with an empty list.
        Assert.Empty(source.CountCalls);
    }

    [Fact]
    public async Task Sample_events_come_back_so_the_fields_can_be_seen()
    {
        // What turns the preview into the field picker: the author clicks a field in a real log line
        // instead of typing a path they are guessing at.
        var source = new FakeEventSource()
            .WithDocument(("ApiName", "AiServices"), ("backend_latency", 4120));

        var result = await Run(source);

        var sample = Assert.Single(result.Samples);

        Assert.Equal("AiServices", sample["ApiName"]);
        Assert.Equal(ConditionPreviewService.SampleSize, Assert.Single(source.PreviewCalls).SampleSize);
    }

    [Fact]
    public async Task A_source_that_refuses_reports_why_instead_of_throwing()
    {
        // The shard-failure message arrives through here, which is the moment it is most useful: the
        // author is looking at the screen, not reading a checkpoint hours later.
        var source = new FakeEventSource
        {
            Throws = new InvalidOperationException(
                "search_phase_execution_exception: Partial shards failure — query_shard_exception (index wso2_2026-05-23)")
        };

        var result = await Run(source);

        Assert.False(result.Succeeded);
        Assert.Contains("wso2_2026-05-23", result.Message);
    }

    [Fact]
    public async Task A_cluster_that_does_not_answer_reports_a_timeout_rather_than_failing_the_request()
    {
        // Found by pointing the console at an address with nothing on it, which is the first thing an
        // author does by accident. A timed-out HttpClient request surfaces as OperationCanceledException,
        // so the filter that excluded cancellation let it escape and the console showed "An error
        // occurred while processing your request." — a 500 for the most ordinary mistake there is.
        var source = new FakeEventSource { Throws = new TaskCanceledException("The request was canceled.") };

        var result = await Run(source);

        Assert.False(result.Succeeded);
        Assert.Contains("did not answer", result.Message);
        Assert.Contains("cluster", result.Message);
    }

    [Fact]
    public async Task A_cancellation_the_caller_asked_for_is_still_a_cancellation()
    {
        // The other side of that filter. When the request really was abandoned — the browser navigated
        // away — there is nobody to show a message to, and swallowing it would turn a dropped request
        // into a fabricated answer.
        using var stopping = new CancellationTokenSource();
        await stopping.CancelAsync();

        var source = new FakeEventSource { Throws = new TaskCanceledException("The request was canceled.") };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ConditionPreviewService().RunAsync(
                Source, source, ["logs-*"], "", "@timestamp", [], 10, LastHour(), stopping.Token));
    }

    [Fact]
    public async Task A_backwards_range_is_refused_before_the_source_is_touched()
    {
        var source = new FakeEventSource();
        var now = DateTimeOffset.UtcNow;

        var result = await new ConditionPreviewService().RunAsync(
            Source, source, ["logs-*"], "", "@timestamp", [], 10, new TimeRange(now, now.AddMinutes(-5)));

        Assert.False(result.Succeeded);
        Assert.Empty(source.PreviewCalls);
    }

    [Fact]
    public async Task Without_an_index_pattern_it_refuses_rather_than_reading_the_cluster()
    {
        // A bare preview against no pattern would be a search across every index on the node, started by
        // somebody who has not finished typing.
        var source = new FakeEventSource();

        var result = await new ConditionPreviewService().RunAsync(
            Source, source, [], "", "@timestamp", [], 10, LastHour());

        Assert.False(result.Succeeded);
        Assert.Empty(source.PreviewCalls);
    }

    [Fact]
    public async Task The_group_count_is_bounded()
    {
        var source = new FakeEventSource();
        source.TotalMatched = 5;

        await Run(source, ["source.ip"]);

        Assert.Equal(ConditionPreviewService.MaxGroups, Assert.Single(source.CountCalls).MaxGroups);
    }
}
