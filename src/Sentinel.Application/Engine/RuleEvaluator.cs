using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Actions;
using Sentinel.Application.Detection;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Engine;

public sealed record EvaluationOutcome(
    int RuleId,
    int WindowsEvaluated,
    int CandidatesFound,
    int AlertsRaised,
    int Suppressed,
    int ActionsSucceeded,
    int ActionsFailed,
    int ActionsSkipped,
    DateTimeOffset Checkpoint,
    bool SkippedBacklog,
    long DurationMs,
    string? Error = null)
{
    public bool Failed => Error is not null;
}

/// <summary>Where a rule's evaluation left off, and what happened on the last run.</summary>
public interface ICheckpointStore
{
    Task<DateTimeOffset?> ReadAsync(int ruleId, CancellationToken ct = default);

    Task WriteAsync(int ruleId, EvaluationOutcome outcome, CancellationToken ct = default);

    Task ResetAsync(int ruleId, DateTimeOffset? to, CancellationToken ct = default);

    Task<int> ConsecutiveFailuresAsync(int ruleId, CancellationToken ct = default);
}

/// <summary>Loads what the engine needs to evaluate one rule, without the engine knowing about EF.</summary>
public interface IRuleRuntimeSource
{
    /// <summary>Rules that are enabled, each at its current version, with the connection it reads from.</summary>
    Task<IReadOnlyList<(RuleDefinition Rule, Connection Source)>> ActiveRulesAsync(CancellationToken ct = default);

    Task<(RuleDefinition Rule, Connection Source)?> ActiveRuleAsync(int ruleId, CancellationToken ct = default);
}

/// <summary>
/// One rule, evaluated once.
///
/// Deliberately not a loop and not a timer: this evaluates and returns, so the same code path serves the
/// scheduler, a "run now" from the UI, and a test. Everything about <em>when</em> to call it belongs to
/// the scheduler, and everything about <em>whether the condition holds</em> belongs to the strategy — this
/// only joins them up and reports what happened.
///
/// The order matters and is the platform's whole shape: plan the windows, ask the strategy, let the
/// pipeline decide what is worth recording, and only then dispatch. Nothing here knows what an action is.
/// </summary>
public sealed class RuleEvaluator(
    IDetectionStrategyRegistry strategies,
    IEventSource eventSource,
    DetectionPipeline pipeline,
    ActionDispatcher dispatcher,
    ICheckpointStore checkpoints,
    ILogger<RuleEvaluator> logger,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<EvaluationOutcome> EvaluateAsync(
        RuleDefinition rule,
        Connection source,
        bool dispatchActions = true,
        CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var now = _clock.GetUtcNow();
        var checkpoint = await checkpoints.ReadAsync(rule.RuleId, ct);

        var plan = TimeWindowPlanner.Plan(now, checkpoint, rule.Window, rule.QueryDelay, rule.Interval);

        if (!plan.HasWork)
        {
            return new EvaluationOutcome(
                rule.RuleId, 0, 0, 0, 0, 0, 0, 0, plan.Checkpoint, plan.SkippedBacklog,
                stopwatch.ElapsedMilliseconds);
        }

        if (plan.SkippedBacklog)
        {
            // Said out loud rather than buried: a capped catch-up means a stretch of time was never
            // examined, and an operator deciding whether an incident was missed needs to know that.
            logger.LogWarning(
                "Rule {RuleId} skipped backlog catching up to {Checkpoint}: {Reason}",
                rule.RuleId, plan.Checkpoint, plan.Reason);
        }

        var candidates = 0;
        var raised = 0;
        var suppressed = 0;
        var succeeded = 0;
        var failed = 0;
        var skipped = 0;

        try
        {
            var strategy = strategies.Resolve(rule.StrategyType);

            foreach (var window in plan.Windows)
            {
                ct.ThrowIfCancellationRequested();

                var found = await strategy.EvaluateAsync(new StrategyRequest(rule, source, window), eventSource, ct);
                candidates += found.Candidates.Count;

                if (found.Truncated)
                {
                    // "At least this many" rather than "this many". Acting on a partial view without
                    // saying so is how a platform reports four blocked addresses out of forty.
                    logger.LogWarning(
                        "Rule {RuleId} hit the bucket ceiling for window {From:o}–{To:o}; more subjects may qualify",
                        rule.RuleId, window.From, window.To);
                }

                var processed = await pipeline.ProcessAsync(rule, found.Candidates, ct);
                suppressed += processed.Suppressed;

                // Walked as decisions rather than as alerts, because the candidate that produced an alert
                // is what carries the subject and the evidence an action needs — and pairing them back up
                // from the alert afterwards would be reconstructing something never lost.
                foreach (var decision in processed.Decisions)
                {
                    if (decision.Outcome != CandidateOutcome.Alerted || decision.Alert is null)
                        continue;

                    raised++;

                    if (!dispatchActions || rule.Actions.Count == 0)
                        continue;

                    var evidence = decision.Candidate.Evidence.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value?.ToString() ?? "",
                        StringComparer.Ordinal);

                    var result = await dispatcher.DispatchAsync(
                        decision.Alert, rule, decision.Candidate.Subject, evidence,
                        decision.Candidate.Sample, ct);

                    succeeded += result.Succeeded;
                    failed += result.Failed;
                    skipped += result.Skipped;
                }
            }

            var outcome = new EvaluationOutcome(
                rule.RuleId, plan.Windows.Count, candidates, raised, suppressed,
                succeeded, failed, skipped, plan.Checkpoint, plan.SkippedBacklog,
                stopwatch.ElapsedMilliseconds);

            await checkpoints.WriteAsync(rule.RuleId, outcome, ct);
            return outcome;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The checkpoint is not advanced. The windows that were not evaluated will be evaluated on the
            // next run, which is the entire reason the checkpoint is written at the end rather than the
            // start: a shutdown must cost a delay, not a gap.
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Rule {RuleId} failed to evaluate", rule.RuleId);

            var outcome = new EvaluationOutcome(
                rule.RuleId, 0, candidates, raised, suppressed, succeeded, failed, skipped,
                // Deliberately the *old* checkpoint: a failed evaluation has examined nothing it can
                // vouch for, and moving past those windows would lose them permanently.
                checkpoint ?? plan.Checkpoint,
                plan.SkippedBacklog,
                stopwatch.ElapsedMilliseconds,
                Describe(ex));

            await checkpoints.WriteAsync(rule.RuleId, outcome, ct);
            return outcome;
        }
    }

    private static string Describe(Exception ex) => ex switch
    {
        UnknownStrategyException => ex.Message,
        HttpRequestException => $"The event source could not be reached: {ex.Message}",
        TaskCanceledException => "The event source did not answer before the connection's timeout.",
        _ => ex.Message
    };
}
