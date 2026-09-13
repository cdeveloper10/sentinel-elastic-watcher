using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Actions;
using Sentinel.Application.Engine;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Infrastructure.Engine;

/// <summary>
/// The loop that drives evaluation.
///
/// Thin on purpose. Everything about which rules are due, who owns them and what happens when one fails
/// belongs to <see cref="RuleScheduler"/>, which returns rather than looping and so can be tested without
/// waiting on a timer. This adds only the three things a hosted service is actually for: a tick, a scope
/// per tick, and an orderly stop.
/// </summary>
public sealed class DetectionEngineService(
    IServiceScopeFactory scopes,
    EngineSettings settings,
    ILogger<DetectionEngineService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var tick = TimeSpan.FromSeconds(Math.Max(1, settings.TickSeconds));

        logger.LogInformation(
            "Detection engine started on node {Node}, ticking every {Tick}s", settings.NodeId, tick.TotalSeconds);

        using var timer = new PeriodicTimer(tick);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunTickAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Never allowed to end the loop. A tick that throws is a tick that failed; a loop that
                // ends is a platform that has silently stopped detecting, which is the failure mode this
                // whole system exists to avoid.
                logger.LogError(ex, "Detection engine tick failed");
            }

            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        logger.LogInformation("Detection engine stopped on node {Node}", settings.NodeId);
    }

    private async Task RunTickAsync(CancellationToken ct)
    {
        // A scope per tick, because the stores hold a DbContext and one long-lived context across a
        // process lifetime would accumulate every entity the engine has ever touched.
        await using var scope = scopes.CreateAsyncScope();

        var scheduler = scope.ServiceProvider.GetRequiredService<RuleScheduler>();
        var outcomes = await scheduler.TickAsync(ct);

        foreach (var outcome in outcomes)
        {
            if (outcome.Failed)
            {
                logger.LogWarning(
                    "Rule {RuleId} failed: {Error}", outcome.RuleId, outcome.Error);
                continue;
            }

            if (outcome.AlertsRaised > 0 || outcome.ActionsFailed > 0 || outcome.ActionsSkipped > 0)
            {
                logger.LogInformation(
                    "Rule {RuleId}: {Windows} window(s), {Alerts} alert(s), " +
                    "actions {Succeeded} ok / {Failed} failed / {Skipped} skipped in {Duration}ms",
                    outcome.RuleId, outcome.WindowsEvaluated, outcome.AlertsRaised,
                    outcome.ActionsSucceeded, outcome.ActionsFailed, outcome.ActionsSkipped,
                    outcome.DurationMs);
            }
        }

        await ReportAsync(scope.ServiceProvider, outcomes, ct);
    }

    /// <summary>
    /// Says, in the one place every console replica can read, that this engine is alive and what it is
    /// enforcing.
    ///
    /// After the tick rather than before, so "last seen" means "last completed a full pass" — an engine
    /// wedged mid-tick stops reporting, which is exactly what somebody needs to be told.
    ///
    /// A failure is logged and swallowed. Losing a heartbeat costs the console a status; treating it as
    /// fatal would let a bookkeeping row stop the platform detecting anything, which is the wrong way
    /// round.
    /// </summary>
    private async Task ReportAsync(
        IServiceProvider services, IReadOnlyList<EvaluationOutcome> outcomes, CancellationToken ct)
    {
        try
        {
            var nodes = services.GetRequiredService<IEngineNodeStore>();
            var safety = services.GetRequiredService<ActionSafetySettings>();

            await nodes.ReportAsync(new EngineHeartbeat(
                settings.NodeId,
                _startedAt,
                typeof(DetectionEngineService).Assembly.GetName().Version?.ToString() ?? "unknown",
                settings.Enabled,
                settings.TickSeconds,
                settings.MaxConcurrentRules,
                safety.ActionsEnabled,
                safety.NeverBlockAddresses.Count + safety.NeverBlockUsers.Count,
                outcomes.Count,
                outcomes.Sum(o => o.AlertsRaised),
                outcomes.Sum(o => o.DurationMs)), ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not record this node's heartbeat");
        }
    }

    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
}

/// <summary>
/// Removes expired cooldown and rate-counter rows, and engine nodes that have stopped reporting.
///
/// Separate from the engine because it must keep running when the engine is paused: cooldown rows that
/// nobody sweeps would otherwise accumulate for as long as the pause lasts, and the tidying is not what
/// an operator switched off.
/// </summary>
public sealed class MaintenanceService(
    IServiceScopeFactory scopes,
    ILogger<MaintenanceService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();

                var cooldowns = scope.ServiceProvider.GetRequiredService<EfCooldownStore>();
                var rates = scope.ServiceProvider.GetRequiredService<EfActionRateStore>();
                var nodes = scope.ServiceProvider.GetRequiredService<IEngineNodeStore>();

                // Nodes that have been silent for a day are gone: a Kubernetes pod is replaced under a new
                // name, so its row would otherwise stay for ever, and a list of long-dead engines makes
                // the live ones harder to see.
                var removed = await cooldowns.SweepAsync(stoppingToken)
                              + await rates.SweepAsync(stoppingToken)
                              + await nodes.SweepAsync(TimeSpan.FromDays(1), stoppingToken);

                if (removed > 0)
                    logger.LogDebug("Swept {Count} expired rows", removed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Maintenance sweep failed");
            }

            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
