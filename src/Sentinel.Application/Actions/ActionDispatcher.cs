using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Actions;

public sealed class RetrySettings
{
    /// <summary>Total attempts, first included. Three means one try and two retries.</summary>
    public int MaxAttempts { get; set; } = 3;

    public int BaseDelayMs { get; set; } = 2_000;
    public int MaxDelayMs { get; set; } = 30_000;
}

/// <summary>Where execution records live. The unique key is what makes idempotency survive a restart.</summary>
public interface IActionExecutionStore
{
    /// <summary>
    /// Claims the right to perform this action, returning false if the key already exists.
    ///
    /// Read-then-write would race: two nodes both find nothing, both insert, and the address is blocked
    /// twice. The uniqueness of the idempotency key has to be enforced where the write happens.
    /// </summary>
    Task<bool> TryClaimAsync(ActionExecution execution, CancellationToken ct = default);

    Task UpdateAsync(ActionExecution execution, CancellationToken ct = default);
}

/// <summary>
/// Closes out held actions whose approval window has passed.
///
/// Kept off <see cref="IActionExecutionStore"/> deliberately. That interface is what the dispatcher needs
/// in order to run an action, and it is small so that a test can stand in for it in four lines; this is
/// housekeeping the engine performs and nothing in a dispatch path ever calls. Putting it there would have
/// obliged seven test doubles to implement a method none of them has an opinion about.
///
/// Swept rather than evaluated when somebody opens the page, because an action nobody looked at is
/// precisely the one this exists for: it has to reach a terminal state on its own, or "waiting for
/// approval" becomes a list that grows for ever and means nothing.
/// </summary>
public interface IApprovalSweep
{
    /// <summary>Expires everything past its window as of this moment, and answers how many.</summary>
    Task<int> ExpireApprovalsAsync(DateTime asOf, CancellationToken ct = default);
}

/// <summary>Looks up the connection an action binding names.</summary>
public interface IConnectionLookup
{
    Task<Connection?> ByNameAsync(string name, CancellationToken ct = default);
}

public sealed record DispatchResult(IReadOnlyList<ActionExecution> Executions)
{
    public int Succeeded => Executions.Count(e => e.Status == ActionExecutionStatus.Success);
    public int Failed => Executions.Count(e => e.Status is ActionExecutionStatus.Failed or ActionExecutionStatus.DeadLetter);
    public int Skipped => Executions.Count(e => e.Status == ActionExecutionStatus.Skipped);

    /// <summary>Held for a person to decide. Counted apart from skipped: nobody has refused these yet.</summary>
    public int AwaitingApproval =>
        Executions.Count(e => e.Status == ActionExecutionStatus.PendingApproval);
}

/// <summary>
/// Runs an alert's actions, and owns everything that is the same for all of them.
///
/// Providers perform one attempt and report. Retry, backoff, idempotency, the safety rails and the
/// execution record live here, so that a new provider inherits all of it rather than reimplementing some
/// of it — which is how one action ends up retrying forever while another does not retry at all.
///
/// There is no conditional on action type anywhere in this class. That is the point of the registry, and
/// it is what the brief was asking for when it said not to write <c>if action == "sms"</c>.
/// </summary>
public sealed class ActionDispatcher(
    IActionRegistry registry,
    IConnectionLookup connections,
    IActionExecutionStore executions,
    ActionSafetyPolicy safety,
    RetrySettings retry,
    ILogger<ActionDispatcher> logger,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    public async Task<DispatchResult> DispatchAsync(
        Alert alert,
        RuleDefinition rule,
        IReadOnlyDictionary<string, string> subject,
        IReadOnlyDictionary<string, string> evidence,

        // One of the events behind the alert, for templates naming sample.*. Optional because a source
        // may not be able to provide one, and an action that does not ask for it works either way.
        IReadOnlyDictionary<string, string>? sample = null,
        CancellationToken ct = default)
    {
        var results = new List<ActionExecution>();

        // What has happened so far, for the actions still to come. This is what makes the ordering below
        // worth anything to a message: "block, then say it was blocked" needs the second half to be able
        // to find out whether the first half happened.
        var outcomes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Sequential. The actions on one alert are usually related — block, then tell somebody it was
        // blocked — and running them in parallel would report success before the block landed.
        foreach (var binding in rule.Actions)
        {
            ct.ThrowIfCancellationRequested();

            var context = ActionContext.From(alert, subject, evidence, binding.Settings, sample, outcomes);
            var execution = await ExecuteOneAsync(alert, rule, binding, context, ct);

            results.Add(execution);
            Record(outcomes, execution);
        }

        return new DispatchResult(results);
    }

    /// <summary>
    /// Publishes what an action did, for the actions after it.
    ///
    /// Keyed by action type, so a message reads <c>{{actions.block_ip.status}}</c>. Where a rule has two
    /// actions of the same type — legitimate, through two connections — the later write wins, which makes
    /// the value the nearest preceding one. The reason is carried too, because "SKIPPED" alone does not
    /// tell an operator whether the address was on the never-block list or the gateway was disabled.
    /// </summary>
    private static void Record(Dictionary<string, string> outcomes, ActionExecution execution)
    {
        outcomes[$"{execution.ActionType}.status"] = execution.Status;
        outcomes[$"{execution.ActionType}.reason"] = execution.ErrorMessage ?? "";
        outcomes[$"{execution.ActionType}.target"] = execution.Target ?? "";
    }

    private async Task<ActionExecution> ExecuteOneAsync(
        Alert alert,
        RuleDefinition rule,
        RuleActionBinding binding,
        ActionContext context,
        CancellationToken ct)
    {
        var now = _clock.GetUtcNow();

        var execution = new ActionExecution
        {
            AlertId = alert.Id,
            RuleId = rule.RuleId,
            RuleVersion = rule.Version,
            ActionType = binding.Type,
            ConnectionName = binding.Connection,
            IdempotencyKey = IdempotencyKey(alert.AlertId, binding),
            Status = ActionExecutionStatus.Pending,
            CreatedAt = now.UtcDateTime
        };

        if (!registry.TryResolve(binding.Type, out var provider))
            return await SkipAsync(execution, "UNKNOWN_ACTION",
                $"No provider is registered for '{binding.Type}'.", now, ct);

        var descriptor = provider.Describe();
        execution.Target = ResolveTarget(descriptor, context);

        var connection = await connections.ByNameAsync(binding.Connection, ct);
        if (connection is null)
            return await SkipAsync(execution, "UNKNOWN_CONNECTION",
                $"Connection '{binding.Connection}' does not exist.", now, ct);

        if (!connection.Enabled)
            return await SkipAsync(execution, "CONNECTION_DISABLED",
                $"Connection '{binding.Connection}' is disabled.", now, ct);

        if (!string.Equals(connection.Type, descriptor.RequiredConnectionType, StringComparison.OrdinalIgnoreCase))
            return await SkipAsync(execution, "CONNECTION_TYPE_MISMATCH",
                $"'{binding.Type}' needs a {descriptor.RequiredConnectionType} connection, " +
                $"but '{binding.Connection}' is {connection.Type}.", now, ct);

        var verdict = await safety.EvaluateAsync(descriptor, rule.RuleId, execution.Target, ct);
        if (!verdict.Allowed)
        {
            logger.LogWarning(
                "Refused {Action} on {Target} for rule {RuleId}: {Reason}",
                binding.Type, execution.Target, rule.RuleId, verdict.Reason);

            return await SkipAsync(execution, verdict.Code!, verdict.Reason!, now, ct);
        }

        // Claimed before the first attempt. A duplicate claim means another node — or this one, before a
        // restart — already owns this action, and blocking an address twice is not the same as blocking it
        // once when the second call carries a fresh expiry.
        if (!await executions.TryClaimAsync(execution, ct))
        {
            logger.LogInformation(
                "Skipping {Action} for alert {Alert}: already claimed under {Key}",
                binding.Type, alert.AlertId, execution.IdempotencyKey);

            execution.Status = ActionExecutionStatus.Skipped;
            execution.ErrorCode = "ALREADY_EXECUTED";
            execution.ErrorMessage = "This action was already claimed for this alert.";
            execution.FinishedAt = now.UtcDateTime;
            return execution;
        }

        // Parked rather than performed, and only after the claim — so the gate cannot become a second way
        // to run the action. A node reaching this alert later finds the key already owned.
        //
        // Nothing here calls the provider, which is what makes the gate real: there is no path from a
        // pending approval to an executed action that does not pass through a person.
        if (binding.RequiresApproval)
        {
            execution.Status = ActionExecutionStatus.PendingApproval;
            execution.ApprovalExpiresAt = now.UtcDateTime.Add(safety.ApprovalWindow);
            execution.ErrorCode = "AWAITING_APPROVAL";
            execution.ErrorMessage =
                $"Held for approval until {execution.ApprovalExpiresAt:u}. It has not been carried out.";

            await executions.UpdateAsync(execution, ct);

            logger.LogInformation(
                "{Action} on {Target} for rule {RuleId} is awaiting approval",
                binding.Type, execution.Target, rule.RuleId);

            return execution;
        }

        return await AttemptAsync(execution, provider, context, connection, ct);
    }

    /// <summary>
    /// Carries out an action that was held for approval, once somebody has approved it.
    ///
    /// The same attempt path as any other action — the same retry, the same backoff, the same record — so
    /// an approved action is not a second implementation of dispatching that drifts from the first. What
    /// is different is only when it happens and that a person decided it.
    ///
    /// The claim was taken when it parked, so this does not claim again: the right to perform this action
    /// has been held since the alert was raised.
    /// </summary>
    public Task<ActionExecution> ExecuteApprovedAsync(
        ActionExecution execution,
        IActionProvider provider,
        ActionContext context,
        Connection connection,
        CancellationToken ct = default) =>
        AttemptAsync(execution, provider, context, connection, ct);

    private async Task<ActionExecution> AttemptAsync(
        ActionExecution execution,
        IActionProvider provider,
        ActionContext context,
        Connection connection,
        CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        execution.StartedAt = _clock.GetUtcNow().UtcDateTime;
        execution.Status = ActionExecutionStatus.Running;
        await executions.UpdateAsync(execution, ct);

        var attempts = Math.Max(1, retry.MaxAttempts);

        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            execution.RetryCount = attempt - 1;

            ActionOutcome outcome;
            try
            {
                outcome = await provider.ExecuteAsync(context, connection, execution.IdempotencyKey, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Shutting down. Left claimed and not terminal, so it is visible as unfinished rather than
                // silently lost — an action that never ran is an incident, not a tidy-up.
                execution.Status = ActionExecutionStatus.Retrying;
                execution.ErrorCode = "CANCELLED";
                execution.ErrorMessage = "The platform stopped before this action completed.";
                await executions.UpdateAsync(execution, ct: CancellationToken.None);
                throw;
            }
            catch (Exception ex)
            {
                outcome = ActionOutcome.Transient("PROVIDER_EXCEPTION", ex.Message);
                logger.LogError(ex, "{Action} threw for alert {Alert}", execution.ActionType, execution.AlertId);
            }

            execution.ResponseStatusCode = outcome.ResponseStatusCode;
            execution.RequestSummary = outcome.RequestSummary ?? execution.RequestSummary;

            if (outcome.Succeeded)
            {
                Finish(execution, ActionExecutionStatus.Success, stopwatch);
                execution.ErrorCode = null;
                execution.ErrorMessage = null;
                await executions.UpdateAsync(execution, ct);
                return execution;
            }

            execution.ErrorCode = outcome.ErrorCode;
            execution.ErrorMessage = outcome.ErrorMessage;

            // A permanent failure will fail identically on every attempt; retrying it only delays the
            // moment somebody finds out.
            if (!outcome.Retryable)
            {
                Finish(execution, ActionExecutionStatus.Failed, stopwatch);
                await executions.UpdateAsync(execution, ct);
                return execution;
            }

            if (attempt == attempts)
            {
                // Kept rather than discarded: an action that was supposed to block an address and never
                // did is exactly the record an operator needs to find.
                Finish(execution, ActionExecutionStatus.DeadLetter, stopwatch);
                await executions.UpdateAsync(execution, ct);
                return execution;
            }

            var delay = Backoff(attempt);
            execution.Status = ActionExecutionStatus.Retrying;
            execution.NextAttemptAt = _clock.GetUtcNow().Add(delay).UtcDateTime;
            await executions.UpdateAsync(execution, ct);

            await Task.Delay(delay, _clock, ct);
        }

        Finish(execution, ActionExecutionStatus.DeadLetter, stopwatch);
        await executions.UpdateAsync(execution, ct);
        return execution;
    }

    /// <summary>
    /// Exponential with jitter. The jitter matters more than the growth: without it, twenty actions that
    /// failed against the same unavailable API retry in lockstep and arrive together, which is how a
    /// recovering service is knocked over again.
    /// </summary>
    internal TimeSpan Backoff(int attempt)
    {
        var exponential = retry.BaseDelayMs * Math.Pow(2, attempt - 1);
        var capped = Math.Min(retry.MaxDelayMs, exponential);
        var jittered = capped * (0.5 + Random.Shared.NextDouble() * 0.5);

        return TimeSpan.FromMilliseconds(Math.Min(retry.MaxDelayMs, jittered));
    }

    /// <summary>
    /// Stable across restarts and across nodes, because it is derived from the alert and the binding rather
    /// than from anything about this process or this moment.
    /// </summary>
    internal static string IdempotencyKey(string alertId, RuleActionBinding binding)
    {
        var material = $"{alertId}|{binding.Type.ToLowerInvariant()}|{binding.Connection.ToLowerInvariant()}";
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));

        return Convert.ToHexString(digest)[..32].ToLowerInvariant();
    }

    /// <summary>
    /// What the action will act on, taken from the subject using the field the provider says it needs. The
    /// dispatcher does not know what a block target is; it asks.
    /// </summary>
    private static string ResolveTarget(ActionDescriptor descriptor, ActionContext context)
    {
        var setting = descriptor.Settings.FirstOrDefault(s => s.Key == "targetField");
        var path = context.Settings.TryGetValue("targetField", out var configured) && configured.Length > 0
            ? configured
            : setting?.Default ?? "";

        return path.Length > 0 && context.TryResolve(path, out var value) ? value : "";
    }

    /// <summary>
    /// Records an action that was deliberately not carried out, and says why.
    ///
    /// It is written, not merely returned. The reason this matters more here than in most places: the
    /// never-block list exists so the platform does not block the office's own egress address, and the
    /// moment it fires is exactly the moment somebody needs to be able to read "we did not block
    /// 192.168.9.11 because it is on the never-block list". Without a row, that is indistinguishable from
    /// the action never having been configured — the alert shows a message sent and no block, and nothing
    /// anywhere explains the difference.
    ///
    /// Found by arming a rule that blocks and notifies, against an address covered by the never-block
    /// list: the block was correctly withheld and left no trace outside one log line on the engine.
    /// </summary>
    private async Task<ActionExecution> SkipAsync(
        ActionExecution execution, string code, string reason, DateTimeOffset now, CancellationToken ct)
    {
        execution.Status = ActionExecutionStatus.Skipped;
        execution.ErrorCode = code;
        execution.ErrorMessage = reason;
        execution.FinishedAt = now.UtcDateTime;

        // StartedAt stays null: nothing started. The claim is what inserts the row, and a refused claim
        // means the skip is already recorded, which is the same outcome.
        try
        {
            await executions.TryClaimAsync(execution, ct);
        }
        catch (Exception ex)
        {
            // The skip is a record, not the operation. Failing to write it must not stop the rest of the
            // alert's actions from running.
            logger.LogError(ex,
                "Could not record that {Action} was skipped for alert {Alert}: {Reason}",
                execution.ActionType, execution.AlertId, reason);
        }

        return execution;
    }

    private void Finish(ActionExecution execution, string status, Stopwatch stopwatch)
    {
        stopwatch.Stop();
        execution.Status = status;
        execution.FinishedAt = _clock.GetUtcNow().UtcDateTime;
        execution.DurationMs = (int)stopwatch.ElapsedMilliseconds;
        execution.NextAttemptAt = null;
    }
}
