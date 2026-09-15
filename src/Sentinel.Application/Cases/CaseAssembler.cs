using Microsoft.Extensions.Logging;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Rules;

namespace Sentinel.Application.Cases;

/// <summary>Where cases live.</summary>
public interface ICaseStore
{
    /// <summary>The open case for this entity, or null. Closed cases are never returned: they are finished.</summary>
    Task<Case?> OpenForAsync(string entityKey, CancellationToken ct = default);

    /// <summary>
    /// Opens one, returning false when another node opened it first.
    ///
    /// Attempted-then-caught rather than checked-then-written, the way alerts and action claims are: two
    /// engine nodes raising alerts about one host in the same instant would both find nothing, both
    /// insert, and one investigation would become two.
    /// </summary>
    Task<bool> TryOpenAsync(Case newCase, CancellationToken ct = default);

    Task AttachAsync(Case existing, Alert alert, CaseEvent entry, CancellationToken ct = default);
}

public sealed class CaseSettings
{
    /// <summary>
    /// Grouping is off unless this is on, because a platform that starts silently filing alerts into
    /// investigations changes what every existing queue looks like.
    /// </summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// Puts each new alert into an investigation.
///
/// Runs after the alert is written, because it needs the row's identity — and because an alert that
/// failed deduplication must not open a case for an incident already being investigated.
///
/// Like the enrichment stage, a failure here cannot cost the alert. A case is how the alert is *organised*;
/// losing one is untidy, and losing the alert because the tidying failed would be a far worse trade.
/// </summary>
public sealed class CaseAssembler(
    ICaseStore cases,
    CaseSettings settings,
    ILogger<CaseAssembler> logger,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private static readonly IReadOnlyList<string> Order =
        [Severity.Low, Severity.Medium, Severity.High, Severity.Critical];

    /// <summary>The case this alert belongs to, opening one if nothing suitable is already open.</summary>
    public async Task<Case?> PlaceAsync(
        Alert alert,
        IReadOnlyDictionary<string, string> enrichment,
        CancellationToken ct = default)
    {
        if (!settings.Enabled)
            return null;

        try
        {
            return await AssignAsync(alert, enrichment, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex, "Alert {Alert} could not be placed in a case; it stands on its own", alert.AlertId);

            return null;
        }
    }

    private async Task<Case?> AssignAsync(
        Alert alert, IReadOnlyDictionary<string, string> enrichment, CancellationToken ct)
    {
        var entity = CaseCorrelation.For(alert, enrichment);
        var now = _clock.GetUtcNow().UtcDateTime;

        // While a case for this entity is open, every alert about it joins that case, however long the
        // gap. There was a time window here and it had to go: it contradicted the constraint it sat
        // beside. "At most one open case per entity" and "an alert four hours later starts a new one" are
        // the same statement only if the platform closes the old one — and closing an investigation is a
        // conclusion, which only a person can reach.
        //
        // So a case ends when somebody ends it. A case that grows for a week is a true statement about
        // the queue not being worked, and hiding it behind an automatic split would make that invisible.
        var existing = await cases.OpenForAsync(entity.Key, ct);

        if (existing is not null)
        {
            existing.AlertCount++;
            existing.LastAlertAt = now;
            existing.Severity = Highest(existing.Severity, alert.Severity);

            await cases.AttachAsync(existing, alert, new CaseEvent
            {
                CaseId = existing.Id,
                At = now,
                Kind = CaseEventKind.AlertAdded,
                AlertId = alert.Id,
                Text = $"{alert.RuleName} fired on {alert.Subject} ({alert.EventCount} event(s), {alert.Severity})."
            }, ct);

            return existing;
        }

        var opened = new Case
        {
            CaseId = $"CASE-{now:yyyyMMdd}-{Guid.NewGuid().ToString("n")[..6].ToUpperInvariant()}",
            Title = CaseCorrelation.Title(entity),
            EntityKey = entity.Key,
            EntityLabel = entity.Label,
            OpenKey = entity.Key,
            Status = CaseStatus.Open,
            Severity = alert.Severity,
            AlertCount = 1,
            OpenedAt = now,
            LastAlertAt = now
        };

        if (await cases.TryOpenAsync(opened, ct))
        {
            await cases.AttachAsync(opened, alert, new CaseEvent
            {
                CaseId = opened.Id,
                At = now,
                Kind = CaseEventKind.Opened,
                AlertId = alert.Id,
                Text = $"Opened by {alert.RuleName} on {alert.Subject}."
            }, ct);

            return opened;
        }

        // Another node won. Whatever it opened is the case this alert belongs to, so ask again rather
        // than treating the race as a failure.
        var theirs = await cases.OpenForAsync(entity.Key, ct);

        if (theirs is null)
            return null;

        theirs.AlertCount++;
        theirs.LastAlertAt = now;
        theirs.Severity = Highest(theirs.Severity, alert.Severity);

        await cases.AttachAsync(theirs, alert, new CaseEvent
        {
            CaseId = theirs.Id,
            At = now,
            Kind = CaseEventKind.AlertAdded,
            AlertId = alert.Id,
            Text = $"{alert.RuleName} fired on {alert.Subject} ({alert.EventCount} event(s), {alert.Severity})."
        }, ct);

        return theirs;
    }

    /// <summary>A case is as serious as the worst thing in it, and never becomes less so.</summary>
    internal static string Highest(string current, string candidate)
    {
        var currentRank = Rank(current);
        var candidateRank = Rank(candidate);

        return candidateRank > currentRank ? Order[candidateRank] : current;
    }

    private static int Rank(string severity)
    {
        for (var i = 0; i < Order.Count; i++)
        {
            if (Order[i].Equals(severity, StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return 0;
    }
}
