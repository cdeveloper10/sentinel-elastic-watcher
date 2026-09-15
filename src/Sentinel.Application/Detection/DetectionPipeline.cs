using System.Text.Json;
using Sentinel.Application.Cases;
using Sentinel.Application.Enrichment;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Domain.Alerts;

namespace Sentinel.Application.Detection;

/// <summary>Why a candidate did not become an alert. Recorded rather than discarded, so silence is explicable.</summary>
public enum CandidateOutcome
{
    Alerted,
    SuppressedByCooldown,
    DuplicateOfExistingAlert
}

public sealed record PipelineDecision(
    DetectionCandidate Candidate,
    CandidateOutcome Outcome,
    Alert? Alert,
    string? Detail);

public sealed record PipelineResult(IReadOnlyList<PipelineDecision> Decisions)
{
    public IEnumerable<Alert> NewAlerts =>
        Decisions.Where(d => d.Outcome == CandidateOutcome.Alerted && d.Alert is not null).Select(d => d.Alert!);

    public int Suppressed => Decisions.Count(d => d.Outcome == CandidateOutcome.SuppressedByCooldown);
    public int Duplicates => Decisions.Count(d => d.Outcome == CandidateOutcome.DuplicateOfExistingAlert);
}

/// <summary>Where a subject's last firing is remembered, so cooldown survives a restart.</summary>
public interface ICooldownStore
{
    Task<DateTimeOffset?> LastFiredAtAsync(string key, CancellationToken ct = default);

    Task RecordAsync(string key, DateTimeOffset firedAt, TimeSpan retention, CancellationToken ct = default);
}

/// <summary>
/// Where alerts live. <see cref="TryInsertAsync"/> returns false when the fingerprint already exists —
/// deduplication as a uniqueness constraint the database enforces, rather than a read-then-write that two
/// nodes can both win.
/// </summary>
public interface IAlertStore
{
    Task<bool> TryInsertAsync(Alert alert, CancellationToken ct = default);
}

/// <summary>
/// Turns what a strategy found into what the platform will act on.
///
/// This is where the second and third of the four suppression mechanisms live, and the order they run in
/// is the point. Deduplication asks "have I already recorded this exact evaluation?" and guards restarts
/// and overlapping windows; cooldown asks "has this subject fired recently enough that firing again would
/// be noise?" and guards the overlap sliding windows create by design.
///
/// Cooldown is checked first because it is cheaper and answers more often. But deduplication is what
/// actually holds under concurrency: two nodes evaluating the same window will both pass the cooldown
/// check, and only one insert will win the unique index.
/// </summary>
public sealed class DetectionPipeline(
    IAlertStore alerts,
    ICooldownStore cooldowns,
    TimeProvider? clock = null,
    EnrichmentPipeline? enrichment = null,
    CaseAssembler? cases = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    // Both defaulted rather than required, so a test asking about cooldown or deduplication does not have
    // to assemble stages it has no opinion about. The container supplies the real ones.
    private readonly EnrichmentPipeline _enrichment = enrichment ?? EnrichmentPipeline.None;
    private readonly CaseAssembler? _cases = cases;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public async Task<PipelineResult> ProcessAsync(
        RuleDefinition rule,
        IReadOnlyList<DetectionCandidate> candidates,
        CancellationToken ct = default)
    {
        var decisions = new List<PipelineDecision>(candidates.Count);
        var now = _clock.GetUtcNow();

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();

            var cooldownKey = CooldownPolicy.Key(rule.RuleId, candidate.Subject);
            var lastFired = await cooldowns.LastFiredAtAsync(cooldownKey, ct);

            if (CooldownPolicy.IsSuppressed(lastFired, candidate.Window.To, rule.Cooldown))
            {
                var until = CooldownPolicy.SuppressedUntil(lastFired, rule.Cooldown);
                decisions.Add(new PipelineDecision(
                    candidate,
                    CandidateOutcome.SuppressedByCooldown,
                    null,
                    $"In cooldown until {until:O}."));
                continue;
            }

            // After cooldown and before the insert. After, so a suppressed candidate costs no lookups;
            // before, so what was found is part of the row rather than a second write — and so a critical
            // asset raises the severity that gets recorded rather than one that has to be corrected.
            //
            // The cost of being before the deduplicating insert is that a losing race enriches for
            // nothing. Those are rare — a retry, a restart, two nodes — and the alternative is writing
            // every alert twice.
            var enriched = await _enrichment.EnrichAsync(
                new EnrichmentRequest(rule.RuleId, rule.Name, rule.Severity, candidate.Subject, candidate.Sample),
                ct);

            var alert = Build(rule, candidate, now, enriched);

            // The unique fingerprint decides. A losing insert means another evaluation of this same window
            // already recorded it — a retry, a restart, or the other node.
            if (!await alerts.TryInsertAsync(alert, ct))
            {
                decisions.Add(new PipelineDecision(
                    candidate,
                    CandidateOutcome.DuplicateOfExistingAlert,
                    null,
                    "An alert with this fingerprint already exists."));
                continue;
            }

            // After the insert, because it needs the row's identity — and because an alert that lost the
            // deduplicating race must not open an investigation into an incident already being
            // investigated.
            if (_cases is not null)
                alert.Case = await _cases.PlaceAsync(alert, enriched.Facts, ct);

            // Recorded only after the alert is committed, so a failed insert cannot leave a subject in
            // cooldown for an alert that does not exist.
            await cooldowns.RecordAsync(
                cooldownKey,
                candidate.Window.To,
                // Kept a little past the cooldown, so a record cannot expire between the check and the use.
                rule.Cooldown + TimeSpan.FromMinutes(5),
                ct);

            decisions.Add(new PipelineDecision(candidate, CandidateOutcome.Alerted, alert, null));
        }

        return new PipelineResult(decisions);
    }

    private static Alert Build(
        RuleDefinition rule, DetectionCandidate candidate, DateTimeOffset now, EnrichedAlert enriched)
    {
        var subject = candidate.Subject;

        return new Alert
        {
            AlertId = Guid.NewGuid().ToString("n"),
            Fingerprint = DetectionFingerprint.Compute(
                rule.RuleId, rule.Version, subject, candidate.Window.To, rule.Interval),

            RuleId = rule.RuleId,
            RuleVersion = rule.Version,
            RuleName = rule.Name,

            // What the rule said, unless an enrichment argued for more. It can only have been raised —
            // see EnrichmentPipeline for why lowering is not offered.
            Severity = enriched.Severity,

            // Null rather than "{}" when nothing was found, so "no enrichment is registered" and "the
            // enrichments found nothing about this subject" do not read identically in the console.
            EnrichmentJson = enriched.Any ? JsonSerializer.Serialize(enriched.Facts, Json) : null,

            Subject = DetectionFingerprint.SubjectKey(subject),
            SubjectJson = JsonSerializer.Serialize(subject, Json),

            // Lifted out for filtering when the rule grouped by them; null when it grouped by something else.
            SourceIp = Find(subject, "source.ip", "client.ip", "ip"),
            UserId = Find(subject, "user.id", "user.name", "userId"),

            EventCount = candidate.EventCount,
            EvidenceJson = JsonSerializer.Serialize(candidate.Evidence, Json),

            // Null rather than "{}" when there is none, so the console can tell "this source gave no
            // sample" from "the sample had no fields" and say so instead of showing an empty panel.
            SampleJson = candidate.Sample is null ? null : JsonSerializer.Serialize(candidate.Sample, Json),

            WindowFrom = candidate.Window.From.UtcDateTime,
            WindowTo = candidate.Window.To.UtcDateTime,
            DetectedAt = now.UtcDateTime,

            Status = AlertStatus.Detected
        };
    }

    private static string? Find(IReadOnlyDictionary<string, string> subject, params string[] names)
    {
        foreach (var name in names)
        {
            if (subject.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }
}
