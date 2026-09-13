using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Application.Detection;

/// <summary>
/// The four mechanisms that keep one condition from becoming a thousand actions. They are separate on
/// purpose, and confusing any two of them produces a different bug.
///
/// <list type="bullet">
/// <item><b>Aggregation</b> collapses many events into one detection. Done by the source: a thousand
/// failed logins from one address are counted, not enumerated.</item>
/// <item><b>Deduplication</b> stops the same detection being recorded twice. Guards restarts, retries and
/// overlapping evaluations of the same window — see <see cref="DetectionFingerprint"/>.</item>
/// <item><b>Cooldown</b> suppresses the <em>next</em> detection for a subject that has already fired. This
/// is what makes sliding windows workable — see <see cref="CooldownPolicy"/>.</item>
/// <item><b>Idempotency</b> stops one detection's action running twice. Lives with the dispatcher, not
/// here.</item>
/// </list>
/// </summary>
public static class DetectionFingerprint
{
    /// <summary>
    /// A stable identity for "this rule version saw this subject in this evaluation".
    ///
    /// The window end is rounded down to the evaluation interval, which is what makes re-running a
    /// scheduled evaluation produce the same fingerprint. Without that rounding, a process that restarted
    /// mid-run would evaluate a window ending a few seconds later, compute a different fingerprint, and
    /// record a duplicate detection for an event it had already acted on.
    /// </summary>
    public static string Compute(
        int ruleId,
        int ruleVersion,
        IReadOnlyDictionary<string, string> subject,
        DateTimeOffset windowEnd,
        TimeSpan interval)
    {
        var bucket = Bucket(windowEnd, interval);

        // Subject fields are ordered so that a group-by written as [ip, user] and one written as
        // [user, ip] cannot produce two identities for the same pair.
        var parts = subject
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"{pair.Key}={pair.Value}");

        var material = string.Join('|', [
            ruleId.ToString(),
            ruleVersion.ToString(),
            bucket.ToUnixTimeSeconds().ToString(),
            .. parts
        ]);

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    /// <summary>Floors an instant to the interval grid, so equivalent evaluations agree on their bucket.</summary>
    public static DateTimeOffset Bucket(DateTimeOffset instant, TimeSpan interval)
    {
        if (interval <= TimeSpan.Zero)
            return instant;

        var ticks = instant.UtcTicks - instant.UtcTicks % interval.Ticks;
        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    /// <summary>
    /// The subject as a single readable string, for keys and for display. Distinct from the fingerprint:
    /// this one is meant to be legible, and cooldown is keyed on it so an operator can see what is
    /// suppressed and why.
    /// </summary>
    public static string SubjectKey(IReadOnlyDictionary<string, string> subject) =>
        subject.Count == 0
            ? "*"
            : string.Join(',', subject
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
}

/// <summary>Whether a subject that already fired is allowed to fire again yet.</summary>
public static class CooldownPolicy
{
    /// <summary>
    /// Cooldown is per rule <em>and subject</em>, never per rule alone.
    ///
    /// Silencing a whole rule because one address triggered it would mean an attacker could shield every
    /// other address by tripping the rule once, deliberately, from somewhere expendable. It would also
    /// mean the first noisy subject in an incident hides the rest of it.
    /// </summary>
    public static bool IsSuppressed(DateTimeOffset? lastFiredAt, DateTimeOffset now, TimeSpan cooldown)
    {
        if (lastFiredAt is null || cooldown <= TimeSpan.Zero)
            return false;

        return now < lastFiredAt.Value + cooldown;
    }

    public static DateTimeOffset? SuppressedUntil(DateTimeOffset? lastFiredAt, TimeSpan cooldown) =>
        lastFiredAt is null || cooldown <= TimeSpan.Zero ? null : lastFiredAt.Value + cooldown;

    /// <summary>Key a cooldown record is stored under. Same shape as the fingerprint's subject, without the window.</summary>
    public static string Key(int ruleId, IReadOnlyDictionary<string, string> subject) =>
        $"rule:{ruleId}:{DetectionFingerprint.SubjectKey(subject)}";
}
