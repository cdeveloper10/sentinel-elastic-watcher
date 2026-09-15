namespace Sentinel.Domain.Alerts;

/// <summary>
/// One investigation, gathering the alerts that are about the same thing.
///
/// The unit an analyst works in is not an alert. Twelve alerts about one host in ten minutes are one
/// question — what is happening to that host — and answering it twelve times, closing twelve rows, is the
/// toil that makes people stop reading alerts altogether.
///
/// Built after disposition and enrichment rather than before, and the order matters: without a disposition
/// there is nothing to close a case *with*, and without enrichment two alerts about one machine — one
/// grouped by its address, one by the account on it — look like two unrelated subjects. Grouping before
/// either exists only tidies the noise.
/// </summary>
public class Case
{
    public int Id { get; set; }

    /// <summary>Stable, quotable identifier. What somebody puts in a ticket or says out loud.</summary>
    public string CaseId { get; set; } = "";

    public string Title { get; set; } = "";

    /// <summary>
    /// What this case is about, as the correlation decided it — <c>asset:dc01</c> or
    /// <c>subject:10.5.5.5</c>.
    ///
    /// Kept even after closing, because "show me every case we have ever had about this host" is the
    /// question somebody asks the second time it happens.
    /// </summary>
    public string EntityKey { get; set; } = "";

    /// <summary>The same thing in words, for a list somebody has to read.</summary>
    public string EntityLabel { get; set; } = "";

    /// <summary>
    /// <see cref="EntityKey"/> while the case is open, and null once it is closed.
    ///
    /// The mechanism, not a cache. A unique index on this column is what makes "at most one open case per
    /// entity" true under concurrency: two engine nodes raising alerts about one host at the same instant
    /// would otherwise both find nothing and both open a case. Nulls do not collide in either PostgreSQL
    /// or SQLite, so closed cases fall out of the constraint without needing a filtered index that has to
    /// be written differently per provider.
    /// </summary>
    public string? OpenKey { get; set; }

    /// <summary>One of <see cref="CaseStatus"/>.</summary>
    public string Status { get; set; } = CaseStatus.Open;

    /// <summary>The highest severity among its alerts. A case is as serious as the worst thing in it.</summary>
    public string Severity { get; set; } = "";

    public string? AssignedTo { get; set; }

    public int AlertCount { get; set; }

    public DateTime OpenedAt { get; set; }

    /// <summary>When the most recent alert joined. What decides whether the next one joins this case or starts another.</summary>
    public DateTime LastAlertAt { get; set; }

    public DateTime? ClosedAt { get; set; }
    public string? ClosedBy { get; set; }

    /// <summary>What the investigation concluded, from <see cref="AlertDisposition"/>.</summary>
    public string? Disposition { get; set; }

    public string? ClosingNote { get; set; }

    public ICollection<Alert> Alerts { get; set; } = [];
    public ICollection<CaseEvent> Events { get; set; } = [];
}

public static class CaseStatus
{
    public const string Open = "OPEN";

    /// <summary>Somebody has picked it up. Distinct from open, so a queue can be read at a glance.</summary>
    public const string Investigating = "INVESTIGATING";

    public const string Closed = "CLOSED";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Open, Investigating, Closed };

    public static string? Canonical(string? value) =>
        value is null ? null : All.FirstOrDefault(v => v.Equals(value, StringComparison.OrdinalIgnoreCase));

    public static bool IsOpen(string status) =>
        !Closed.Equals(status, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One thing that happened to a case, in order.
///
/// The timeline is the case's real content. A status field says where an investigation ended up; this says
/// how it got there — which alert arrived when, who picked it up, what they found, what the platform did.
/// It is also the answer to "what did we know at the time", which is the question asked afterwards.
///
/// Append-only. An event is a fact about a moment, and editing one would make the record of an
/// investigation something the investigation's outcome could rewrite.
/// </summary>
public class CaseEvent
{
    public long Id { get; set; }

    public int CaseId { get; set; }
    public Case? Case { get; set; }

    public DateTime At { get; set; }

    /// <summary>One of <see cref="CaseEventKind"/>.</summary>
    public string Kind { get; set; } = CaseEventKind.Note;

    /// <summary>Who, or null where the platform did it rather than a person.</summary>
    public string? Author { get; set; }

    public string Text { get; set; } = "";

    /// <summary>The alert this event is about, where it is about one.</summary>
    public long? AlertId { get; set; }
}

public static class CaseEventKind
{
    public const string Opened = "OPENED";
    public const string AlertAdded = "ALERT_ADDED";
    public const string Assigned = "ASSIGNED";
    public const string StatusChanged = "STATUS_CHANGED";

    /// <summary>Something a person wrote.</summary>
    public const string Note = "NOTE";

    public const string Closed = "CLOSED";
}
