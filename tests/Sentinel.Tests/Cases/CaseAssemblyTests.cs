using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Cases;
using Sentinel.Domain.Alerts;
using Sentinel.Domain.Rules;

namespace Sentinel.Tests.Cases;

/// <summary>
/// Gathering alerts into investigations.
///
/// The unit an analyst works in is not an alert. Twelve alerts about one host in ten minutes are one
/// question, and answering it twelve times is the toil that makes people stop reading alerts.
///
/// What is worth protecting here is mostly restraint: grouping that nobody can explain is grouping nobody
/// trusts, so the rule is deliberately short, and a failure to file an alert must never become a failure
/// to record it.
/// </summary>
public class CaseAssemblyTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 2, 14, 0, 0, TimeSpan.Zero);

    private static Alert Alert(
        string subject = "source.ip=10.5.5.5",
        string severity = Severity.Medium,
        string rule = "Brute force",
        long id = 1) => new()
    {
        Id = id,
        AlertId = $"alert-{id}",
        RuleId = 1,
        RuleVersion = 1,
        RuleName = rule,
        Severity = severity,
        Subject = subject,
        EventCount = 20,
        DetectedAt = Now.UtcDateTime
    };

    private static Dictionary<string, string> Asset(string name) =>
        new(StringComparer.OrdinalIgnoreCase) { ["asset.name"] = name };

    private static Dictionary<string, string> Nothing() => new(StringComparer.OrdinalIgnoreCase);

    private static CaseAssembler Assembler(
        InMemoryCases store, CaseSettings? settings = null, DateTimeOffset? at = null) =>
        new(store, settings ?? new CaseSettings(), NullLogger<CaseAssembler>.Instance, new FixedClock(at ?? Now));

    // -- correlation ---------------------------------------------------------

    [Fact]
    public void Two_alerts_about_one_asset_correlate_even_when_the_rules_saw_it_differently()
    {
        // The reason cases come after enrichment. A brute-force rule identifies an address and a lockout
        // rule identifies an account; both enrich to dc01. Without the asset they are two unrelated
        // subjects and the analyst is the one who has to notice — which is the work being removed.
        var byAddress = CaseCorrelation.For(Alert(subject: "source.ip=10.5.5.5"), Asset("dc01"));
        var byAccount = CaseCorrelation.For(Alert(subject: "user.name=svc-backup"), Asset("dc01"));

        Assert.Equal(byAddress.Key, byAccount.Key);
        Assert.Equal("dc01", byAddress.Label);
    }

    [Fact]
    public void Without_an_asset_it_falls_back_to_the_subject()
    {
        var entity = CaseCorrelation.For(Alert(subject: "source.ip=10.5.5.5"), Nothing());

        Assert.Equal("subject:source.ip=10.5.5.5", entity.Key);
    }

    [Fact]
    public void The_key_ignores_casing_and_the_label_does_not()
    {
        // "AiServices" and "aiservices" are one host; the label is what a person recognises.
        Assert.Equal(
            CaseCorrelation.For(Alert(), Asset("DC01")).Key,
            CaseCorrelation.For(Alert(), Asset("dc01")).Key);

        Assert.Equal("DC01", CaseCorrelation.For(Alert(), Asset("DC01")).Label);
    }

    // -- assembly ------------------------------------------------------------

    [Fact]
    public async Task The_first_alert_opens_a_case()
    {
        var store = new InMemoryCases();

        var opened = await Assembler(store).PlaceAsync(Alert(), Asset("dc01"));

        Assert.NotNull(opened);
        Assert.Equal("dc01", opened!.Title);
        Assert.Equal(CaseStatus.Open, opened.Status);
        Assert.Equal(1, opened.AlertCount);
        Assert.Single(store.Events);
        Assert.Equal(CaseEventKind.Opened, store.Events[0].Kind);
    }

    [Fact]
    public async Task The_next_alert_about_the_same_thing_joins_it()
    {
        var store = new InMemoryCases();
        var assembler = Assembler(store);

        var first = await assembler.PlaceAsync(Alert(id: 1), Asset("dc01"));
        var second = await assembler.PlaceAsync(Alert(id: 2, rule: "Slow backend"), Asset("dc01"));

        Assert.Equal(first!.Id, second!.Id);
        Assert.Equal(2, second.AlertCount);
        Assert.Single(store.Cases);

        // The timeline says which rule brought each one, because "why is this alert in this case" is the
        // first thing somebody asks of a grouping they did not make.
        Assert.Contains(store.Events, e => e.Kind == CaseEventKind.AlertAdded && e.Text.Contains("Slow backend"));
    }

    [Fact]
    public async Task An_alert_about_something_else_gets_its_own_case()
    {
        var store = new InMemoryCases();
        var assembler = Assembler(store);

        await assembler.PlaceAsync(Alert(id: 1), Asset("dc01"));
        await assembler.PlaceAsync(Alert(id: 2), Asset("payments-01"));

        Assert.Equal(2, store.Cases.Count);
    }

    [Fact]
    public async Task A_case_is_as_serious_as_the_worst_thing_in_it()
    {
        var store = new InMemoryCases();
        var assembler = Assembler(store);

        await assembler.PlaceAsync(Alert(id: 1, severity: Severity.Low), Asset("dc01"));
        var after = await assembler.PlaceAsync(Alert(id: 2, severity: Severity.Critical), Asset("dc01"));

        Assert.Equal(Severity.Critical, after!.Severity);

        // And never becomes less so: a later low-severity alert does not calm an investigation down.
        var last = await assembler.PlaceAsync(Alert(id: 3, severity: Severity.Low), Asset("dc01"));

        Assert.Equal(Severity.Critical, last!.Severity);
    }

    [Fact]
    public async Task An_alert_hours_later_still_joins_an_open_case()
    {
        // There was a time window here, and writing this test is what removed it: it contradicted the
        // constraint beside it. "At most one open case per entity" and "an alert four hours later starts
        // a new one" can only both hold if something closes the old case — and concluding an
        // investigation is a judgement only a person can make.
        //
        // So an open case stays the case for its entity until somebody closes it. One that has been
        // collecting alerts all week is a true statement about the queue not being worked.
        var store = new InMemoryCases();

        var first = await Assembler(store).PlaceAsync(Alert(id: 1), Asset("dc01"));
        var second = await Assembler(store, at: Now.AddHours(4)).PlaceAsync(Alert(id: 2), Asset("dc01"));

        Assert.Single(store.Cases);
        Assert.Equal(first!.Id, second!.Id);
        Assert.Equal(Now.AddHours(4).UtcDateTime, second.LastAlertAt);
    }

    [Fact]
    public async Task A_closed_case_is_never_reopened()
    {
        // Closed means somebody finished. The next alert about that host is the next investigation, not a
        // continuation of one whose conclusion has already been recorded.
        var store = new InMemoryCases();
        var assembler = Assembler(store);

        var first = await assembler.PlaceAsync(Alert(id: 1), Asset("dc01"));

        first!.Status = CaseStatus.Closed;
        first.OpenKey = null;

        var second = await assembler.PlaceAsync(Alert(id: 2), Asset("dc01"));

        Assert.NotEqual(first.Id, second!.Id);
        Assert.Equal(CaseStatus.Open, second.Status);
    }

    [Fact]
    public async Task Losing_the_race_to_open_one_joins_the_winner()
    {
        // Two engine nodes raising alerts about one host in the same instant. The constraint refuses the
        // second insert, and the right answer is to join what the other node opened rather than to treat
        // the refusal as a failure.
        var store = new InMemoryCases { RefuseNextOpen = true };

        var placed = await Assembler(store).PlaceAsync(Alert(id: 2), Asset("dc01"));

        Assert.NotNull(placed);
        Assert.Equal("opened-elsewhere", placed!.CaseId);
        Assert.Equal(2, placed.AlertCount);
    }

    [Fact]
    public async Task Grouping_can_be_switched_off()
    {
        var store = new InMemoryCases();

        var placed = await Assembler(store, new CaseSettings { Enabled = false }).PlaceAsync(Alert(), Asset("dc01"));

        Assert.Null(placed);
        Assert.Empty(store.Cases);
    }

    [Fact]
    public async Task A_store_that_fails_costs_the_case_and_not_the_alert()
    {
        // Filing is how an alert is organised. Losing the alert because the filing failed would be a far
        // worse trade than an alert that stands on its own.
        var store = new InMemoryCases { Throws = new InvalidOperationException("the database went away") };

        var placed = await Assembler(store).PlaceAsync(Alert(), Asset("dc01"));

        Assert.Null(placed);
    }

    [Fact]
    public void Severity_only_rises()
    {
        Assert.Equal(Severity.Critical, CaseAssembler.Highest(Severity.Low, Severity.Critical));
        Assert.Equal(Severity.Critical, CaseAssembler.Highest(Severity.Critical, Severity.Low));
        Assert.Equal(Severity.High, CaseAssembler.Highest(Severity.High, Severity.High));
    }

    // -- doubles -------------------------------------------------------------

    private sealed class InMemoryCases : ICaseStore
    {
        public List<Case> Cases { get; } = [];
        public List<CaseEvent> Events { get; } = [];

        /// <summary>Stands in for the unique index refusing a second open case for one entity.</summary>
        public bool RefuseNextOpen { get; set; }

        public Exception? Throws { get; set; }

        private int _nextId = 1;

        public Task<Case?> OpenForAsync(string entityKey, CancellationToken ct = default)
        {
            if (Throws is not null)
                throw Throws;

            if (RefuseNextOpen && Cases.Count == 0)
            {
                // What the winning node left behind, found on the second look.
                Cases.Add(new Case
                {
                    Id = _nextId++,
                    CaseId = "opened-elsewhere",
                    EntityKey = entityKey,
                    OpenKey = entityKey,
                    Status = CaseStatus.Open,
                    Severity = Severity.Medium,
                    AlertCount = 1
                });

                RefuseNextOpen = false;
                return Task.FromResult<Case?>(null);
            }

            return Task.FromResult(Cases.FirstOrDefault(c => c.OpenKey == entityKey));
        }

        public Task<bool> TryOpenAsync(Case newCase, CancellationToken ct = default)
        {
            if (Cases.Any(c => c.OpenKey == newCase.OpenKey))
                return Task.FromResult(false);

            newCase.Id = _nextId++;
            Cases.Add(newCase);

            return Task.FromResult(true);
        }

        public Task AttachAsync(Case existing, Alert alert, CaseEvent entry, CancellationToken ct = default)
        {
            alert.CaseId = existing.Id;
            Events.Add(entry);

            return Task.CompletedTask;
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
