namespace Sentinel.Application.Rules;

/// <summary>
/// A field the template assumes exists, and what it is for.
///
/// Named by role as well as by path because no two estates spell these the same way. The console compares
/// the path against the mapping it discovered and, when the index calls it something else, says which row
/// to repoint rather than leaving an author to work out why a template matched nothing.
/// </summary>
public sealed record TemplateField(string Path, string Role);

/// <summary>
/// A rule worth writing, minus the two things only the estate knows: which connection and which indices.
/// </summary>
public sealed record RuleTemplate(
    string Id,
    string Name,
    string Summary,

    /// <summary>What this catches and, just as usefully, what it does not. Shown on the template's card.</summary>
    string Purpose,

    string Severity,
    string StrategyType,
    IReadOnlyList<ConditionClause> Conditions,
    IReadOnlyList<string> GroupBy,
    long Threshold,
    int WindowSeconds,
    int IntervalSeconds,
    int QueryDelaySeconds,
    int CooldownSeconds,
    IReadOnlyList<TemplateField> Fields,

    /// <summary>A message that already says something useful, so an author edits rather than composes.</summary>
    string Message)
{
    /// <summary>The query these conditions mean — compiled here so the console never has to.</summary>
    public string QueryJson => ConditionQuery.ToQueryJson(Conditions);
}

/// <summary>
/// The rules people actually write, ready to be adjusted.
///
/// Not a convenience. The second rule of a family is the same as the first with two numbers changed, and
/// an author who has to rebuild it from an empty form each time writes fewer rules than one who does not —
/// which shows up as gaps in what the estate watches rather than as a complaint about the UI.
///
/// They are deliberately conservative: wide windows, unremarkable thresholds, long cooldowns, and no
/// actions at all. A template that arrived pre-wired to block addresses would be a template that blocks
/// the wrong ones on the day somebody clicked it without reading. Actions are added by hand, which is
/// where the decision belongs.
///
/// Field paths follow ECS where there is an ECS name for it. They will not match every index and are not
/// meant to — <see cref="RuleTemplate.Fields"/> says what each one is for so the console can offer the
/// local spelling.
/// </summary>
public static class RuleTemplates
{
    private const string Status = "http.response.status_code";
    private const string Service = "service.name";
    private const string Latency = "event.duration";

    public static readonly IReadOnlyList<RuleTemplate> All =
    [
        new(
            Id: "server-errors",
            Name: "Server errors from one service",
            Summary: "Ten or more 5xx responses from a single service in five minutes.",
            Purpose: "The everyday outage detector. Grouping by service is what makes it useful — a " +
                     "cluster-wide count of 5xx says the estate is unhealthy, which nobody can act on; " +
                     "this says which service.",
            Severity: "HIGH",
            StrategyType: "threshold",
            Conditions: [new ConditionClause(Status, ConditionOperator.AtLeast, ["500"], ConditionValueKind.Number)],
            GroupBy: [Service],
            Threshold: 10,
            WindowSeconds: 300,
            IntervalSeconds: 60,
            QueryDelaySeconds: 30,
            CooldownSeconds: 1800,
            Fields:
            [
                new TemplateField(Status, "HTTP status code, as a number"),
                new TemplateField(Service, "What to count separately — the service, API or application name")
            ],
            Message: "{{rule.name}}: {{subject}} returned {{evidence.eventCount}} server errors in " +
                     "{{evidence.window}}. Most recent at {{sample.@timestamp}}."),

        new(
            Id: "gateway-unavailable",
            Name: "Backend unreachable",
            Summary: "Five 502, 503 or 504 responses from one backend in three minutes.",
            Purpose: "Separated from ordinary 5xx because it means something different: the gateway is " +
                     "healthy and the thing behind it is not. Tighter window and lower threshold, because " +
                     "this is usually already an incident by the time it repeats.",
            Severity: "CRITICAL",
            StrategyType: "threshold",
            Conditions:
            [
                new ConditionClause(Status, ConditionOperator.OneOf, ["502", "503", "504"], ConditionValueKind.Number)
            ],
            GroupBy: [Service],
            Threshold: 5,
            WindowSeconds: 180,
            IntervalSeconds: 60,
            QueryDelaySeconds: 30,
            CooldownSeconds: 900,
            Fields:
            [
                new TemplateField(Status, "HTTP status code, as a number"),
                new TemplateField(Service, "The backend or upstream being called")
            ],
            Message: "{{rule.name}}: {{subject}} is answering {{evidence.eventCount}} gateway errors in " +
                     "{{evidence.window}}. Latest status {{sample.http.response.status_code}} at {{sample.@timestamp}}."),

        new(
            Id: "slow-backend",
            Name: "A service turned slow",
            Summary: "Twenty responses over three seconds from one service in five minutes.",
            Purpose: "Latency degradation before it becomes an error rate. Counting slow responses rather " +
                     "than averaging them is deliberate: an average hides twenty terrible requests behind " +
                     "two thousand quick ones, and it is the twenty that people are complaining about.",
            Severity: "MEDIUM",
            StrategyType: "threshold",
            Conditions:
            [
                new ConditionClause(Latency, ConditionOperator.AtLeast, ["3000"], ConditionValueKind.Number)
            ],
            GroupBy: [Service],
            Threshold: 20,
            WindowSeconds: 300,
            IntervalSeconds: 60,
            QueryDelaySeconds: 30,
            CooldownSeconds: 3600,
            Fields:
            [
                new TemplateField(Latency, "How long the call took, as a number — check the unit before trusting the threshold"),
                new TemplateField(Service, "What to count separately")
            ],
            Message: "{{rule.name}}: {{subject}} served {{evidence.eventCount}} slow responses in " +
                     "{{evidence.window}}. Slowest seen {{sample.event.duration}}."),

        new(
            Id: "auth-failures-account",
            Name: "Repeated sign-in failures for one account",
            Summary: "Five failed authentications for the same user in five minutes.",
            Purpose: "Grouped by account rather than by address, so it catches the slow attempt spread " +
                     "across many addresses that a per-address rule never sees. Usually a forgotten " +
                     "password; occasionally not.",
            Severity: "HIGH",
            StrategyType: "threshold",
            Conditions:
            [
                new ConditionClause("event.outcome", ConditionOperator.Is, ["failure"]),
                new ConditionClause("event.category", ConditionOperator.Is, ["authentication"])
            ],
            GroupBy: ["user.name"],
            Threshold: 5,
            WindowSeconds: 300,
            IntervalSeconds: 60,
            QueryDelaySeconds: 30,
            CooldownSeconds: 1800,
            Fields:
            [
                new TemplateField("event.outcome", "Whether the attempt succeeded — usually a keyword field"),
                new TemplateField("event.category", "What kind of event it is"),
                new TemplateField("user.name", "The account being signed in to")
            ],
            Message: "{{rule.name}}: {{evidence.eventCount}} failed sign-ins for {{subject}} in " +
                     "{{evidence.window}}, from {{sample.source.ip}}."),

        new(
            Id: "brute-force-address",
            Name: "Many sign-in failures from one address",
            Summary: "Twenty failed authentications from the same address in five minutes.",
            Purpose: "The rule people reach for first, and the one to be most careful with. Behind NAT " +
                     "every employee shares an address, so add that range to the never-block list before " +
                     "attaching any blocking action to this.",
            Severity: "CRITICAL",
            StrategyType: "threshold",
            Conditions:
            [
                new ConditionClause("event.outcome", ConditionOperator.Is, ["failure"]),
                new ConditionClause("event.category", ConditionOperator.Is, ["authentication"])
            ],
            GroupBy: ["source.ip"],
            Threshold: 20,
            WindowSeconds: 300,
            IntervalSeconds: 60,
            QueryDelaySeconds: 30,
            CooldownSeconds: 3600,
            Fields:
            [
                new TemplateField("event.outcome", "Whether the attempt succeeded"),
                new TemplateField("event.category", "What kind of event it is"),
                new TemplateField("source.ip", "The address the attempt came from")
            ],
            Message: "{{rule.name}}: {{evidence.eventCount}} failed sign-ins from {{subject}} in " +
                     "{{evidence.window}}, most recently against {{sample.user.name}}."),

        new(
            Id: "client-errors",
            Name: "A client is being rejected",
            Summary: "Fifty 4xx responses to one caller in ten minutes.",
            Purpose: "Catches an integration that broke on the client's side — an expired key, a changed " +
                     "contract, a retry loop. Threshold is high on purpose: a handful of 404s is the " +
                     "normal noise of any public endpoint.",
            Severity: "LOW",
            StrategyType: "threshold",
            Conditions:
            [
                new ConditionClause(Status, ConditionOperator.Between, ["400", "499"], ConditionValueKind.Number)
            ],
            GroupBy: ["client.name"],
            Threshold: 50,
            WindowSeconds: 600,
            IntervalSeconds: 120,
            QueryDelaySeconds: 30,
            CooldownSeconds: 7200,
            Fields:
            [
                new TemplateField(Status, "HTTP status code, as a number"),
                new TemplateField("client.name", "Who is calling — the application, key or consumer name")
            ],
            Message: "{{rule.name}}: {{subject}} received {{evidence.eventCount}} rejections in " +
                     "{{evidence.window}}. Last one {{sample.http.response.status_code}} on {{sample.url.path}}.")
    ];

    public static RuleTemplate? Find(string? id) =>
        All.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}
