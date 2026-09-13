using Sentinel.Application.Detection;
using Sentinel.Application.Rules;
using Sentinel.Infrastructure.Elasticsearch;

namespace Sentinel.Tests.Rules;

/// <summary>
/// That every offered template is a rule the platform would actually accept.
///
/// A template that cannot be saved is worse than no template: the author picks it expecting a head start
/// and gets a form full of validation errors they did not write, which costs more confidence than it saves
/// time. These run the templates through the same validator the save endpoint uses and the same query
/// check the source applies.
///
/// It is also the guard that keeps the catalogue honest as the platform changes. Tighten the interval
/// bounds or rename a strategy and the templates fail here, at build time, rather than in front of whoever
/// clicked one.
/// </summary>
public class RuleTemplateTests
{
    // The real registry with the real strategies, because a template naming a strategy that does not
    // exist is exactly one of the things this is here to catch.
    private static readonly RuleValidator Validator = new(
        new DetectionStrategyRegistry([new ThresholdDetectionStrategy(), new MatchDetectionStrategy()]));

    private static RuleDefinition AsRule(RuleTemplate template) => new(
        RuleId: 0,
        Version: 1,
        Name: template.Name,
        Description: template.Summary,
        Severity: template.Severity,

        // The two the template deliberately does not carry, filled in with what the console requires an
        // author to choose before the form can be submitted.
        ConnectionId: 1,
        IndexPatterns: ["gateway-logs-*"],

        QueryJson: template.QueryJson,
        TimestampField: "@timestamp",
        StrategyType: template.StrategyType,
        GroupBy: template.GroupBy,
        Threshold: template.Threshold,
        Window: TimeSpan.FromSeconds(template.WindowSeconds),
        QueryDelay: TimeSpan.FromSeconds(template.QueryDelaySeconds),
        Interval: TimeSpan.FromSeconds(template.IntervalSeconds),
        Cooldown: TimeSpan.FromSeconds(template.CooldownSeconds),
        Actions: []);

    public static TheoryData<string> Ids()
    {
        var data = new TheoryData<string>();

        foreach (var template in RuleTemplates.All)
            data.Add(template.Id);

        return data;
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void Every_template_is_a_rule_the_platform_would_accept(string id)
    {
        var template = RuleTemplates.Find(id)!;
        var result = Validator.Validate(AsRule(template), QueryProblem);

        Assert.True(result.IsValid,
            $"{id}: {string.Join("; ", result.Failures.Select(f => $"{f.Field} {f.Message}"))}");
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void Every_template_compiles_to_a_query_the_source_accepts(string id)
    {
        var template = RuleTemplates.Find(id)!;

        Assert.True(ElasticsearchQueryBuilder.IsValidQuery(template.QueryJson, out var error), $"{id}: {error}");
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void Every_template_opens_in_the_builder(string id)
    {
        // The point of shipping conditions rather than a blob of JSON: picking a template puts rows on
        // screen that an author can retarget at their own field names in two clicks.
        var template = RuleTemplates.Find(id)!;

        Assert.True(ConditionQuery.TryRead(template.QueryJson, out var read), id);
        Assert.Equal(template.Conditions.Count, read.Count);
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void Every_field_a_template_uses_is_one_it_declares(string id)
    {
        // The declared list is what the console checks against the discovered mapping to say "your index
        // calls this something else". A condition on an undeclared field would slip past that check and
        // silently match nothing.
        var template = RuleTemplates.Find(id)!;
        var declared = template.Fields.Select(f => f.Path).ToHashSet(StringComparer.Ordinal);

        foreach (var field in template.Conditions.Select(c => c.Field).Concat(template.GroupBy))
            Assert.Contains(field, declared);
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void No_template_arrives_carrying_an_action(string id)
    {
        // A template that came pre-wired to block addresses would block the wrong ones the first time
        // somebody clicked it without reading. Attaching an action stays a deliberate act.
        var template = RuleTemplates.Find(id)!;

        Assert.NotEqual("", template.Message);
        Assert.DoesNotContain("block", template.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Template_ids_are_unique()
    {
        Assert.Equal(RuleTemplates.All.Count, RuleTemplates.All.Select(t => t.Id).Distinct().Count());
    }

    [Fact]
    public void An_unknown_id_is_not_found_rather_than_throwing()
    {
        Assert.Null(RuleTemplates.Find("no-such-template"));
        Assert.Null(RuleTemplates.Find(null));
    }

    private static string? QueryProblem(string queryJson) =>
        ElasticsearchQueryBuilder.IsValidQuery(queryJson, out var error) ? null : error;
}
