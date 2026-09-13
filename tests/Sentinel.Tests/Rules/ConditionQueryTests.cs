using System.Text.Json;
using Sentinel.Application.Rules;

namespace Sentinel.Tests.Rules;

/// <summary>
/// The condition builder's compiler.
///
/// This is the one piece of the builder that has to be exactly right, because it decides what the engine
/// runs. A form that renders a row slightly wrong is annoying; a compiler that emits <c>"500"</c> where it
/// meant <c>500</c> produces a rule that matches nothing and says nothing about why, which is the failure
/// this whole feature exists to remove.
///
/// The round trip is tested as hard as the compile. Reopening a saved rule has to show the same rows it
/// was built from, or the builder quietly becomes a one-way door.
/// </summary>
public class ConditionQueryTests
{
    private static string Compile(params ConditionClause[] clauses) => ConditionQuery.ToQueryJson(clauses);

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void No_rows_mean_no_query()
    {
        // Not "{}" and not a match_all. The engine always adds the time bound, so an empty string is
        // exactly "everything in the window" — and it is what the rule already stores for that case.
        Assert.Equal("", ConditionQuery.ToQueryJson([]));
        Assert.Equal("", ConditionQuery.ToQueryJson(null));
    }

    [Fact]
    public void A_number_is_written_as_a_number()
    {
        // The failure this exists to prevent. A term query for "500" against an integer field is not the
        // same query as one for 500, and the difference shows up as a rule that never fires.
        var json = Parse(Compile(new ConditionClause(
            "http.response.status_code", ConditionOperator.Is, ["500"], ConditionValueKind.Number)));

        var term = json.GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("term").GetProperty("http.response.status_code");

        Assert.Equal(JsonValueKind.Number, term.ValueKind);
        Assert.Equal(500, term.GetInt32());
    }

    [Fact]
    public void Digits_in_a_text_field_stay_text()
    {
        // The other half of the same decision, and why the kind is carried rather than inferred: an
        // account number written in digits is a keyword, and quoting it is correct.
        var json = Parse(Compile(new ConditionClause("client.id", ConditionOperator.Is, ["4400291"])));

        var term = json.GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("term").GetProperty("client.id");

        Assert.Equal(JsonValueKind.String, term.ValueKind);
    }

    [Fact]
    public void Negative_rows_go_to_must_not()
    {
        var json = Parse(Compile(
            new ConditionClause("event.outcome", ConditionOperator.Is, ["failure"]),
            new ConditionClause("user.name", ConditionOperator.IsNot, ["healthcheck"]),
            new ConditionClause("error.code", ConditionOperator.Missing, [])));

        var boolean = json.GetProperty("bool");

        Assert.Equal(1, boolean.GetProperty("filter").GetArrayLength());
        Assert.Equal(2, boolean.GetProperty("must_not").GetArrayLength());
    }

    [Theory]
    [InlineData(ConditionOperator.GreaterThan, "gt")]
    [InlineData(ConditionOperator.AtLeast, "gte")]
    [InlineData(ConditionOperator.LessThan, "lt")]
    [InlineData(ConditionOperator.AtMost, "lte")]
    public void A_bound_becomes_a_range(string op, string expected)
    {
        var json = Parse(Compile(new ConditionClause(
            "backend_latency", op, ["3000"], ConditionValueKind.Number)));

        var range = json.GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("range").GetProperty("backend_latency");

        Assert.Equal(3000, range.GetProperty(expected).GetInt32());
    }

    [Fact]
    public void Between_becomes_one_range_with_both_ends()
    {
        var json = Parse(Compile(new ConditionClause(
            "http.response.status_code", ConditionOperator.Between, ["400", "499"], ConditionValueKind.Number)));

        var range = json.GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("range").GetProperty("http.response.status_code");

        Assert.Equal(400, range.GetProperty("gte").GetInt32());
        Assert.Equal(499, range.GetProperty("lte").GetInt32());
    }

    [Fact]
    public void One_of_becomes_a_terms_clause()
    {
        var json = Parse(Compile(new ConditionClause(
            "http.response.status_code", ConditionOperator.OneOf, ["502", "503", "504"], ConditionValueKind.Number)));

        var terms = json.GetProperty("bool").GetProperty("filter")[0]
            .GetProperty("terms").GetProperty("http.response.status_code");

        Assert.Equal(3, terms.GetArrayLength());
        Assert.Equal(502, terms[0].GetInt32());
    }

    // -- reading one back ----------------------------------------------------

    [Fact]
    public void Everything_it_writes_it_can_read_back()
    {
        // The property that makes the builder safe to open on a saved rule. Every operator, in one query,
        // through the compiler and back.
        ConditionClause[] original =
        [
            new("event.outcome", ConditionOperator.Is, ["failure"]),
            new("user.name", ConditionOperator.IsNot, ["healthcheck"]),
            new("status", ConditionOperator.OneOf, ["502", "503"], ConditionValueKind.Number),
            new("message", ConditionOperator.Contains, ["timeout"]),
            new("url.path", ConditionOperator.StartsWith, ["/api/"]),
            new("latency", ConditionOperator.GreaterThan, ["100"], ConditionValueKind.Number),
            new("size", ConditionOperator.Between, ["1", "9"], ConditionValueKind.Number),
            new("trace.id", ConditionOperator.Exists, []),
            new("error.code", ConditionOperator.Missing, []),
            new("enabled", ConditionOperator.Is, ["true"], ConditionValueKind.Boolean)
        ];

        Assert.True(ConditionQuery.TryRead(ConditionQuery.ToQueryJson(original), out var read));

        // Order within a bool changes — filters are listed before must_nots — so they are compared as sets
        // of rows rather than as a sequence. What matters is that no row was lost or altered.
        Assert.Equal(original.Length, read.Count);

        foreach (var clause in original)
        {
            Assert.Contains(read, r =>
                r.Field == clause.Field &&
                r.Operator == clause.Operator &&
                r.Kind == clause.Kind &&
                r.Values.SequenceEqual(clause.Values));
        }
    }

    [Fact]
    public void A_hand_written_single_clause_opens_in_the_builder()
    {
        // Every rule written before the builder existed looks like this. They should not all be stranded
        // in the raw editor for ever.
        Assert.True(ConditionQuery.TryRead("""{"term":{"event.type":"authentication_failed"}}""", out var read));

        var clause = Assert.Single(read);

        Assert.Equal("event.type", clause.Field);
        Assert.Equal(ConditionOperator.Is, clause.Operator);
        Assert.Equal("authentication_failed", clause.Values[0]);
    }

    [Fact]
    public void An_empty_query_reads_as_no_rows()
    {
        Assert.True(ConditionQuery.TryRead("", out var read));
        Assert.Empty(read);
    }

    [Theory]
    // A real query the rows cannot express. Answering false is the correct answer, not a limitation to
    // work around: the console keeps it in the raw editor with the query intact.
    [InlineData("""{"bool":{"should":[{"term":{"a":"b"}}],"minimum_should_match":1}}""")]
    [InlineData("""{"bool":{"must":[{"term":{"a":"b"}}]}}""")]
    [InlineData("""{"script":{"script":"doc['a'].value > 1"}}""")]
    [InlineData("""{"bool":{"filter":[{"range":{"a":{"gt":1,"lt":9,"boost":2}}}]}}""")]
    [InlineData("not json at all")]
    public void A_query_the_rows_cannot_express_is_refused_rather_than_approximated(string queryJson)
    {
        Assert.False(ConditionQuery.TryRead(queryJson, out var read));
        Assert.Empty(read);
    }

    // -- validation ----------------------------------------------------------

    [Fact]
    public void A_number_field_refuses_a_value_that_is_not_a_number()
    {
        var result = ConditionQuery.Validate(
            [new ConditionClause("latency", ConditionOperator.GreaterThan, ["quick"], ConditionValueKind.Number)]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("not a number"));
    }

    [Fact]
    public void A_range_needs_both_ends()
    {
        var result = ConditionQuery.Validate(
            [new ConditionClause("size", ConditionOperator.Between, ["1"], ConditionValueKind.Number)]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("both ends"));
    }

    [Fact]
    public void Exists_takes_no_value_and_a_blank_value_is_refused()
    {
        Assert.False(ConditionQuery.Validate(
            [new ConditionClause("trace.id", ConditionOperator.Exists, ["something"])]).IsValid);

        Assert.False(ConditionQuery.Validate(
            [new ConditionClause("user.name", ConditionOperator.Is, ["  "])]).IsValid);
    }

    [Fact]
    public void A_row_without_a_field_is_refused()
    {
        var result = ConditionQuery.Validate([new ConditionClause("", ConditionOperator.Is, ["x"])]);

        Assert.False(result.IsValid);
        Assert.Contains(result.Failures, f => f.Message.Contains("needs a field"));
    }
}
