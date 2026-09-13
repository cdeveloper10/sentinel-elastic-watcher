using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Application.Connections;

namespace Sentinel.Application.Rules;

/// <summary>How a clause's values are written into the query.</summary>
public static class ConditionValueKind
{
    public const string Text = "text";
    public const string Number = "number";
    public const string Boolean = "boolean";

    public static bool IsKnown(string? kind) => kind is Text or Number or Boolean;
}

/// <summary>
/// The comparisons a condition row can make.
///
/// Deliberately short. Every one of these maps to a single Elasticsearch clause whose behaviour an author
/// can predict, and anything that does not fit belongs in the raw query box rather than in a vocabulary
/// that grows until it is the query language again with worse names.
/// </summary>
public static class ConditionOperator
{
    public const string Is = "is";
    public const string IsNot = "is_not";
    public const string OneOf = "one_of";
    public const string Contains = "contains";
    public const string StartsWith = "starts_with";
    public const string GreaterThan = "gt";
    public const string AtLeast = "gte";
    public const string LessThan = "lt";
    public const string AtMost = "lte";
    public const string Between = "between";
    public const string Exists = "exists";
    public const string Missing = "missing";

    public static readonly IReadOnlyList<string> All =
    [
        Is, IsNot, OneOf, Contains, StartsWith,
        GreaterThan, AtLeast, LessThan, AtMost, Between,
        Exists, Missing
    ];

    public static bool IsKnown(string? op) => op is not null && All.Contains(op, StringComparer.Ordinal);

    /// <summary>How many values the operator needs. -1 means one or more.</summary>
    public static int Arity(string op) => op switch
    {
        Exists or Missing => 0,
        Between => 2,
        OneOf => -1,
        _ => 1
    };
}

/// <summary>
/// One row of the condition builder: a field, a comparison, and the values it compares against.
///
/// <paramref name="Kind"/> is not decoration. A term query for <c>500</c> against a numeric field and a
/// term query for <c>"500"</c> against a keyword field are different queries, and guessing from the shape
/// of the text gets an account number written as digits wrong. The builder knows the field's mapping and
/// says which it meant.
/// </summary>
public sealed record ConditionClause(
    string Field,
    string Operator,
    IReadOnlyList<string> Values,
    string Kind = ConditionValueKind.Text);

/// <summary>
/// Condition rows in, an Elasticsearch query clause out — and back again.
///
/// There is one compiler and it lives here, on the server, for a reason that has bitten this project
/// before: the console and the engine must never disagree about what a rule asks. The builder sends rows,
/// this turns them into the query that is stored and run, and the rule's saved query is the only thing the
/// engine ever reads.
///
/// <see cref="TryRead"/> is what makes the builder usable on a rule that already exists, including one
/// written by hand before any of this existed. It reads back only the shape this class emits; anything
/// else is left to the raw editor rather than being approximated, because a builder that silently drops
/// half of somebody's query is worse than one that admits it cannot show it.
/// </summary>
public static class ConditionQuery
{
    /// <summary>More rows than this and the query belongs in the raw editor.</summary>
    public const int MaxClauses = 20;

    /// <summary>More values than this in a single <c>one_of</c> and the author wants a different field.</summary>
    public const int MaxValues = 50;

    public static ValidationResult Validate(IReadOnlyList<ConditionClause>? clauses)
    {
        if (clauses is null || clauses.Count == 0)
            return ValidationResult.Success;

        var failures = new List<ValidationFailure>();

        if (clauses.Count > MaxClauses)
            failures.Add(new ValidationFailure(
                "conditions", $"A condition can have at most {MaxClauses} rows."));

        for (var i = 0; i < clauses.Count; i++)
        {
            var clause = clauses[i];
            var where = $"conditions[{i}]";

            if (string.IsNullOrWhiteSpace(clause.Field))
            {
                failures.Add(new ValidationFailure(where, "A condition row needs a field."));
                continue;
            }

            if (!ConditionOperator.IsKnown(clause.Operator))
            {
                failures.Add(new ValidationFailure(
                    where, $"'{clause.Operator}' is not a comparison this builder knows."));
                continue;
            }

            if (!ConditionValueKind.IsKnown(clause.Kind))
            {
                failures.Add(new ValidationFailure(where, $"'{clause.Kind}' is not a value kind."));
                continue;
            }

            var values = clause.Values ?? [];
            var arity = ConditionOperator.Arity(clause.Operator);

            if (arity == 0 && values.Count > 0)
                failures.Add(new ValidationFailure(
                    where, $"'{clause.Operator}' compares against nothing, so it takes no value."));

            if (arity == -1 && values.Count == 0)
                failures.Add(new ValidationFailure(where, "Give at least one value."));

            if (arity == -1 && values.Count > MaxValues)
                failures.Add(new ValidationFailure(where, $"At most {MaxValues} values."));

            if (arity > 0 && values.Count != arity)
                failures.Add(new ValidationFailure(
                    where,
                    arity == 2
                        ? "A range needs both ends: a lowest and a highest value."
                        : $"'{clause.Operator}' takes exactly one value."));

            foreach (var value in values)
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    failures.Add(new ValidationFailure(where, "A value cannot be blank."));
                    break;
                }

                if (clause.Kind == ConditionValueKind.Number && !double.TryParse(value, out _))
                {
                    failures.Add(new ValidationFailure(
                        where, $"'{value}' is not a number, and {clause.Field} is a numeric field."));
                    break;
                }

                if (clause.Kind == ConditionValueKind.Boolean && !bool.TryParse(value, out _))
                {
                    failures.Add(new ValidationFailure(
                        where, $"'{value}' is not true or false."));
                    break;
                }
            }
        }

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    /// <summary>
    /// The query these rows mean. Empty for no rows, which is a legitimate rule: the time window is
    /// always applied on top of whatever this returns, so "no condition" is "everything in the window".
    /// </summary>
    public static string ToQueryJson(IReadOnlyList<ConditionClause>? clauses)
    {
        if (clauses is null || clauses.Count == 0)
            return "";

        var filter = new JsonArray();
        var mustNot = new JsonArray();

        foreach (var clause in clauses)
        {
            if (string.IsNullOrWhiteSpace(clause.Field) || !ConditionOperator.IsKnown(clause.Operator))
                continue;

            var leaf = Leaf(clause);

            if (leaf is null)
                continue;

            // The two negative operators are the same leaf, moved. Writing them as their own clause types
            // would mean two more shapes for TryRead to recognise and nothing gained.
            if (clause.Operator is ConditionOperator.IsNot or ConditionOperator.Missing)
                mustNot.Add(leaf);
            else
                filter.Add(leaf);
        }

        if (filter.Count == 0 && mustNot.Count == 0)
            return "";

        var boolean = new JsonObject();

        if (filter.Count > 0) boolean["filter"] = filter;
        if (mustNot.Count > 0) boolean["must_not"] = mustNot;

        return new JsonObject { ["bool"] = boolean }.ToJsonString();
    }

    private static JsonNode? Leaf(ConditionClause clause)
    {
        var field = clause.Field.Trim();
        var values = clause.Values ?? [];

        JsonNode? Value(int index) =>
            index < values.Count ? Typed(values[index], clause.Kind) : null;

        switch (clause.Operator)
        {
            case ConditionOperator.Exists:
            case ConditionOperator.Missing:
                return new JsonObject { ["exists"] = new JsonObject { ["field"] = field } };

            case ConditionOperator.Is:
            case ConditionOperator.IsNot:
                return Value(0) is { } term
                    ? new JsonObject { ["term"] = new JsonObject { [field] = term } }
                    : null;

            case ConditionOperator.OneOf:
            {
                if (values.Count == 0)
                    return null;

                var list = new JsonArray();
                foreach (var value in values)
                    list.Add(Typed(value, clause.Kind));

                return new JsonObject { ["terms"] = new JsonObject { [field] = list } };
            }

            case ConditionOperator.Contains:
                return Value(0) is { } match
                    ? new JsonObject { ["match"] = new JsonObject { [field] = match } }
                    : null;

            case ConditionOperator.StartsWith:
                return Value(0) is { } prefix
                    ? new JsonObject { ["prefix"] = new JsonObject { [field] = prefix } }
                    : null;

            case ConditionOperator.Between:
            {
                if (values.Count < 2)
                    return null;

                var range = new JsonObject
                {
                    ["gte"] = Typed(values[0], clause.Kind),
                    ["lte"] = Typed(values[1], clause.Kind)
                };

                return new JsonObject { ["range"] = new JsonObject { [field] = range } };
            }

            case ConditionOperator.GreaterThan:
            case ConditionOperator.AtLeast:
            case ConditionOperator.LessThan:
            case ConditionOperator.AtMost:
            {
                if (Value(0) is not { } bound)
                    return null;

                var range = new JsonObject { [clause.Operator] = bound };

                return new JsonObject { ["range"] = new JsonObject { [field] = range } };
            }

            default:
                return null;
        }
    }

    private static JsonNode? Typed(string value, string kind) => kind switch
    {
        ConditionValueKind.Number when long.TryParse(value, out var whole) => JsonValue.Create(whole),
        ConditionValueKind.Number when double.TryParse(value, out var real) => JsonValue.Create(real),
        ConditionValueKind.Boolean when bool.TryParse(value, out var flag) => JsonValue.Create(flag),
        _ => JsonValue.Create(value)
    };

    /// <summary>
    /// Reads a stored query back into rows, when it is a query these rows could have produced.
    ///
    /// False rather than a partial answer. A rule whose query the builder cannot represent opens in the
    /// raw editor with its query intact, which is the honest outcome — the alternative is a form that
    /// looks complete and silently discards the half it did not understand on the next save.
    /// </summary>
    public static bool TryRead(string? queryJson, out IReadOnlyList<ConditionClause> clauses)
    {
        clauses = [];

        if (string.IsNullOrWhiteSpace(queryJson))
            return true; // No condition at all is a condition the builder can show: an empty one.

        JsonNode? root;

        try
        {
            root = JsonNode.Parse(queryJson);
        }
        catch (JsonException)
        {
            return false;
        }

        if (root is not JsonObject obj)
            return false;

        var read = new List<ConditionClause>();

        // A hand-written single clause, so a rule that says {"term":{"x":"y"}} opens in the builder.
        if (!obj.ContainsKey("bool"))
        {
            if (!TryLeaf(obj, negated: false, out var single))
                return false;

            clauses = [single];
            return true;
        }

        if (obj.Count != 1 || obj["bool"] is not JsonObject boolean)
            return false;

        foreach (var property in boolean)
        {
            if (property.Key is not ("filter" or "must_not"))
                return false; // must, should, minimum_should_match — real queries this cannot represent.

            if (property.Value is not JsonArray array)
                return false;

            foreach (var entry in array)
            {
                if (entry is not JsonObject leaf || !TryLeaf(leaf, property.Key == "must_not", out var clause))
                    return false;

                read.Add(clause);
            }
        }

        clauses = read;
        return true;
    }

    private static bool TryLeaf(JsonObject leaf, bool negated, out ConditionClause clause)
    {
        clause = new ConditionClause("", "", []);

        if (leaf.Count != 1)
            return false;

        var (name, body) = (leaf.First().Key, leaf.First().Value);

        switch (name)
        {
            case "exists" when body is JsonObject exists && exists["field"] is JsonValue field:
                clause = new ConditionClause(
                    field.ToString(),
                    negated ? ConditionOperator.Missing : ConditionOperator.Exists,
                    []);
                return true;

            case "term" when Single(body, out var termField, out var termValue):
                clause = new ConditionClause(
                    termField,
                    negated ? ConditionOperator.IsNot : ConditionOperator.Is,
                    [Text(termValue)],
                    KindOf(termValue));
                return true;

            case "match" when !negated && Single(body, out var matchField, out var matchValue):
                clause = new ConditionClause(
                    matchField, ConditionOperator.Contains, [Text(matchValue)]);
                return true;

            case "prefix" when !negated && Single(body, out var prefixField, out var prefixValue):
                clause = new ConditionClause(
                    prefixField, ConditionOperator.StartsWith, [Text(prefixValue)]);
                return true;

            case "terms" when !negated && body is JsonObject terms && terms.Count == 1 &&
                              terms.First().Value is JsonArray values && values.Count > 0:
            {
                var kind = KindOf(values[0]);

                clause = new ConditionClause(
                    terms.First().Key,
                    ConditionOperator.OneOf,
                    values.Select(Text).ToList(),
                    kind);

                return true;
            }

            case "range" when !negated && body is JsonObject ranges && ranges.Count == 1 &&
                              ranges.First().Value is JsonObject bounds:
            {
                var rangeField = ranges.First().Key;

                if (bounds.Count == 2 && bounds["gte"] is { } low && bounds["lte"] is { } high)
                {
                    clause = new ConditionClause(
                        rangeField, ConditionOperator.Between, [Text(low), Text(high)], KindOf(low));

                    return true;
                }

                if (bounds.Count == 1)
                {
                    var (op, bound) = (bounds.First().Key, bounds.First().Value);

                    if (op is ConditionOperator.GreaterThan or ConditionOperator.AtLeast
                           or ConditionOperator.LessThan or ConditionOperator.AtMost)
                    {
                        clause = new ConditionClause(rangeField, op, [Text(bound)], KindOf(bound));
                        return true;
                    }
                }

                return false;
            }

            default:
                return false;
        }

        static bool Single(JsonNode? body, out string field, out JsonNode? value)
        {
            field = "";
            value = null;

            if (body is not JsonObject obj || obj.Count != 1)
                return false;

            (field, value) = (obj.First().Key, obj.First().Value);
            return value is JsonValue;
        }
    }

    private static string Text(JsonNode? node) => node?.ToString() ?? "";

    private static string KindOf(JsonNode? node) => node is JsonValue value
        ? value.GetValueKind() switch
        {
            JsonValueKind.Number => ConditionValueKind.Number,
            JsonValueKind.True or JsonValueKind.False => ConditionValueKind.Boolean,
            _ => ConditionValueKind.Text
        }
        : ConditionValueKind.Text;
}
