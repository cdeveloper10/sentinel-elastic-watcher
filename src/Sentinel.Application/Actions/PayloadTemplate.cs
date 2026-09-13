using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Application.Connections;

namespace Sentinel.Application.Actions;

/// <summary>
/// The body a rule sends to its web service, written by the rule's author.
///
/// Every gateway wants a different document. One SMS provider takes <c>{"to","text"}</c>, the next takes
/// <c>{"mobile","message","sender"}</c>, and a rule that pages the payments team sends different facts than
/// one that pages the platform team. So the shape belongs to the rule, not to the platform — which is what
/// "each rule decides what reaches its own service" means concretely.
///
/// The author writes the JSON their gateway documents, with placeholders where the alert's values go:
///
/// <code>
/// {
///   "to": "+989121234567",
///   "text": "{{message}}",
///   "meta": { "api": "{{event.ApiName.keyword}}", "hits": "{{evidence.eventCount}}" },
///   "priority": 2
/// }
/// </code>
///
/// <b>The structure is parsed before anything is substituted.</b> That ordering is the security property.
/// Rendering placeholders into JSON <i>text</i> and parsing afterwards is the classic injection: an API
/// name containing a quote breaks the document, and one containing <c>","admin":true</c> adds a field the
/// author never wrote — and that value came out of a log line somebody else was able to influence. Here the
/// author's JSON is parsed first, so the document's shape is fixed before a single value is looked at, and
/// a rendered value can only ever land inside a leaf. <see cref="JsonPayload"/> makes the same argument for
/// the payloads the platform builds itself.
///
/// Literals keep the type the author wrote: <c>"priority": 2</c> is sent as the number 2. A placeholder
/// always renders as a string, even when the value looks numeric — <c>"hits": "{{evidence.eventCount}}"</c>
/// sends <c>"12"</c>, not <c>12</c>. Inferring the type from the rendered text is how an account id of
/// "0071" becomes 71 and a sixteen-digit reference loses its last digits. A gateway that wanted a number
/// and received a string answers with a 400, which is a failure that appears in the execution record and
/// can be fixed; a silently mangled identifier is not.
/// </summary>
public static class PayloadTemplate
{
    /// <summary>Enough for any gateway's document, small enough that a rule cannot carry a payload of data.</summary>
    public const int MaxLength = 8_000;

    /// <summary>Deep enough for real APIs, shallow enough that rendering cannot recurse into a problem.</summary>
    public const int MaxDepth = 8;

    /// <summary>A body with more values than this is carrying something other than an alert.</summary>
    public const int MaxLeaves = 64;

    /// <summary>
    /// Checks a template at save time, so an author is told about a typo now rather than discovering it in
    /// the one message that mattered. Hands back the parsed shape when it is usable.
    /// </summary>
    public static ValidationResult Validate(
        string? template,
        string field,
        IReadOnlyCollection<string> knownPaths,
        out JsonObject? shape)
    {
        shape = null;

        if (string.IsNullOrWhiteSpace(template))
            return ValidationResult.Success;

        if (template.Length > MaxLength)
            return ValidationResult.Fail(new ValidationFailure(
                field, $"Keep the payload under {MaxLength:N0} characters."));

        JsonNode? parsed;

        try
        {
            parsed = Parse(template);
        }
        catch (JsonException ex)
        {
            return ValidationResult.Fail(new ValidationFailure(
                field, $"This is not valid JSON: {ex.Message}"));
        }

        if (parsed is not JsonObject parsedObject)
            return ValidationResult.Fail(new ValidationFailure(
                field, "The payload must be a JSON object — an HTTP body is a document, not a bare value."));

        var leaves = CountLeaves(parsedObject);

        if (leaves > MaxLeaves)
            return ValidationResult.Fail(new ValidationFailure(
                field, $"The payload holds {leaves} values; keep it under {MaxLeaves}."));

        // A placeholder nothing provides renders as a blank. In a message that is the right behaviour; in a
        // gateway payload it is a field going out empty every time the rule fires, which nobody notices
        // until the field was the one that mattered. Save time is the only moment somebody is watching.
        var unknown = new List<string>();

        foreach (var leaf in StringLeaves(parsedObject))
            unknown.AddRange(TemplateRenderer.UnknownPaths(leaf, knownPaths));

        var distinct = unknown.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (distinct.Count > 0)
            return ValidationResult.Fail(new ValidationFailure(
                field,
                $"Nothing provides {string.Join(", ", distinct)}. " +
                "Discover the rule's fields to see what its alerts carry."));

        shape = parsedObject;
        return ValidationResult.Success;
    }

    /// <summary>
    /// Fills a shape in for one alert.
    ///
    /// Structure is copied, never re-parsed: what comes back has exactly the objects, arrays, numbers and
    /// booleans the author wrote, with the string leaves rendered. Nothing a value contains can change that.
    /// </summary>
    public static JsonObject Render(JsonObject shape, ActionContext context, out IReadOnlyList<string> missing)
    {
        var missingPaths = new List<string>();
        var rendered = (JsonObject)RenderNode(shape, context, missingPaths, depth: 0)!;

        missing = missingPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return rendered;
    }

    /// <summary>Parses without validating, for a caller that has already validated. Null when unusable.</summary>
    public static JsonObject? TryParse(string? template)
    {
        if (string.IsNullOrWhiteSpace(template))
            return null;

        try
        {
            return Parse(template) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static JsonNode? Parse(string template) => JsonNode.Parse(
        template,
        documentOptions: new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip,
            MaxDepth = MaxDepth
        });

    private static JsonNode? RenderNode(
        JsonNode? node, ActionContext context, List<string> missing, int depth)
    {
        if (depth > MaxDepth)
            return null;

        switch (node)
        {
            case JsonObject source:
            {
                var target = new JsonObject();

                foreach (var property in source)
                    target[property.Key] = RenderNode(property.Value, context, missing, depth + 1);

                return target;
            }

            case JsonArray source:
            {
                var target = new JsonArray();

                foreach (var item in source)
                    target.Add(RenderNode(item, context, missing, depth + 1));

                return target;
            }

            case JsonValue value when value.TryGetValue<string>(out var text):
            {
                var result = TemplateRenderer.Render(text, context);
                missing.AddRange(result.MissingPaths);

                return JsonValue.Create(result.Text);
            }

            // A number, a boolean or a null the author wrote. Carried through untouched — this is the only
            // way a payload gets a value that is not a string, and it is the author's own literal.
            default:
                return node?.DeepClone();
        }
    }

    private static int CountLeaves(JsonNode? node) => node switch
    {
        JsonObject o => o.Sum(p => CountLeaves(p.Value)),
        JsonArray a => a.Sum(CountLeaves),
        _ => 1
    };

    /// <summary>Every string in the document, which is every place a placeholder can appear.</summary>
    private static IEnumerable<string> StringLeaves(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var text in o.SelectMany(p => StringLeaves(p.Value)))
                    yield return text;
                break;

            case JsonArray a:
                foreach (var text in a.SelectMany(StringLeaves))
                    yield return text;
                break;

            case JsonValue v when v.TryGetValue<string>(out var s):
                yield return s;
                break;
        }
    }
}
