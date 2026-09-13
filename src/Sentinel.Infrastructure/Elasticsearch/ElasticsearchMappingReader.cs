using System.Text.Json;
using Sentinel.Application.EventSources;

namespace Sentinel.Infrastructure.Elasticsearch;

/// <summary>
/// Turns an Elasticsearch mapping response into the flat list of field paths a rule author picks from.
///
/// The mapping arrives as a tree, one subtree per index, with objects nested inside objects and
/// multi-fields hanging off leaves — <c>message</c> as analysed text with a <c>message.keyword</c>
/// sibling underneath it. A rule refers to <c>source.ip</c>, not to that shape, so somebody has to flatten
/// it, and the flattening is where the useful judgement lives: which of these can actually carry a
/// group-by.
///
/// That last question is why this is worth its own class. Grouping by an analysed <c>text</c> field does
/// not fail loudly — Elasticsearch either refuses because fielddata is off, or groups by individual token,
/// which quietly produces nonsense. The rule builder can only avoid offering those if something has
/// already worked out which fields are aggregatable.
/// </summary>
public static class ElasticsearchMappingReader
{
    /// <summary>
    /// Field types that can be grouped and counted on. Everything analysed is excluded: <c>text</c> is
    /// broken into tokens, and an aggregation over it counts words rather than values.
    /// </summary>
    private static readonly HashSet<string> AggregatableTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "keyword", "constant_keyword", "wildcard", "ip", "boolean", "date", "date_nanos",
        "byte", "short", "integer", "long", "unsigned_long", "float", "half_float", "scaled_float", "double",
        "version"
    };

    /// <summary>Containers rather than values: they hold fields, they are not one.</summary>
    private static readonly HashSet<string> StructuralTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "object", "nested"
    };

    public static FieldCatalog Read(string mappingJson)
    {
        using var document = JsonDocument.Parse(mappingJson);

        var fields = new Dictionary<string, FieldDescriptor>(StringComparer.Ordinal);
        var indices = new List<string>();

        foreach (var index in document.RootElement.EnumerateObject())
        {
            indices.Add(index.Name);

            if (!index.Value.TryGetProperty("mappings", out var mappings))
                continue;

            if (mappings.TryGetProperty("properties", out var properties))
                Walk(properties, prefix: "", fields);
        }

        // Ordered so the same cluster always produces the same list — a field picker that reshuffles
        // between page loads is its own kind of bug.
        var ordered = fields.Values.OrderBy(f => f.Path, StringComparer.Ordinal).ToList();

        return new FieldCatalog(ordered, indices);
    }

    private static void Walk(JsonElement properties, string prefix, Dictionary<string, FieldDescriptor> fields)
    {
        foreach (var property in properties.EnumerateObject())
        {
            var path = prefix.Length == 0 ? property.Name : $"{prefix}.{property.Name}";
            var definition = property.Value;

            var type = definition.TryGetProperty("type", out var typeElement)
                ? typeElement.GetString() ?? "object"
                : "object";

            var hasChildren = definition.TryGetProperty("properties", out var children);

            // An entry with children is a container. Elasticsearch omits "type" for plain objects, so the
            // presence of properties is the reliable signal rather than the declared type.
            if (hasChildren)
            {
                Walk(children, path, fields);

                // A nested field is addressable in its own right; a plain object is not a value.
                if (type.Equals("nested", StringComparison.OrdinalIgnoreCase))
                    Add(fields, new FieldDescriptor(path, "nested", Aggregatable: false, Searchable: false));

                continue;
            }

            if (StructuralTypes.Contains(type))
                continue;

            Add(fields, new FieldDescriptor(
                path,
                type,
                Aggregatable: AggregatableTypes.Contains(type),
                Searchable: IsSearchable(definition, type)));

            // Multi-fields: message.keyword under an analysed message. These are usually the only
            // groupable form of a text field, so losing them would leave the rule builder with nothing to
            // offer for the field the author actually wants.
            if (definition.TryGetProperty("fields", out var multiFields))
            {
                foreach (var sub in multiFields.EnumerateObject())
                {
                    var subType = sub.Value.TryGetProperty("type", out var subTypeElement)
                        ? subTypeElement.GetString() ?? "keyword"
                        : "keyword";

                    Add(fields, new FieldDescriptor(
                        $"{path}.{sub.Name}",
                        subType,
                        Aggregatable: AggregatableTypes.Contains(subType),
                        Searchable: IsSearchable(sub.Value, subType)));
                }
            }
        }
    }

    private static bool IsSearchable(JsonElement definition, string type)
    {
        // Explicitly un-indexed fields are stored but cannot be queried, so offering them in a rule would
        // produce a query that silently matches nothing.
        if (definition.TryGetProperty("index", out var indexed) &&
            indexed.ValueKind is JsonValueKind.False)
            return false;

        return !StructuralTypes.Contains(type);
    }

    /// <summary>
    /// Indices behind one pattern rarely agree. Where two disagree on a field's type the first one wins
    /// and the field stays listed: dropping it would hide a field the author can see in their data, and
    /// guessing a merged type would be worse than either answer.
    /// </summary>
    private static void Add(Dictionary<string, FieldDescriptor> fields, FieldDescriptor field) =>
        fields.TryAdd(field.Path, field);
}
