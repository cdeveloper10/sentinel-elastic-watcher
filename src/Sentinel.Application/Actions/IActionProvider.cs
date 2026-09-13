using Sentinel.Application.Connections;
using Sentinel.Domain.Connections;

namespace Sentinel.Application.Actions;

public sealed record ActionOutcome(
    bool Succeeded,
    string? ErrorCode,
    string? ErrorMessage,
    int? ResponseStatusCode,
    string? RequestSummary,
    bool Retryable)
{
    public static ActionOutcome Success(string? summary = null, int? status = null) =>
        new(true, null, null, status, summary, false);

    /// <summary>A failure worth another attempt: a timeout, a 5xx, a rate limit.</summary>
    public static ActionOutcome Transient(string code, string message, int? status = null, string? summary = null) =>
        new(false, code, message, status, summary, true);

    /// <summary>A failure that will fail identically forever: a malformed request, a rejected credential.</summary>
    public static ActionOutcome Permanent(string code, string message, int? status = null, string? summary = null) =>
        new(false, code, message, status, summary, false);
}

/// <summary>One field the action's form should show, described by the provider rather than the frontend.</summary>
public sealed record ActionSettingSchema(
    string Key,
    string Label,
    string Type,
    bool Required,
    string? Default = null,
    string? Help = null,
    IReadOnlyList<string>? Options = null);

/// <summary>
/// What the UI needs to render an action's configuration without knowing what the action is.
///
/// The brief asks for the action form to be driven by provider metadata, and this is why: a new provider
/// otherwise means a frontend release, and the frontend gradually accumulates knowledge of every action
/// the backend can perform — the coupling the registry exists to prevent, reintroduced one form at a time.
/// </summary>
public sealed record ActionDescriptor(
    string Type,
    string DisplayName,
    string Description,

    /// <summary>The connection type this action needs, so the UI offers only connections it can use.</summary>
    string RequiredConnectionType,

    /// <summary>
    /// Whether running this twice on one subject is materially different from running it once. Blocking an
    /// address is not; sending a message is.
    /// </summary>
    bool IsIdempotentByNature,

    /// <summary>Whether this action changes the state of a live system, which is what the safety rails guard.</summary>
    bool IsDisruptive,

    IReadOnlyList<ActionSettingSchema> Settings,

    /// <summary>
    /// The endpoint this action calls when its connection does not say otherwise.
    ///
    /// Published so the connection form can offer one path field per action that could run through that
    /// connection, pre-filled with the conventional value — without the console needing to know what any
    /// particular action is. The path belongs to the connection because it describes the service, not the
    /// rule: every rule pointing at one gateway calls the same endpoint on it.
    /// </summary>
    string DefaultPath = "");

/// <summary>
/// How one kind of response is carried out.
///
/// The provider is the last layer that knows anything specific. Above it, the dispatcher knows that an
/// alert has actions; the registry knows which provider serves a name; and the detection engine knows
/// none of it — which is what lets an action be added without the engine changing, and why there is no
/// switch on action type anywhere above this interface.
///
/// A provider does not retry, does not decide about idempotency and does not write to the execution log.
/// It performs one attempt and reports what happened; everything around that is the dispatcher's, so that
/// every action gets the same treatment rather than each one inventing its own.
/// </summary>
public interface IActionProvider
{
    /// <summary>Registry key, matching the <c>type</c> in a rule's action binding.</summary>
    string Type { get; }

    ActionDescriptor Describe();

    /// <summary>Whether a rule's settings for this action make sense, checked at save time.</summary>
    /// <param name="availablePaths">
    /// The placeholders this rule's alerts will carry, from <c>RuleVocabulary</c>. Passed in rather than
    /// discovered, because what an alert carries depends on the rule's strategy and grouping — and it is
    /// what lets a provider reject a message or a payload that refers to a field the rule never produces,
    /// at save time, while an author is still watching.
    /// </param>
    ValidationResult Validate(
        IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths);

    /// <summary>
    /// Performs one attempt.
    /// </summary>
    /// <param name="idempotencyKey">
    /// Passed to the external system where it accepts one, so that a retry the platform makes and a retry
    /// the network makes collapse into the same operation on the other side.
    /// </param>
    Task<ActionOutcome> ExecuteAsync(
        ActionContext context,
        Connection connection,
        string idempotencyKey,
        CancellationToken ct = default);
}

/// <summary>
/// Providers by name.
///
/// This is the piece the brief cares most about, and the reason is worth stating plainly: without it,
/// "which action is this" becomes a conditional, and that conditional appears in the dispatcher, then in
/// the validator, then in the UI, and adding an action means finding all of them. With it, adding an
/// action means writing a class and registering it.
/// </summary>
public interface IActionRegistry
{
    IActionProvider Resolve(string type);

    bool TryResolve(string? type, out IActionProvider provider);

    IReadOnlyCollection<ActionDescriptor> Describe();
}

public sealed class ActionRegistry : IActionRegistry
{
    private readonly IReadOnlyDictionary<string, IActionProvider> _providers;

    public ActionRegistry(IEnumerable<IActionProvider> providers)
    {
        _providers = providers.ToDictionary(p => p.Type, StringComparer.OrdinalIgnoreCase);

        if (_providers.Count == 0)
            throw new InvalidOperationException("No action providers were registered.");
    }

    public IActionProvider Resolve(string type) =>
        TryResolve(type, out var provider)
            ? provider
            : throw new UnknownActionException(type, _providers.Keys.ToList());

    public bool TryResolve(string? type, out IActionProvider provider)
    {
        if (type is not null && _providers.TryGetValue(type, out var found))
        {
            provider = found;
            return true;
        }

        provider = null!;
        return false;
    }

    public IReadOnlyCollection<ActionDescriptor> Describe() =>
        _providers.Values.Select(p => p.Describe()).OrderBy(d => d.DisplayName, StringComparer.Ordinal).ToList();
}

public sealed class UnknownActionException(string type, IReadOnlyCollection<string> known)
    : Exception($"No action provider is registered for '{type}'. Registered: {string.Join(", ", known)}.")
{
    public string RequestedType { get; } = type;
}
