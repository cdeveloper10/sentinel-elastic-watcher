using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Actions;
using Sentinel.Application.Connections;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Http;

namespace Sentinel.Infrastructure.Actions;

/// <summary>
/// The HTTP mechanics the response actions share.
///
/// Kept in one place so that every provider gets the same handling of a 429, the same idempotency header
/// and the same rule about what may appear in an error message — three things that go wrong quietly and
/// separately when each provider writes its own.
/// </summary>
public abstract class HttpActionProvider(
    ConnectionHttpClients clients,
    IConnectionSecrets secrets,
    ILogger logger) : IActionProvider
{
    public const string HttpClientName = "action";

    /// <summary>Header the target system reads to collapse a repeat of the same operation.</summary>
    public const string IdempotencyHeader = "Idempotency-Key";

    public abstract string Type { get; }

    public abstract ActionDescriptor Describe();

    public abstract ValidationResult Validate(
        IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths);

    public abstract Task<ActionOutcome> ExecuteAsync(
        ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default);

    protected async Task<ActionOutcome> PostAsync(
        Connection connection,
        string path,
        JsonObject payload,
        string idempotencyKey,
        IReadOnlyCollection<string> redactInSummary,
        CancellationToken ct)
    {
        var summary = JsonPayload.Summarize(payload, redactInSummary);

        using var request = new HttpRequestMessage(
            HttpMethod.Post, $"{connection.Endpoint.TrimEnd('/')}{path}")
        {
            Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json")
        };

        request.Headers.TryAddWithoutValidation(IdempotencyHeader, idempotencyKey);
        Authenticate(connection, request);

        try
        {
            // Per connection: a gateway behind a private CA verifies differently from one behind a
            // public certificate, and that is a property of the service being called.
            using var client = clients.For(connection, HttpClientName, maxConnectionsPerServer: 32);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(connection.TimeoutSeconds, 1, 300)));

            using var response = await client.SendAsync(request, timeout.Token);
            var status = (int)response.StatusCode;

            if (response.IsSuccessStatusCode)
                return ActionOutcome.Success(summary, status);

            // 429 and 5xx are the target system asking to be tried again; a 4xx is it saying the request
            // is wrong, which no number of retries will change.
            var body = await SafeReadAsync(response, timeout.Token);

            return status is 429 or >= 500
                ? ActionOutcome.Transient(StatusCode(status), body, status, summary)
                : ActionOutcome.Permanent(StatusCode(status), body, status, summary);
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return ActionOutcome.Transient("TIMEOUT",
                $"The system did not answer within {connection.TimeoutSeconds} seconds.", null, summary);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "{Action} could not reach connection {Connection}", Type, connection.Name);
            return ActionOutcome.Transient("UNREACHABLE", "The system could not be reached.", null, summary);
        }
    }

    /// <summary>
    /// A bounded, sanitised slice of the error body. The whole body would put whatever the target system
    /// chose to echo — headers, tokens, internal addresses — into an execution record that is shown in the
    /// UI and kept for audit.
    /// </summary>
    private static async Task<string> SafeReadAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            var trimmed = body.Trim();

            return trimmed.Length switch
            {
                0 => $"The system answered {(int)response.StatusCode} with no detail.",
                > 300 => trimmed[..300] + "…",
                _ => trimmed
            };
        }
        catch
        {
            return $"The system answered {(int)response.StatusCode}.";
        }
    }

    private static string StatusCode(int status) => status switch
    {
        401 or 403 => "UNAUTHORIZED",
        404 => "NOT_FOUND",
        409 => "CONFLICT",
        422 => "REJECTED",
        429 => "RATE_LIMITED",
        >= 500 => "UPSTREAM_ERROR",
        _ => "HTTP_" + status
    };

    private void Authenticate(Connection connection, HttpRequestMessage request)
    {
        var credentials = secrets.For(connection);

        switch (connection.AuthenticationMode?.ToLowerInvariant())
        {
            case AuthenticationMode.ApiKey when credentials.TryGetValue("apiKey", out var apiKey):
                request.Headers.TryAddWithoutValidation("X-API-KEY", apiKey);
                break;

            case AuthenticationMode.Bearer when credentials.TryGetValue("token", out var token):
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                break;

            case AuthenticationMode.Basic
                when credentials.TryGetValue("username", out var user) &&
                     credentials.TryGetValue("password", out var password):
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}")));
                break;
        }
    }

    /// <summary>Shared settings for the two blocking actions.</summary>
    protected static ValidationResult ValidateDuration(IReadOnlyDictionary<string, string> settings)
    {
        if (!settings.TryGetValue("durationSeconds", out var raw) || raw.Length == 0)
            return ValidationResult.Success;

        if (!int.TryParse(raw, out var seconds))
            return ValidationResult.Fail(new ValidationFailure("durationSeconds", "The duration must be a number of seconds."));

        return seconds switch
        {
            < 60 => ValidationResult.Fail(new ValidationFailure(
                "durationSeconds", "A block shorter than a minute expires before anyone can look at it.")),

            // Not a policy about attackers — a policy about mistakes. An indefinite automated block is one
            // nobody remembers to lift.
            > 86_400 * 7 => ValidationResult.Fail(new ValidationFailure(
                "durationSeconds", "Automated blocks are capped at seven days. Longer ones should be decided by a person.")),

            _ => ValidationResult.Success
        };
    }

    /// <summary>
    /// Whether the field an action reads its target from is one the rule's alerts actually carry.
    ///
    /// Without this the mistake is invisible until the rule fires: a Block IP action set to
    /// <c>event.source.ip</c> on a rule grouped by <c>SourceIP.keyword</c> resolves to nothing, and the
    /// action reports NO_TARGET on every alert forever. That is a rule that looks armed, raises alerts, and
    /// silently never blocks anything — the failure this platform can least afford to make quiet.
    /// </summary>
    protected static ValidationResult ValidateTargetField(
        IReadOnlyDictionary<string, string> settings,
        string defaultField,
        IReadOnlyCollection<string> availablePaths)
    {
        var field = settings.TryGetValue("targetField", out var configured) && configured.Length > 0
            ? configured
            : defaultField;

        // Checked as a placeholder because that is what it is — the same vocabulary, without the braces.
        if (TemplateRenderer.UnknownPaths($"{{{{{field}}}}}", availablePaths).Count == 0)
            return ValidationResult.Success;

        return ValidationResult.Fail(new ValidationFailure(
            "targetField",
            $"This rule's alerts carry no '{field}'. Available: {string.Join(", ", availablePaths)}."));
    }

    /// <summary>Every failure from several checks, so an author fixes one form rather than three saves.</summary>
    protected static ValidationResult Combine(params ValidationResult[] results)
    {
        var failures = results.SelectMany(r => r.Failures).ToList();

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }
}

/// <summary>Blocks an address at the gateway or firewall the connection points at.</summary>
public sealed class BlockIpActionProvider(
    ConnectionHttpClients clients,
    IConnectionSecrets secrets,
    ILogger<BlockIpActionProvider> logger)
    : HttpActionProvider(clients, secrets, logger)
{
    public override string Type => "block_ip";

    private const string DefaultTargetField = "event.source.ip";

    /// <summary>Where a security API conventionally blocks an address. A connection may say otherwise.</summary>
    private const string DefaultEndpointPath = "/security/block/ip";

    public override ActionDescriptor Describe() => new(
        Type,
        "Block IP address",
        "Asks the security API to stop traffic from the address the alert identified.",
        ConnectionType.SecurityApi,
        IsIdempotentByNature: true,
        IsDisruptive: true,
        [
            new ActionSettingSchema("targetField", "Address field", "field", Required: true,
                Default: DefaultTargetField,
                Help: "Which field of the alert holds the address to block."),

            new ActionSettingSchema("durationSeconds", "Block for", "duration", Required: false,
                Default: "1800",
                Help: "How long the block lasts before the security API lifts it.")
        ],
        DefaultPath: DefaultEndpointPath);

    public override ValidationResult Validate(
        IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
        Combine(
            ValidateDuration(settings),
            ValidateTargetField(settings, DefaultTargetField, availablePaths));

    public override Task<ActionOutcome> ExecuteAsync(
        ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
    {
        var field = context.Settings.TryGetValue("targetField", out var configured) && configured.Length > 0
            ? configured
            : DefaultTargetField;

        if (!context.TryResolve(field, out var address) || address.Length == 0)
            return Task.FromResult(ActionOutcome.Permanent("NO_TARGET",
                $"The alert has no '{field}', so there is no address to block."));

        // Assembled as an object. Substituting these values into a JSON string would let an address
        // carrying a quote break the document or add a field — and the value came out of a log line
        // somebody else wrote.
        var payload = new JsonObject
        {
            ["ip"] = address,
            ["duration"] = context.Settings.TryGetValue("durationSeconds", out var d) && int.TryParse(d, out var s)
                ? s
                : 1800,
            ["reason"] = context.RuleName,
            ["alertId"] = context.AlertId,
            ["severity"] = context.Severity
        };

        var path = ConnectionPaths.For(connection, Type, DefaultEndpointPath);

        return PostAsync(connection, path, payload, idempotencyKey, [], ct);
    }
}

/// <summary>Suspends an account through the security API the connection points at.</summary>
public sealed class BlockUserActionProvider(
    ConnectionHttpClients clients,
    IConnectionSecrets secrets,
    ILogger<BlockUserActionProvider> logger)
    : HttpActionProvider(clients, secrets, logger)
{
    public override string Type => "block_user";

    private const string DefaultTargetField = "event.user.id";

    /// <summary>Where a security API conventionally suspends an account. A connection may say otherwise.</summary>
    private const string DefaultEndpointPath = "/security/block/user";

    public override ActionDescriptor Describe() => new(
        Type,
        "Block user account",
        "Asks the security API to suspend the account the alert identified.",
        ConnectionType.SecurityApi,
        IsIdempotentByNature: true,
        IsDisruptive: true,
        [
            new ActionSettingSchema("targetField", "Account field", "field", Required: true,
                Default: DefaultTargetField,
                Help: "Which field of the alert holds the account to suspend."),

            new ActionSettingSchema("durationSeconds", "Suspend for", "duration", Required: false,
                Default: "1800")
        ],
        DefaultPath: DefaultEndpointPath);

    public override ValidationResult Validate(
        IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths) =>
        Combine(
            ValidateDuration(settings),
            ValidateTargetField(settings, DefaultTargetField, availablePaths));

    public override Task<ActionOutcome> ExecuteAsync(
        ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
    {
        var field = context.Settings.TryGetValue("targetField", out var configured) && configured.Length > 0
            ? configured
            : DefaultTargetField;

        if (!context.TryResolve(field, out var user) || user.Length == 0)
            return Task.FromResult(ActionOutcome.Permanent("NO_TARGET",
                $"The alert has no '{field}', so there is no account to suspend."));

        var payload = new JsonObject
        {
            ["userId"] = user,
            ["duration"] = context.Settings.TryGetValue("durationSeconds", out var d) && int.TryParse(d, out var s)
                ? s
                : 1800,
            ["reason"] = context.RuleName,
            ["alertId"] = context.AlertId,
            ["severity"] = context.Severity
        };

        var path = ConnectionPaths.For(connection, Type, DefaultEndpointPath);

        return PostAsync(connection, path, payload, idempotencyKey, [], ct);
    }
}

/// <summary>
/// Calls the SMS gateway the connection points at.
///
/// Two settings decide what the gateway receives, and the split between them is the design: <c>template</c>
/// is the sentence a person reads, <c>payload</c> is the document the gateway parses. Most rules need only
/// the first and send the platform's default body. A rule whose gateway wants its own field names, or that
/// should carry facts the default body has no place for, writes the second — and then it, not the platform,
/// decides what leaves the building.
///
/// That is why the payload is per rule rather than per connection: two rules pointed at one gateway
/// routinely need to send different things, and a rule that watches payments has different facts worth
/// sending than one that watches a login page.
/// </summary>
public sealed class SmsActionProvider(
    ConnectionHttpClients clients,
    IConnectionSecrets secrets,
    ILogger<SmsActionProvider> logger)
    : HttpActionProvider(clients, secrets, logger)
{
    public override string Type => "sms";

    /// <summary>The name the rendered message is published under, for use inside a payload.</summary>
    public const string MessagePath = "message";

    private const string DefaultTemplate =
        "Security alert\nRule: {{rule.name}}\nSeverity: {{alert.severity}}\n" +
        "Subject: {{subject}}\nAlert: {{alert.id}}";

    /// <summary>Where an SMS gateway conventionally accepts a message. A connection may say otherwise.</summary>
    private const string DefaultEndpointPath = "/sms/send";

    /// <summary>
    /// Field names kept out of the stored request summary.
    ///
    /// An execution record is read by more people than are entitled to the security team's phone numbers,
    /// and once a payload is the author's to shape, the platform can no longer know which field holds one.
    /// So the common names are redacted by default and the author can name more. Over-redacting a summary
    /// costs nothing; under-redacting it writes phone numbers into a log that is shown in the console.
    /// </summary>
    private static readonly string[] AlwaysRedact = ["recipients", "to", "mobile", "msisdn", "phone", "phoneNumber"];

    public override ActionDescriptor Describe() => new(
        Type,
        "Send SMS",
        "Calls the gateway the connection points at, with a body this rule defines.",
        ConnectionType.Sms,

        // Sending the same message twice is not the same as sending it once, which is exactly why the
        // dispatcher claims an idempotency key before the first attempt rather than trusting the gateway.
        IsIdempotentByNature: false,

        // It disturbs a person, not a system. Rate caps that would hold back the message telling somebody
        // the platform is misbehaving would be the wrong way round.
        IsDisruptive: false,
        [
            new ActionSettingSchema("template", "Message", "template", Required: false,
                Default: DefaultTemplate,
                Help: "The sentence a person reads. Available as {{message}} inside the payload below."),

            new ActionSettingSchema("payload", "Request body", "json", Required: false,
                Help: "The JSON your gateway expects, with placeholders for this alert's values. " +
                      "Leave it empty to send the default body."),

            new ActionSettingSchema("recipients", "Recipients", "string", Required: false,
                Help: "Comma-separated. Leave empty to use the connection's own list."),

            new ActionSettingSchema("redact", "Hide from the log", "string", Required: false,
                Help: "Extra payload field names to replace with *** in the execution record.")
        ],
        DefaultPath: DefaultEndpointPath);

    public override ValidationResult Validate(
        IReadOnlyDictionary<string, string> settings, IReadOnlyCollection<string> availablePaths)
    {
        var failures = new List<ValidationFailure>();

        // The message can name anything the alert carries, and also itself is not one of those things.
        var messagePaths = availablePaths.ToList();

        if (settings.TryGetValue("template", out var template) && template.Length > 0)
        {
            if (template.Length > TemplateRenderer.MaxLength)
                failures.Add(new ValidationFailure(
                    "template", $"Keep the message under {TemplateRenderer.MaxLength} characters."));

            failures.AddRange(TemplateRenderer.UnknownPaths(template, messagePaths)
                .Select(path => new ValidationFailure(
                    "template", $"Nothing provides {path}. Available: {string.Join(", ", messagePaths)}.")));
        }

        settings.TryGetValue("payload", out var payload);

        failures.AddRange(PayloadTemplate
            .Validate(payload, "payload", [.. messagePaths, MessagePath], out _)
            .Failures);

        return failures.Count == 0 ? ValidationResult.Success : new ValidationResult(failures);
    }

    public override Task<ActionOutcome> ExecuteAsync(
        ActionContext context, Connection connection, string idempotencyKey, CancellationToken ct = default)
    {
        var template = context.Settings.TryGetValue("template", out var configured) && configured.Length > 0
            ? configured
            : DefaultTemplate;

        // A missing field leaves a blank rather than the literal placeholder: an SMS reading
        // "User: {{event.user.id}}" during an incident is worse than one reading "User:".
        var message = TemplateRenderer.Render(template, context).Text;

        var recipients = Recipients(context);
        var shape = PayloadTemplate.TryParse(context.Settings.GetValueOrDefault("payload"));

        var payload = shape is null
            ? DefaultBody(message, context, recipients)
            : PayloadTemplate.Render(shape, context.With(MessagePath, message), out _);

        // The connection decides, not the rule: the endpoint describes the service, and every rule that
        // uses this gateway calls the same one.
        var path = ConnectionPaths.For(connection, Type, DefaultEndpointPath);

        return PostAsync(connection, path, payload, idempotencyKey, RedactedFields(context), ct);
    }

    /// <summary>
    /// What a rule sends when it says nothing: the message, and enough identification to trace it back to
    /// the alert that caused it.
    /// </summary>
    private static JsonObject DefaultBody(string message, ActionContext context, JsonArray? recipients)
    {
        var payload = new JsonObject
        {
            ["message"] = message,
            ["alertId"] = context.AlertId,
            ["severity"] = context.Severity
        };

        if (recipients is not null)
            payload["recipients"] = recipients;

        return payload;
    }

    private static JsonArray? Recipients(ActionContext context)
    {
        if (!context.Settings.TryGetValue("recipients", out var configured) || configured.Length == 0)
            return null;

        var list = new JsonArray();

        foreach (var recipient in configured.Split(
                     ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            list.Add(recipient);

        return list;
    }

    private static IReadOnlyCollection<string> RedactedFields(ActionContext context)
    {
        if (!context.Settings.TryGetValue("redact", out var extra) || extra.Length == 0)
            return AlwaysRedact;

        return
        [
            .. AlwaysRedact,
            .. extra.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        ];
    }
}
