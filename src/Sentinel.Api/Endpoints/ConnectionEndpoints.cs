using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Auth;
using Sentinel.Application.Audit;
using Sentinel.Application.Connections;
using Sentinel.Application.EventSources;
using Sentinel.Application.Security;
using Sentinel.Domain.Connections;
using Sentinel.Domain.Platform;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Api.Endpoints;

public static class ConnectionEndpoints
{
    public static void MapConnections(this WebApplication app)
    {
        var group = app.MapGroup("/api/connections").WithTags("Connections");

        group.MapGet("", List).Requires(Permission.ConnectionsRead);
        group.MapGet("/{id:int}", Get).Requires(Permission.ConnectionsRead);
        group.MapPost("", Create).Requires(Permission.ConnectionsManage);
        group.MapPut("/{id:int}", Update).Requires(Permission.ConnectionsManage);
        group.MapDelete("/{id:int}", Delete).Requires(Permission.ConnectionsManage);

        // Reading from a cluster is a read, so this needs only connections.read — an analyst checking why
        // a rule went quiet should not need the permission that lets them change a credential.
        group.MapPost("/{id:int}/probe", Probe).Requires(Permission.ConnectionsRead);
        group.MapGet("/{id:int}/indices", Indices).Requires(Permission.ConnectionsRead);
        group.MapGet("/{id:int}/fields", Fields).Requires(Permission.ConnectionsRead);
    }

    /// <summary>
    /// Projected without the ciphertext rather than filtered after the fact, so no later change to this
    /// shape can start returning it. What a caller sees is which secrets are set, never their values.
    /// </summary>
    private static async Task<IResult> List(SentinelDbContext db, CancellationToken ct) =>
        Results.Ok(await db.Connections.AsNoTracking()
            .OrderBy(c => c.Name)
            .Select(c => new
            {
                c.Id, c.Name, c.DisplayName, c.Description, c.Type, c.Endpoint,
                c.AuthenticationMode, c.TimeoutSeconds, c.Enabled, c.ConfigurationJson,
                c.LastProbedAt, c.LastProbeSucceeded, c.LastProbeMessage,
                c.CreatedAt, c.UpdatedAt, c.UpdatedBy,
                SecretKeys = c.SecretKeysJson
            })
            .ToListAsync(ct));

    private static async Task<IResult> Get(int id, SentinelDbContext db, CancellationToken ct)
    {
        var connection = await db.Connections.AsNoTracking()
            .Where(c => c.Id == id)
            .Select(c => new
            {
                c.Id, c.Name, c.DisplayName, c.Description, c.Type, c.Endpoint,
                c.AuthenticationMode, c.TimeoutSeconds, c.Enabled, c.ConfigurationJson,
                c.LastProbedAt, c.LastProbeSucceeded, c.LastProbeMessage,
                SecretKeys = c.SecretKeysJson
            })
            .FirstOrDefaultAsync(ct);

        return connection is null ? Results.NotFound() : Results.Ok(connection);
    }

    private static async Task<IResult> Create(
        ConnectionRequest request,
        SentinelDbContext db,
        ISecretProtector protector,
        OutboundAddressSettings addresses,
        IAuditTrail audit,
        CurrentUser current,
        TimeProvider clock,
        CancellationToken ct)
    {
        var secrets = request.Secrets ?? [];

        var validation = ConnectionRules.Validate(
            request.Name, request.Type, request.Endpoint, request.AuthenticationMode,
            request.TimeoutSeconds, secrets.Keys, addresses, request.ConfigurationJson);

        if (!validation.IsValid)
            return Problems(validation);

        if (await db.Connections.AnyAsync(c => c.Name == request.Name, ct))
            return Results.Conflict(new { error = $"A connection named '{request.Name}' already exists." });

        var actor = await current.ActorAsync(ct);
        var now = clock.GetUtcNow().UtcDateTime;

        var connection = new Connection
        {
            Name = request.Name.Trim(),
            DisplayName = request.DisplayName?.Trim() ?? request.Name.Trim(),
            Description = request.Description?.Trim() ?? "",
            Type = ConnectionType.Canonical(request.Type),
            Endpoint = request.Endpoint.Trim(),
            AuthenticationMode = Sentinel.Domain.Connections.AuthenticationMode.Canonical(request.AuthenticationMode),
            TimeoutSeconds = request.TimeoutSeconds,
            Enabled = request.Enabled,
            ConfigurationJson = string.IsNullOrWhiteSpace(request.ConfigurationJson) ? "{}" : request.ConfigurationJson,
            SecretCiphertext = secrets.Count > 0 ? protector.Protect(secrets) : null,
            SecretKeysJson = JsonSerializer.Serialize(secrets.Keys.Order().ToList()),
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = actor.Name,
            UpdatedBy = actor.Name
        };

        db.Connections.Add(connection);
        await db.SaveChangesAsync(ct);

        // The change set is redacted by the audit layer, so the endpoint does not have to remember which
        // of these fields is a credential.
        await audit.RecordAsync(actor, AuditOperation.ConnectionCreated, "connection", connection.Id.ToString(),
            changes: new { connection.Name, connection.Type, connection.Endpoint, secretsSet = secrets.Keys },
            ct: ct);

        return Results.Created($"/api/connections/{connection.Id}", new { connection.Id, connection.Name });
    }

    private static async Task<IResult> Update(
        int id,
        ConnectionRequest request,
        SentinelDbContext db,
        ISecretProtector protector,
        OutboundAddressSettings addresses,
        IAuditTrail audit,
        CurrentUser current,
        TimeProvider clock,
        CancellationToken ct)
    {
        var connection = await db.Connections.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (connection is null)
            return Results.NotFound();

        // Omitting secrets on an update keeps what is stored, so changing a timeout does not require
        // re-entering an API key — which is how keys end up written down.
        var stored = ReadKeys(connection.SecretKeysJson);
        var incoming = request.Secrets ?? [];
        var effectiveKeys = incoming.Count > 0 ? incoming.Keys.ToList() : stored;

        var validation = ConnectionRules.Validate(
            request.Name, request.Type, request.Endpoint, request.AuthenticationMode,
            request.TimeoutSeconds, effectiveKeys, addresses, request.ConfigurationJson);

        if (!validation.IsValid)
            return Problems(validation);

        if (await db.Connections.AnyAsync(c => c.Name == request.Name && c.Id != id, ct))
            return Results.Conflict(new { error = $"A connection named '{request.Name}' already exists." });

        var before = new Dictionary<string, object?>
        {
            ["name"] = connection.Name,
            ["endpoint"] = connection.Endpoint,
            ["authenticationMode"] = connection.AuthenticationMode,
            ["timeoutSeconds"] = connection.TimeoutSeconds,
            ["enabled"] = connection.Enabled
        };

        var actor = await current.ActorAsync(ct);

        connection.Name = request.Name.Trim();
        connection.DisplayName = request.DisplayName?.Trim() ?? connection.DisplayName;
        connection.Description = request.Description?.Trim() ?? "";
        connection.Type = ConnectionType.Canonical(request.Type);
        connection.Endpoint = request.Endpoint.Trim();
        connection.AuthenticationMode = Sentinel.Domain.Connections.AuthenticationMode.Canonical(request.AuthenticationMode);
        connection.TimeoutSeconds = request.TimeoutSeconds;
        connection.Enabled = request.Enabled;
        connection.ConfigurationJson = string.IsNullOrWhiteSpace(request.ConfigurationJson)
            ? connection.ConfigurationJson
            : request.ConfigurationJson;
        connection.UpdatedAt = clock.GetUtcNow().UtcDateTime;
        connection.UpdatedBy = actor.Name;

        if (incoming.Count > 0)
        {
            connection.SecretCiphertext = protector.Protect(incoming);
            connection.SecretKeysJson = JsonSerializer.Serialize(incoming.Keys.Order().ToList());
        }

        await db.SaveChangesAsync(ct);

        var after = new Dictionary<string, object?>
        {
            ["name"] = connection.Name,
            ["endpoint"] = connection.Endpoint,
            ["authenticationMode"] = connection.AuthenticationMode,
            ["timeoutSeconds"] = connection.TimeoutSeconds,
            ["enabled"] = connection.Enabled
        };

        await audit.RecordAsync(actor, AuditOperation.ConnectionUpdated, "connection", id.ToString(),
            changes: new { before, after, secretsReplaced = incoming.Count > 0 }, ct: ct);

        return Results.NoContent();
    }

    private static async Task<IResult> Delete(
        int id, SentinelDbContext db, IAuditTrail audit, CurrentUser current, CancellationToken ct)
    {
        var connection = await db.Connections.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (connection is null)
            return Results.NotFound();

        // Refused rather than cascaded. Deleting the source out from under a live rule would leave it
        // failing every tick with an error nobody connected to this action.
        var used = await db.Rules.CountAsync(r => r.ConnectionId == id, ct);
        if (used > 0)
            return Results.Conflict(new
            {
                error = $"{used} rule(s) read from '{connection.Name}'. Point them elsewhere or delete them first."
            });

        db.Connections.Remove(connection);
        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            AuditOperation.ConnectionDeleted, "connection", id.ToString(),
            changes: new { connection.Name, connection.Type }, ct: ct);

        return Results.NoContent();
    }

    private static async Task<IResult> Probe(
        int id, SentinelDbContext db, IEventSource source, IAuditTrail audit, CurrentUser current,
        TimeProvider clock, CancellationToken ct)
    {
        var connection = await db.Connections.FirstOrDefaultAsync(c => c.Id == id, ct);
        if (connection is null)
            return Results.NotFound();

        if (connection.Type != ConnectionType.Elasticsearch)
            return Results.BadRequest(new
            {
                error = $"'{connection.Name}' is a {connection.Type} connection, which is not an event source."
            });

        var probe = await source.ProbeAsync(connection, ct);

        // Stored so the list can show a connection as verified without re-probing every page load.
        connection.LastProbedAt = clock.GetUtcNow().UtcDateTime;
        connection.LastProbeSucceeded = probe.Reachable;
        connection.LastProbeMessage = probe.Message;
        await db.SaveChangesAsync(ct);

        await audit.RecordAsync(await current.ActorAsync(ct),
            AuditOperation.ConnectionTested, "connection", id.ToString(),
            result: probe.Reachable ? "SUCCESS" : "FAILED", detail: probe.Message, ct: ct);

        return Results.Ok(probe);
    }

    private static async Task<IResult> Indices(
        int id, string? pattern, SentinelDbContext db, IEventSource source, CancellationToken ct)
    {
        var connection = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
        if (connection is null)
            return Results.NotFound();

        try
        {
            return Results.Ok(await source.ListIndicesAsync(connection, pattern ?? "*", ct));
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static async Task<IResult> Fields(
        int id, string patterns, SentinelDbContext db, IEventSource source, CancellationToken ct)
    {
        var connection = await db.Connections.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
        if (connection is null)
            return Results.NotFound();

        var split = patterns.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        // The same validation the rule save path uses, so the field picker cannot offer a pattern that a
        // rule would then be refused for.
        var validation = IndexPatternRules.Validate(split);
        if (!validation.IsValid)
            return Problems(validation);

        try
        {
            return Results.Ok(await source.DescribeFieldsAsync(connection, split, ct));
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    internal static IResult Problems(ValidationResult validation) =>
        Results.ValidationProblem(validation.Failures
            .GroupBy(f => f.Field)
            .ToDictionary(g => g.Key, g => g.Select(f => f.Message).ToArray()));

    private static List<string> ReadKeys(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return [];

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
