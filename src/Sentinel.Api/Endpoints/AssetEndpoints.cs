using System.Net;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Auth;
using Sentinel.Application.Audit;
using Sentinel.Application.Security;
using Sentinel.Domain.Platform;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Api.Endpoints;

/// <summary>
/// The asset inventory the enrichment reads.
///
/// Managed with <c>connections.manage</c> rather than a permission of its own. What an entry decides is
/// how serious an alert about that thing is and whether a rule blocks it, which is the same class of
/// decision as pointing a connection at a gateway — and a new permission nobody has been granted is a
/// feature nobody can use.
/// </summary>
public static class AssetEndpoints
{
    public static void MapAssets(this WebApplication app)
    {
        var group = app.MapGroup("/api/assets").WithTags("Assets");

        group.MapGet("", async (SentinelDbContext db, CancellationToken ct) =>
            Results.Ok(await db.Assets.AsNoTracking()
                .OrderBy(a => a.Name)
                .ToListAsync(ct)))
            .Requires(Permission.ConnectionsRead);

        group.MapPost("", async (
            AssetRequest request, SentinelDbContext db, IAuditTrail audit,
            CurrentUser current, TimeProvider clock, CancellationToken ct) =>
        {
            var (asset, failures) = Validate(request, clock.GetUtcNow().UtcDateTime);

            if (failures.Count > 0)
                return Results.ValidationProblem(failures);

            if (await db.Assets.AnyAsync(a => a.Identifier == asset!.Identifier, ct))
                return Results.Conflict(new { error = $"'{asset!.Identifier}' is already in the inventory." });

            db.Assets.Add(asset!);
            await db.SaveChangesAsync(ct);

            EfAssetLookup.Invalidate();

            await audit.RecordAsync(await current.ActorAsync(ct),
                "ASSET_CREATED", "asset", asset!.Id.ToString(),
                changes: new { asset.Identifier, asset.Criticality }, ct: ct);

            return Results.Created($"/api/assets/{asset.Id}", new { asset.Id });
        }).Requires(Permission.ConnectionsManage);

        group.MapPut("/{id:int}", async (
            int id, AssetRequest request, SentinelDbContext db, IAuditTrail audit,
            CurrentUser current, TimeProvider clock, CancellationToken ct) =>
        {
            var existing = await db.Assets.FirstOrDefaultAsync(a => a.Id == id, ct);

            if (existing is null)
                return Results.NotFound();

            var now = clock.GetUtcNow().UtcDateTime;
            var (asset, failures) = Validate(request, now);

            if (failures.Count > 0)
                return Results.ValidationProblem(failures);

            if (await db.Assets.AnyAsync(a => a.Identifier == asset!.Identifier && a.Id != id, ct))
                return Results.Conflict(new { error = $"'{asset!.Identifier}' is already in the inventory." });

            existing.Identifier = asset!.Identifier;
            existing.Kind = asset.Kind;
            existing.Name = asset.Name;
            existing.Criticality = asset.Criticality;
            existing.Owner = asset.Owner;
            existing.Environment = asset.Environment;
            existing.Notes = asset.Notes;
            existing.UpdatedAt = now;
            existing.UpdatedBy = (await current.ActorAsync(ct)).Name;

            await db.SaveChangesAsync(ct);

            EfAssetLookup.Invalidate();

            await audit.RecordAsync(await current.ActorAsync(ct),
                "ASSET_UPDATED", "asset", id.ToString(),
                changes: new { existing.Identifier, existing.Criticality }, ct: ct);

            return Results.NoContent();
        }).Requires(Permission.ConnectionsManage);

        group.MapDelete("/{id:int}", async (
            int id, SentinelDbContext db, IAuditTrail audit, CurrentUser current, CancellationToken ct) =>
        {
            var existing = await db.Assets.FirstOrDefaultAsync(a => a.Id == id, ct);

            if (existing is null)
                return Results.NotFound();

            db.Assets.Remove(existing);
            await db.SaveChangesAsync(ct);

            EfAssetLookup.Invalidate();

            // Audited with what it said, because removing an entry lowers the severity of every future
            // alert about that thing — a quiet change with a visible effect weeks later.
            await audit.RecordAsync(await current.ActorAsync(ct),
                "ASSET_DELETED", "asset", id.ToString(),
                changes: new { existing.Identifier, existing.Name, existing.Criticality }, ct: ct);

            return Results.NoContent();
        }).Requires(Permission.ConnectionsManage);
    }

    /// <summary>
    /// Checks an entry, and settles what kind it is here rather than at match time.
    ///
    /// Deciding on save means a malformed range is a message to whoever typed it, instead of a row that
    /// silently matches nothing for as long as it sits there.
    /// </summary>
    private static (Asset? Asset, Dictionary<string, string[]> Failures) Validate(AssetRequest request, DateTime now)
    {
        var failures = new Dictionary<string, string[]>();

        var identifier = request.Identifier?.Trim() ?? "";
        var name = request.Name?.Trim() ?? "";

        if (identifier.Length == 0)
            failures["identifier"] = ["An entry needs an address, a range or an account name."];

        if (name.Length == 0)
            failures["name"] = ["Give it a name somebody reading an alert would recognise."];

        var criticality = AssetCriticality.Canonical(request.Criticality);

        if (criticality is null)
            failures["criticality"] = [$"Expected one of: {string.Join(", ", AssetCriticality.All)}."];

        var kind = AssetKind.Canonical(request.Kind);

        if (kind is null)
            failures["kind"] = [$"Expected one of: {string.Join(", ", AssetKind.All)}."];

        else if (kind == AssetKind.Network)
        {
            if (!IPNetwork.TryParse(identifier, out var network))
                failures["identifier"] = ["A network entry must be a CIDR range, such as '10.5.5.0/24'."];
            else
                // Stored as the range it means. TryParse accepts "10.5.5.5/24" and reads it as
                // 10.5.5.0/24, so keeping what was typed would leave a row whose identifier says one
                // thing and whose matching does another — and the console would show the misleading half.
                identifier = network.ToString();
        }

        else if (kind == AssetKind.Address && !IPAddress.TryParse(identifier, out _))
            failures["identifier"] = ["An address entry must be an IP address. Use Network for a range."];

        if (failures.Count > 0)
            return (null, failures);

        return (new Asset
        {
            Identifier = identifier,
            Kind = kind!,
            Name = name,
            Criticality = criticality!,
            Owner = request.Owner?.Trim(),
            Environment = request.Environment?.Trim(),
            Notes = request.Notes?.Trim(),
            CreatedAt = now,
            UpdatedAt = now
        }, failures);
    }
}
