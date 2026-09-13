using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sentinel.Application.Engine;
using Sentinel.Application.Rules;
using Sentinel.Domain.Connections;
using Sentinel.Infrastructure.Persistence;

namespace Sentinel.Infrastructure.Engine;

/// <summary>
/// Loads the rules the engine should evaluate, each pinned to the exact version that is current.
///
/// The version is what makes forensics possible. An alert names the version that produced it, so when
/// somebody asks six weeks later why an address was blocked, the answer is the rule as it was then — not
/// the rule as it is now, which may have been edited precisely because of that incident.
///
/// A rule whose version or connection has gone missing is skipped with a warning rather than throwing.
/// One broken row must not stop the engine evaluating everything else.
/// </summary>
public sealed class EfRuleRuntimeSource(
    SentinelDbContext db, ILogger<EfRuleRuntimeSource> logger) : IRuleRuntimeSource
{
    public async Task<IReadOnlyList<(RuleDefinition Rule, Connection Source)>> ActiveRulesAsync(
        CancellationToken ct = default)
    {
        var rules = await db.Rules.AsNoTracking()
            .Where(r => r.Enabled)
            .OrderBy(r => r.Id)
            .ToListAsync(ct);

        if (rules.Count == 0)
            return [];

        var ruleIds = rules.Select(r => r.Id).ToList();
        var connectionIds = rules.Select(r => r.ConnectionId).Distinct().ToList();

        // Loaded in two queries rather than one per rule: a hundred enabled rules would otherwise be a
        // hundred round trips on every tick.
        var versions = await db.RuleVersions.AsNoTracking()
            .Where(v => ruleIds.Contains(v.RuleId))
            .ToListAsync(ct);

        var connections = await db.Connections.AsNoTracking()
            .Where(c => connectionIds.Contains(c.Id))
            .ToDictionaryAsync(c => c.Id, ct);

        var runnable = new List<(RuleDefinition, Connection)>(rules.Count);

        foreach (var rule in rules)
        {
            var version = versions.FirstOrDefault(v => v.RuleId == rule.Id && v.Version == rule.CurrentVersion);

            if (version is null)
            {
                logger.LogWarning(
                    "Rule {RuleId} points at version {Version}, which does not exist. Skipping it.",
                    rule.Id, rule.CurrentVersion);
                continue;
            }

            if (!connections.TryGetValue(rule.ConnectionId, out var source))
            {
                logger.LogWarning(
                    "Rule {RuleId} reads from connection {ConnectionId}, which does not exist. Skipping it.",
                    rule.Id, rule.ConnectionId);
                continue;
            }

            if (!source.Enabled)
            {
                logger.LogWarning(
                    "Rule {RuleId} reads from connection '{Connection}', which is disabled. Skipping it.",
                    rule.Id, source.Name);
                continue;
            }

            runnable.Add((RuleDefinitionMapper.From(version, rule.ConnectionId), source));
        }

        return runnable;
    }

    public async Task<(RuleDefinition Rule, Connection Source)?> ActiveRuleAsync(
        int ruleId, CancellationToken ct = default)
    {
        var rule = await db.Rules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == ruleId, ct);

        if (rule is null)
            return null;

        var version = await db.RuleVersions.AsNoTracking()
            .FirstOrDefaultAsync(v => v.RuleId == ruleId && v.Version == rule.CurrentVersion, ct);

        if (version is null)
            return null;

        var source = await db.Connections.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == rule.ConnectionId, ct);

        // Deliberately not filtered on Enabled: this serves "run now" and a rehearsal, where evaluating a
        // rule that is not on a schedule is the whole point.
        return source is null ? null : (RuleDefinitionMapper.From(version, rule.ConnectionId), source);
    }
}
