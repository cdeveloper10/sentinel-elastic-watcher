using System.Net;
using System.Net.Sockets;

namespace Sentinel.Application.Actions;

public sealed record SafetyVerdict(bool Allowed, string? Code, string? Reason)
{
    public static readonly SafetyVerdict Allow = new(true, null, null);

    public static SafetyVerdict Refuse(string code, string reason) => new(false, code, reason);
}

public sealed class ActionSafetySettings
{
    /// <summary>
    /// Stops every disruptive action across the platform without disabling detection. The control an
    /// operator reaches for at 03:00 when a rule is blocking the wrong things and nobody yet knows which
    /// rule it is.
    /// </summary>
    public bool ActionsEnabled { get; set; } = true;

    /// <summary>Addresses and networks that must never be blocked, in CIDR or plain form.</summary>
    public List<string> NeverBlockAddresses { get; set; } = [];

    /// <summary>Accounts that must never be suspended: break-glass, service accounts, the on-call rota.</summary>
    public List<string> NeverBlockUsers { get; set; } = [];

    /// <summary>
    /// Ceiling on disruptive actions one rule may perform in <see cref="RateWindowSeconds"/>. A rule that
    /// wants to block two hundred addresses in a minute has either been mis-authored or is describing an
    /// incident the platform should be reporting rather than acting on unaided.
    /// </summary>
    public int MaxDisruptiveActionsPerRule { get; set; } = 25;

    public int RateWindowSeconds { get; set; } = 60;

    /// <summary>Ceiling across every rule, for the case where several rules go wrong together.</summary>
    public int MaxDisruptiveActionsGlobal { get; set; } = 100;
}

/// <summary>Counts disruptive actions so the caps can be enforced across restarts and across nodes.</summary>
public interface IActionRateStore
{
    /// <summary>Increments the counter for a key and returns the new total within the window.</summary>
    Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default);

    Task<int> CurrentAsync(string key, CancellationToken ct = default);
}

/// <summary>
/// What the platform refuses to do to itself.
///
/// This is the part the brief did not ask for, and the part a system that blocks addresses automatically
/// cannot ship without. The first time a brute-force rule runs against a network behind NAT, the address
/// it identifies is the office's egress address, and the platform locks out the people who would have
/// stopped it. The technical controls elsewhere — SSRF, template injection — protect the platform from
/// its inputs; these protect the estate from the platform.
///
/// Every refusal is recorded as a skipped execution rather than dropped, because "the rule fired and we
/// deliberately did nothing" is a different fact from "the rule did not fire", and only one of them means
/// the rule needs attention.
/// </summary>
public sealed class ActionSafetyPolicy(ActionSafetySettings settings, IActionRateStore rates)
{
    public const string CodeDisabled = "ACTIONS_DISABLED";
    public const string CodeAllowlisted = "TARGET_ALLOWLISTED";
    public const string CodeRuleRateLimited = "RULE_RATE_LIMITED";
    public const string CodeGlobalRateLimited = "GLOBAL_RATE_LIMITED";
    public const string CodeNoTarget = "NO_TARGET";

    /// <summary>
    /// Checked before an attempt. Non-disruptive actions — notifying a person — skip the caps entirely:
    /// suppressing the message that tells somebody the platform is misbehaving would be the wrong way
    /// round.
    /// </summary>
    public async Task<SafetyVerdict> EvaluateAsync(
        ActionDescriptor action,
        int ruleId,
        string? target,
        CancellationToken ct = default)
    {
        if (!action.IsDisruptive)
            return SafetyVerdict.Allow;

        if (!settings.ActionsEnabled)
            return SafetyVerdict.Refuse(CodeDisabled,
                "Disruptive actions are switched off platform-wide.");

        if (string.IsNullOrWhiteSpace(target))
            return SafetyVerdict.Refuse(CodeNoTarget,
                "The alert carries no target for this action, so there is nothing to act on. " +
                "Check that the rule groups by the field the action needs.");

        if (IsProtected(action.Type, target))
            return SafetyVerdict.Refuse(CodeAllowlisted,
                $"'{target}' is on the never-act list.");

        var window = TimeSpan.FromSeconds(Math.Max(1, settings.RateWindowSeconds));

        var perRule = await rates.IncrementAsync($"action-rate:rule:{ruleId}", window, ct);
        if (perRule > settings.MaxDisruptiveActionsPerRule)
            return SafetyVerdict.Refuse(CodeRuleRateLimited,
                $"Rule {ruleId} has reached {settings.MaxDisruptiveActionsPerRule} disruptive actions " +
                $"in {window.TotalSeconds:0} seconds. Later actions are being held back.");

        var global = await rates.IncrementAsync("action-rate:global", window, ct);
        if (global > settings.MaxDisruptiveActionsGlobal)
            return SafetyVerdict.Refuse(CodeGlobalRateLimited,
                $"The platform has reached {settings.MaxDisruptiveActionsGlobal} disruptive actions " +
                $"in {window.TotalSeconds:0} seconds across all rules.");

        return SafetyVerdict.Allow;
    }

    private bool IsProtected(string actionType, string target) =>
        actionType.Contains("user", StringComparison.OrdinalIgnoreCase)
            ? settings.NeverBlockUsers.Contains(target, StringComparer.OrdinalIgnoreCase)
            : IsProtectedAddress(target);

    /// <summary>
    /// Matches an address against the never-block list, which holds plain addresses and CIDR ranges. The
    /// range form is what makes the list usable: an operator protects <c>10.0.0.0/8</c> once rather than
    /// enumerating the estate.
    /// </summary>
    internal bool IsProtectedAddress(string target)
    {
        if (!IPAddress.TryParse(target, out var address))
            return settings.NeverBlockAddresses.Contains(target, StringComparer.OrdinalIgnoreCase);

        foreach (var entry in settings.NeverBlockAddresses)
        {
            if (TryMatch(entry, address))
                return true;
        }

        return false;
    }

    private static bool TryMatch(string entry, IPAddress address)
    {
        var trimmed = entry?.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return false;

        var slash = trimmed.IndexOf('/');

        if (slash < 0)
            return IPAddress.TryParse(trimmed, out var single) && single.Equals(address);

        if (!IPAddress.TryParse(trimmed[..slash], out var network) ||
            !int.TryParse(trimmed[(slash + 1)..], out var prefix))
            return false;

        if (network.AddressFamily != address.AddressFamily)
            return false;

        var networkBytes = network.GetAddressBytes();
        var addressBytes = address.GetAddressBytes();
        var maxPrefix = networkBytes.Length * 8;

        if (prefix < 0 || prefix > maxPrefix)
            return false;

        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (networkBytes[i] != addressBytes[i])
                return false;
        }

        if (remainingBits == 0)
            return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (addressBytes[fullBytes] & mask);
    }
}
