namespace Sentinel.Domain.Platform;

/// <summary>
/// Something in the estate, and how much it matters.
///
/// The smallest inventory that changes a decision. Not a CMDB and not trying to be one: what the platform
/// needs before it blocks an address is whether that address is a laptop or a domain controller, and who
/// to ask. Everything else an asset database holds is somebody else's problem.
///
/// Matched by address, network or account rather than by a single kind of key, because the subjects rules
/// group by are not all of one kind — a brute-force rule identifies an address and an account-lockout rule
/// identifies a user, and both want the same question answered.
/// </summary>
public class Asset
{
    public int Id { get; set; }

    /// <summary>
    /// What this matches: an address, a CIDR range, or an account name.
    ///
    /// One column rather than three, because a row answers about one thing and the form should not ask an
    /// operator which of three boxes their value belongs in. <see cref="Kind"/> says how to read it.
    /// </summary>
    public string Identifier { get; set; } = "";

    /// <summary>One of <see cref="AssetKind"/>. Decided when the row is saved, not guessed at match time.</summary>
    public string Kind { get; set; } = AssetKind.Address;

    public string Name { get; set; } = "";

    /// <summary>One of <see cref="AssetCriticality"/>. What raises an alert's severity.</summary>
    public string Criticality { get; set; } = AssetCriticality.Normal;

    /// <summary>Who to wake. Free text because every estate names this differently.</summary>
    public string? Owner { get; set; }

    /// <summary>Production, staging, a lab. A rule that fires on both wants to say which.</summary>
    public string? Environment { get; set; }

    public string? Notes { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

public static class AssetKind
{
    /// <summary>A single address.</summary>
    public const string Address = "ADDRESS";

    /// <summary>A CIDR range, so a subnet is one row rather than two hundred and fifty.</summary>
    public const string Network = "NETWORK";

    /// <summary>An account name or id.</summary>
    public const string Account = "ACCOUNT";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Address, Network, Account };

    public static string? Canonical(string? value) =>
        value is null ? null : All.FirstOrDefault(v => v.Equals(value, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// How much an asset matters, and therefore how serious an alert about it is.
///
/// Four levels that map onto the alert severities on purpose: the whole point is that an alert about a
/// critical asset should not sit in a queue behind one about a test machine, and the simplest way to make
/// that true is for the inventory to speak the same language the alert does.
/// </summary>
public static class AssetCriticality
{
    public const string Low = "LOW";
    public const string Normal = "NORMAL";
    public const string High = "HIGH";
    public const string Critical = "CRITICAL";

    public static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Low, Normal, High, Critical };

    public static string? Canonical(string? value) =>
        value is null ? null : All.FirstOrDefault(v => v.Equals(value, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The severity an alert about this asset should not fall below, or null where it should not move.
    ///
    /// Only the top two raise anything. A "normal" asset is what most of the estate is, and a floor there
    /// would raise every alert in the platform, which is the same as raising none.
    /// </summary>
    public static string? SeverityFloor(string? criticality) => Canonical(criticality) switch
    {
        Critical => "CRITICAL",
        High => "HIGH",
        _ => null
    };
}
