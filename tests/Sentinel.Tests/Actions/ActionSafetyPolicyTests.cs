using Sentinel.Application.Actions;
using Sentinel.Domain.Connections;

namespace Sentinel.Tests.Actions;

/// <summary>
/// What the platform refuses to do to its own estate.
///
/// The controls elsewhere protect the platform from its inputs. These protect the estate from the
/// platform — and the case they exist for is mundane: a brute-force rule on a network behind NAT
/// identifies the office's egress address and locks out the people who would have stopped it.
/// </summary>
public class ActionSafetyPolicyTests
{
    private static readonly ActionDescriptor BlockIp = new(
        "block_ip", "Block IP", "", ConnectionType.SecurityApi,
        IsIdempotentByNature: true, IsDisruptive: true, []);

    private static readonly ActionDescriptor BlockUser = new(
        "block_user", "Block user", "", ConnectionType.SecurityApi,
        IsIdempotentByNature: true, IsDisruptive: true, []);

    private static readonly ActionDescriptor Sms = new(
        "sms", "SMS", "", ConnectionType.Sms,
        IsIdempotentByNature: false, IsDisruptive: false, []);

    private static ActionSafetyPolicy Policy(ActionSafetySettings? settings = null, CountingRateStore? rates = null) =>
        new(settings ?? new ActionSafetySettings(), rates ?? new CountingRateStore());

    [Fact]
    public async Task An_ordinary_address_is_allowed() =>
        Assert.True((await Policy().EvaluateAsync(BlockIp, 1, "203.0.113.10")).Allowed);

    // -- the kill switch ---------------------------------------------------------------------

    [Fact]
    public async Task The_kill_switch_stops_disruptive_actions()
    {
        // The control an operator reaches for when a rule is blocking the wrong things and nobody yet
        // knows which rule it is.
        var verdict = await Policy(new ActionSafetySettings { ActionsEnabled = false })
            .EvaluateAsync(BlockIp, 1, "203.0.113.10");

        Assert.False(verdict.Allowed);
        Assert.Equal(ActionSafetyPolicy.CodeDisabled, verdict.Code);
    }

    [Fact]
    public async Task The_kill_switch_does_not_stop_telling_people()
    {
        // Suppressing the message that says the platform is misbehaving would be the wrong way round.
        Assert.True((await Policy(new ActionSafetySettings { ActionsEnabled = false })
            .EvaluateAsync(Sms, 1, "+989120000000")).Allowed);
    }

    // -- the never-act list ------------------------------------------------------------------

    [Fact]
    public async Task An_allowlisted_address_is_never_blocked()
    {
        var settings = new ActionSafetySettings { NeverBlockAddresses = ["203.0.113.10"] };

        var verdict = await Policy(settings).EvaluateAsync(BlockIp, 1, "203.0.113.10");

        Assert.False(verdict.Allowed);
        Assert.Equal(ActionSafetyPolicy.CodeAllowlisted, verdict.Code);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.20.30.40", true)]
    [InlineData("10.0.0.0/8", "11.20.30.40", false)]
    [InlineData("192.168.1.0/24", "192.168.1.55", true)]
    [InlineData("192.168.1.0/24", "192.168.2.55", false)]
    [InlineData("203.0.113.0/28", "203.0.113.5", true)]
    [InlineData("203.0.113.0/28", "203.0.113.20", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    public async Task Ranges_are_honoured_so_the_list_stays_usable(string entry, string target, bool blocked)
    {
        // An operator protects 10.0.0.0/8 once rather than enumerating the estate.
        var settings = new ActionSafetySettings { NeverBlockAddresses = [entry] };

        Assert.Equal(blocked, !(await Policy(settings).EvaluateAsync(BlockIp, 1, target)).Allowed);
    }

    [Fact]
    public async Task An_allowlisted_account_is_never_suspended()
    {
        // Break-glass and service accounts. Suspending one during an incident is how the incident gets
        // worse.
        var settings = new ActionSafetySettings { NeverBlockUsers = ["break-glass", "svc-backup"] };

        Assert.False((await Policy(settings).EvaluateAsync(BlockUser, 1, "break-glass")).Allowed);
        Assert.True((await Policy(settings).EvaluateAsync(BlockUser, 1, "mallory")).Allowed);
    }

    [Fact]
    public async Task The_address_list_and_the_account_list_do_not_cross()
    {
        var settings = new ActionSafetySettings { NeverBlockUsers = ["10.0.0.1"] };

        // An account named like an address does not protect the address.
        Assert.True((await Policy(settings).EvaluateAsync(BlockIp, 1, "10.0.0.1")).Allowed);
    }

    [Fact]
    public async Task An_action_with_nothing_to_act_on_is_refused_with_a_usable_reason()
    {
        var verdict = await Policy().EvaluateAsync(BlockIp, 1, target: "");

        Assert.False(verdict.Allowed);
        Assert.Equal(ActionSafetyPolicy.CodeNoTarget, verdict.Code);
        Assert.Contains("groups by", verdict.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    // -- the rate caps -----------------------------------------------------------------------

    [Fact]
    public async Task One_rule_cannot_block_without_limit()
    {
        // A rule that wants two hundred blocks in a minute has either been mis-authored or is describing
        // an incident the platform should be reporting rather than acting on unaided.
        var settings = new ActionSafetySettings { MaxDisruptiveActionsPerRule = 3 };
        var policy = Policy(settings, new CountingRateStore());

        for (var i = 0; i < 3; i++)
            Assert.True((await policy.EvaluateAsync(BlockIp, 1, $"203.0.113.{i}")).Allowed);

        var verdict = await policy.EvaluateAsync(BlockIp, 1, "203.0.113.99");

        Assert.False(verdict.Allowed);
        Assert.Equal(ActionSafetyPolicy.CodeRuleRateLimited, verdict.Code);
    }

    [Fact]
    public async Task One_rule_hitting_its_cap_does_not_stop_another()
    {
        var settings = new ActionSafetySettings { MaxDisruptiveActionsPerRule = 1, MaxDisruptiveActionsGlobal = 100 };
        var policy = Policy(settings, new CountingRateStore());

        await policy.EvaluateAsync(BlockIp, ruleId: 1, "203.0.113.1");
        Assert.False((await policy.EvaluateAsync(BlockIp, ruleId: 1, "203.0.113.2")).Allowed);
        Assert.True((await policy.EvaluateAsync(BlockIp, ruleId: 2, "203.0.113.3")).Allowed);
    }

    [Fact]
    public async Task A_global_cap_catches_several_rules_going_wrong_at_once()
    {
        var settings = new ActionSafetySettings
        {
            MaxDisruptiveActionsPerRule = 100,
            MaxDisruptiveActionsGlobal = 2
        };
        var policy = Policy(settings, new CountingRateStore());

        await policy.EvaluateAsync(BlockIp, 1, "203.0.113.1");
        await policy.EvaluateAsync(BlockIp, 2, "203.0.113.2");

        var verdict = await policy.EvaluateAsync(BlockIp, 3, "203.0.113.3");

        Assert.False(verdict.Allowed);
        Assert.Equal(ActionSafetyPolicy.CodeGlobalRateLimited, verdict.Code);
    }

    [Fact]
    public async Task Notifications_are_not_rate_capped()
    {
        var settings = new ActionSafetySettings { MaxDisruptiveActionsPerRule = 1, MaxDisruptiveActionsGlobal = 1 };
        var policy = Policy(settings, new CountingRateStore());

        for (var i = 0; i < 20; i++)
            Assert.True((await policy.EvaluateAsync(Sms, 1, "+98912000000" + i)).Allowed);
    }

    [Fact]
    public async Task A_refused_action_still_says_why_in_terms_an_operator_can_act_on()
    {
        var verdict = await Policy(new ActionSafetySettings { MaxDisruptiveActionsPerRule = 0 },
            new CountingRateStore()).EvaluateAsync(BlockIp, 7, "203.0.113.1");

        Assert.Contains("Rule 7", verdict.Reason!, StringComparison.Ordinal);
    }

    private sealed class CountingRateStore : IActionRateStore
    {
        private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);

        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
        {
            _counts[key] = _counts.GetValueOrDefault(key) + 1;
            return Task.FromResult(_counts[key]);
        }

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) =>
            Task.FromResult(_counts.GetValueOrDefault(key));
    }
}
