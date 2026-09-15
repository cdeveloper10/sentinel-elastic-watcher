using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Application.Actions;
using Sentinel.Application.Enrichment;
using Sentinel.Domain.Platform;
using Sentinel.Domain.Rules;

namespace Sentinel.Tests.Enrichment;

/// <summary>
/// What the platform knows about the subject of an alert beyond what the log line said.
///
/// The step this adds sits between detecting and responding, and the properties worth protecting are
/// mostly about restraint: an enrichment that fails must not cost the alert, and one that is wrong must
/// not be able to make an alert look less serious than the rule said.
/// </summary>
public class EnrichmentTests
{
    private static EnrichmentRequest About(
        string field, string value, string severity = Severity.Medium) =>
        new(1, "Brute force", severity,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [field] = value },
            null);

    private static EnrichmentPipeline Pipeline(params IEnrichment[] enrichments) =>
        new(enrichments, NullLogger<EnrichmentPipeline>.Instance);

    // -- the pipeline --------------------------------------------------------

    [Fact]
    public async Task Facts_are_namespaced_by_the_enrichment_that_found_them()
    {
        // Two enrichments both answering "owner" is ordinary, and neither should win.
        var result = await Pipeline(
                new Fixed("asset", new() { ["owner"] = "Infrastructure" }),
                new Fixed("directory", new() { ["owner"] = "ali.sharafi" }))
            .EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Equal("Infrastructure", result.Facts["asset.owner"]);
        Assert.Equal("ali.sharafi", result.Facts["directory.owner"]);
    }

    [Fact]
    public async Task An_enrichment_that_throws_does_not_cost_the_alert()
    {
        // These reach inventories and third-party services — things that are down at exactly the moment
        // an incident is happening. An alert not recorded because a lookup failed is the worst trade
        // available.
        var result = await Pipeline(
                new Broken("intel"),
                new Fixed("asset", new() { ["name"] = "dc01" }))
            .EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Equal("dc01", result.Facts["asset.name"]);
        Assert.Contains("unreachable", result.Facts["intel.error"]);
    }

    [Fact]
    public async Task A_failure_is_recorded_as_a_fact_rather_than_only_logged()
    {
        // The person reading the alert is not reading the engine's log, and "owner: " with no explanation
        // is indistinguishable from an asset nobody has entered.
        var result = await Pipeline(new Broken("intel")).EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.True(result.Facts.ContainsKey("intel.error"));
    }

    [Fact]
    public async Task An_enrichment_that_hangs_is_abandoned_rather_than_holding_up_detection()
    {
        var result = await Pipeline(new Hangs("slow")).EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Contains("did not answer", result.Facts["slow.error"]);
    }

    [Fact]
    public async Task Cancelling_the_evaluation_is_not_swallowed_as_an_enrichment_failure()
    {
        // The engine shutting down must propagate. Recording it as "the enrichment failed" would turn a
        // stopped process into an alert that looks enriched and is not.
        using var stopping = new CancellationTokenSource();
        await stopping.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Pipeline(new Fixed("asset", [])).EnrichAsync(About("source.ip", "10.5.5.5"), stopping.Token));
    }

    // -- severity ------------------------------------------------------------

    [Fact]
    public async Task An_enrichment_can_raise_the_severity_a_rule_assumed()
    {
        var result = await Pipeline(new Fixed("asset", new() { ["name"] = "dc01" }, Severity.Critical))
            .EnrichAsync(About("source.ip", "10.5.5.5", Severity.Low));

        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Fact]
    public async Task It_cannot_lower_one()
    {
        // The asymmetry that matters. A stale inventory entry saying "this is a test box" would otherwise
        // quietly downgrade a real incident, and nothing about the alert would look wrong afterwards.
        var result = await Pipeline(new Fixed("asset", [], Severity.Low))
            .EnrichAsync(About("source.ip", "10.5.5.5", Severity.Critical));

        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Theory]
    [InlineData(Severity.Low, Severity.High, Severity.High)]
    [InlineData(Severity.High, Severity.Low, Severity.High)]
    [InlineData(Severity.Medium, null, Severity.Medium)]
    [InlineData(Severity.Medium, "NONSENSE", Severity.Medium)]
    public void Raising_takes_the_higher_of_the_two(string current, string? floor, string expected) =>
        Assert.Equal(expected, EnrichmentPipeline.Raise(current, floor));

    // -- the network enrichment ---------------------------------------------

    [Theory]
    [InlineData("10.5.5.5", "private")]
    [InlineData("192.168.1.9", "private")]
    [InlineData("172.16.0.1", "private")]
    [InlineData("172.32.0.1", "public")]
    [InlineData("8.8.8.8", "public")]
    [InlineData("127.0.0.1", "loopback")]
    [InlineData("169.254.1.1", "link-local")]
    public async Task An_address_is_classified(string address, string scope)
    {
        var result = await Network().EnrichAsync(About("source.ip", address));

        Assert.Equal(scope, result.Facts["scope"]);
    }

    [Fact]
    public async Task A_subject_that_is_not_an_address_says_so_rather_than_answering_nothing()
    {
        // A rule grouped by a service name. "scope: " would read like a lookup that failed.
        var result = await Network().EnrichAsync(About("service.name", "AiServices"));

        Assert.Equal("not-an-address", result.Facts["scope"]);
    }

    [Fact]
    public async Task Whether_the_never_act_list_protects_the_address_is_known_before_the_action_runs()
    {
        // The fact this enrichment exists for. The dispatcher consults the never-act list at the moment it
        // refuses to block — which is after the message has gone out saying the address was blocked. Here
        // it is known while the alert is being written, so the rule's own message can say so.
        var safety = new ActionSafetySettings { NeverBlockAddresses = ["10.0.0.0/8"] };

        var inside = await Network(safety).EnrichAsync(About("source.ip", "10.5.5.5"));
        var outside = await Network(safety).EnrichAsync(About("source.ip", "8.8.8.8"));

        Assert.Equal("true", inside.Facts["protected"]);
        Assert.Equal("false", outside.Facts["protected"]);
    }

    // -- the asset enrichment ------------------------------------------------

    [Fact]
    public async Task An_exact_entry_beats_a_range_that_contains_it()
    {
        // Two rows both apply: /8 for the estate and the address for the controller inside it. The
        // specific one was written to say something the general one does not.
        var assets = new Inventory(
            new Asset { Identifier = "10.0.0.0/8", Kind = AssetKind.Network, Name = "Corporate", Criticality = AssetCriticality.Normal },
            new Asset { Identifier = "10.5.5.5", Kind = AssetKind.Address, Name = "dc01", Criticality = AssetCriticality.Critical });

        var result = await new AssetEnrichment(assets).EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Equal("dc01", result.Facts["name"]);
        Assert.Equal(Severity.Critical, result.SeverityFloor);
    }

    [Fact]
    public async Task The_narrowest_range_wins()
    {
        var assets = new Inventory(
            new Asset { Identifier = "10.0.0.0/8", Kind = AssetKind.Network, Name = "Corporate", Criticality = AssetCriticality.Normal },
            new Asset { Identifier = "10.5.5.0/24", Kind = AssetKind.Network, Name = "Server VLAN", Criticality = AssetCriticality.High });

        var result = await new AssetEnrichment(assets).EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Equal("Server VLAN", result.Facts["name"]);
        Assert.Equal("10.5.5.0/24", result.Facts["matched"]);
    }

    [Fact]
    public async Task An_account_is_matched_too()
    {
        // A lockout rule identifies a user, not an address, and wants the same question answered.
        var assets = new Inventory(
            new Asset { Identifier = "svc-backup", Kind = AssetKind.Account, Name = "Backup service account", Criticality = AssetCriticality.High, Owner = "Infrastructure" });

        var result = await new AssetEnrichment(assets).EnrichAsync(About("user.name", "svc-backup"));

        Assert.Equal("Backup service account", result.Facts["name"]);
        Assert.Equal("Infrastructure", result.Facts["owner"]);
    }

    [Fact]
    public async Task An_empty_inventory_is_not_an_error()
    {
        var result = await new AssetEnrichment(new Inventory()).EnrichAsync(About("source.ip", "10.5.5.5"));

        Assert.Empty(result.Facts);
        Assert.Null(result.SeverityFloor);
    }

    [Fact]
    public async Task A_subject_nothing_matches_produces_nothing_rather_than_blanks()
    {
        var assets = new Inventory(
            new Asset { Identifier = "10.5.5.5", Kind = AssetKind.Address, Name = "dc01", Criticality = AssetCriticality.Critical });

        var result = await new AssetEnrichment(assets).EnrichAsync(About("source.ip", "8.8.8.8"));

        Assert.Empty(result.Facts);
    }

    [Theory]
    [InlineData(AssetCriticality.Critical, Severity.Critical)]
    [InlineData(AssetCriticality.High, Severity.High)]
    [InlineData(AssetCriticality.Normal, null)]
    [InlineData(AssetCriticality.Low, null)]
    public void Only_the_top_two_criticalities_raise_anything(string criticality, string? expected)
    {
        // A floor at "normal" would raise every alert in the platform, which is the same as raising none.
        Assert.Equal(expected, AssetCriticality.SeverityFloor(criticality));
    }

    // -- the declaration -----------------------------------------------------

    [Fact]
    public async Task What_an_enrichment_declares_is_what_it_produces()
    {
        // The rule builder offers these as chips, so a declaration that drifts from reality is a
        // placeholder somebody puts in a message that renders blank for ever. Same arrangement as a
        // strategy's evidence keys, for the same reason.
        var assets = new Inventory(
            new Asset
            {
                Identifier = "10.5.5.5", Kind = AssetKind.Address, Name = "dc01",
                Criticality = AssetCriticality.Critical, Owner = "Infra", Environment = "production"
            });

        await Declares(new AssetEnrichment(assets), About("source.ip", "10.5.5.5"));
        await Declares(Network(), About("source.ip", "10.5.5.5"));

        static async Task Declares(IEnrichment enrichment, EnrichmentRequest request)
        {
            var declared = enrichment.Describe().Facts;
            var produced = (await enrichment.EnrichAsync(request)).Facts.Keys;

            foreach (var fact in produced)
                Assert.Contains(fact, declared);
        }
    }

    // -- fixtures ------------------------------------------------------------

    private static NetworkEnrichment Network(ActionSafetySettings? safety = null) =>
        new(safety ?? new ActionSafetySettings());

    private sealed class Inventory(params Asset[] assets) : IAssetLookup
    {
        public Task<IReadOnlyList<Asset>> AllAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<Asset>>(assets);
    }

    private sealed class Fixed(string name, Dictionary<string, string> facts, string? floor = null) : IEnrichment
    {
        public string Name => name;

        public EnrichmentDescriptor Describe() => new(name, name, "", facts.Keys.ToList());

        public Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default) =>
            Task.FromResult(EnrichmentResult.From(facts, floor));
    }

    private sealed class Broken(string name) : IEnrichment
    {
        public string Name => name;

        public EnrichmentDescriptor Describe() => new(name, name, "", []);

        public Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default) =>
            throw new HttpRequestException("The service was unreachable.");
    }

    private sealed class Hangs(string name) : IEnrichment
    {
        public string Name => name;

        public EnrichmentDescriptor Describe() => new(name, name, "", []);

        public async Task<EnrichmentResult> EnrichAsync(EnrichmentRequest request, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return EnrichmentResult.Nothing;
        }
    }

    private sealed class NoRates : IActionRateStore
    {
        public Task<int> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(0);

        public Task<int> CurrentAsync(string key, CancellationToken ct = default) => Task.FromResult(0);
    }
}
