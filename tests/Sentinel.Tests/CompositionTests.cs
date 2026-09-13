using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Actions;
using Sentinel.Application.Audit;
using Sentinel.Application.Detection;
using Sentinel.Application.Engine;
using Sentinel.Application.EventSources;
using Sentinel.Infrastructure;

namespace Sentinel.Tests;

/// <summary>
/// That the container can actually build what the host asks it for.
///
/// This catches the class of bug that otherwise appears at three in the morning: a service registered as
/// a singleton while depending on something scoped. The container captures one <c>DbContext</c> for the
/// life of the process, shares it across threads, and accumulates every entity the engine has ever
/// touched — and none of that shows up until the platform has been running for a while under load.
///
/// <c>ValidateOnBuild</c> and <c>ValidateScopes</c> turn it into a build-time failure, and this test
/// makes the build-time failure happen in CI rather than on a node.
/// </summary>
public class CompositionTests
{
    private static ServiceProvider Build()
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddSentinel(Configuration(), isProduction: false);
        services.AddSentinelPersistence("Host=localhost;Database=sentinel;Username=x;Password=y");

        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            // Every registration is checked now rather than on first resolution, and a singleton holding
            // a scoped dependency is an error rather than a slow leak.
            ValidateOnBuild = true,
            ValidateScopes = true
        });
    }

    private static IConfiguration Configuration() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Engine:NodeId"] = "test-node",
                ["Safety:MaxDisruptiveActionsPerRule"] = "25"
            })
            .Build();

    [Fact]
    public void The_container_builds_with_scope_validation_on()
    {
        using var provider = Build();

        Assert.NotNull(provider);
    }

    [Theory]
    [InlineData(typeof(IEventSource))]
    [InlineData(typeof(IDetectionStrategyRegistry))]
    [InlineData(typeof(IActionRegistry))]
    [InlineData(typeof(DryRunService))]
    [InlineData(typeof(ActionSafetyPolicy))]
    [InlineData(typeof(ActionDispatcher))]
    [InlineData(typeof(DetectionPipeline))]
    [InlineData(typeof(RuleEvaluator))]
    [InlineData(typeof(RuleScheduler))]
    [InlineData(typeof(IAuditTrail))]
    public void Everything_the_engine_needs_can_be_resolved(Type service)
    {
        using var provider = Build();
        using var scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService(service));
    }

    [Fact]
    public void Every_action_provider_is_in_the_registry()
    {
        // The registry is what makes "adding an action changes nothing else" true, and it is only true if
        // registration actually reaches it.
        using var provider = Build();
        var registry = provider.GetRequiredService<IActionRegistry>();

        var types = registry.Describe().Select(d => d.Type).ToList();

        Assert.Contains("block_ip", types);
        Assert.Contains("block_user", types);
        Assert.Contains("sms", types);
    }

    [Fact]
    public void Every_detection_strategy_is_in_the_registry()
    {
        using var provider = Build();
        var registry = provider.GetRequiredService<IDetectionStrategyRegistry>();

        Assert.NotNull(registry.Resolve(Domain.Rules.DetectionStrategyType.Threshold));
        Assert.NotNull(registry.Resolve(Domain.Rules.DetectionStrategyType.Match));
    }

    [Fact]
    public void A_dry_run_service_cannot_reach_a_dispatcher()
    {
        // Structural, not a flag. The one constructor argument is a strategy registry, so there is no path
        // from a rehearsal to anything that blocks an address — which is what makes "a dry run never
        // executes a real action" a property of the design rather than a rule someone has to remember.
        var constructor = Assert.Single(typeof(DryRunService).GetConstructors());
        var parameters = constructor.GetParameters();

        Assert.Single(parameters);
        Assert.Equal(typeof(IDetectionStrategyRegistry), parameters[0].ParameterType);
    }

    [Fact]
    public async Task Two_evaluation_slots_share_no_database_context()
    {
        // The defect this exists for, at the layer where it was real. The scheduler evaluates several rules
        // at once; the engine took one scope per tick; so every concurrent evaluation used one DbContext,
        // which is not thread-safe. Two of three armed rules threw "a second operation was started on this
        // context instance" and evaluated nothing.
        //
        // Scope validation cannot catch this. Every registration was correct on its own — what was wrong
        // was that one scope served work that runs in parallel.
        using var provider = Build();

        var factory = provider.GetRequiredService<IRuleEvaluationSlotFactory>();

        var first = factory.Create();
        var second = factory.Create();

        try
        {
            Assert.NotSame(first, second);
            Assert.NotSame(first.Evaluator, second.Evaluator);
            Assert.NotSame(first.Leases, second.Leases);
        }
        finally
        {
            await first.DisposeAsync();
            await second.DisposeAsync();
        }
    }

    [Fact]
    public async Task A_slot_can_be_taken_without_a_scope_already_being_open()
    {
        // The engine's tick scope exists for the scheduler, not for the evaluations, so the factory has to
        // open its own — which is why it is a singleton over the root scope factory rather than something
        // resolved out of whatever scope happens to be current.
        using var provider = Build();

        var slot = provider.GetRequiredService<IRuleEvaluationSlotFactory>().Create();

        Assert.NotNull(slot.Evaluator);

        await slot.DisposeAsync();
    }

    [Fact]
    public void The_engine_loop_is_not_started_unless_a_process_asks_for_it()
    {
        // The API host composes the platform's logic without evaluating anything, so that a deployment can
        // run several API pods against one engine.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSentinel(Configuration(), isProduction: false);
        services.AddSentinelPersistence("Host=localhost;Database=sentinel;Username=x;Password=y");

        Assert.DoesNotContain(services, d =>
            d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService));

        services.AddSentinelEngine();

        Assert.Equal(2, services.Count(d =>
            d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)));
    }
}
