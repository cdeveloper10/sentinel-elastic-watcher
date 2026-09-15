using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Application.Actions;
using Sentinel.Application.Audit;
using Sentinel.Application.Engine;
using Sentinel.Application.Detection;
using Sentinel.Application.Enrichment;
using Sentinel.Application.EventSources;
using Sentinel.Application.Rules;
using Sentinel.Application.Security;
using Sentinel.Infrastructure.Actions;
using Sentinel.Infrastructure.Elasticsearch;
using Sentinel.Infrastructure.Engine;
using Sentinel.Infrastructure.Http;
using Sentinel.Infrastructure.Persistence;
using Sentinel.Infrastructure.Security;

namespace Sentinel.Infrastructure;

/// <summary>
/// Composition, in one place.
///
/// The registries are the point of this file. Strategies and action providers are registered as ordinary
/// implementations of their interfaces and gathered into a registry by the container — so adding either
/// means writing a class and adding one line here, and nothing that orchestrates evaluation or dispatch
/// changes. That is the whole reason there is no <c>switch</c> on strategy type or action type anywhere
/// in the platform.
/// </summary>
public static class SentinelRegistration
{
    public static IServiceCollection AddSentinel(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isProduction)
    {
        services.Configure<SecretProtectionSettings>(configuration.GetSection("Secrets"));

        services.AddSingleton<ISecretProtector>(sp => new AesGcmSecretProtector(
            sp.GetRequiredService<IOptions<SecretProtectionSettings>>(), isProduction));

        services.AddSingleton<IConnectionSecrets, ConnectionSecrets>();

        services.AddSingleton(configuration.GetSection("Outbound").Get<OutboundAddressSettings>()
                              ?? new OutboundAddressSettings());

        services.AddSingleton(configuration.GetSection("Safety").Get<ActionSafetySettings>()
                              ?? new ActionSafetySettings());

        services.AddSingleton(configuration.GetSection("Retry").Get<RetrySettings>() ?? new RetrySettings());

        services.AddSingleton(configuration.GetSection("Engine").Get<EngineSettings>() ?? new EngineSettings());
        services.TryAddSingleton(TimeProvider.System);

        services.AddSingleton<ConnectionHttpClients>();

        AddEventSources(services);
        AddDetection(services);
        AddActions(services);

        return services;
    }

    /// <summary>
    /// Persistence and the engine loop. Separate from <see cref="AddSentinel"/> so a process can compose
    /// the platform's logic without starting its background work — which is what the API host does when it
    /// runs alongside a dedicated engine deployment.
    /// </summary>
    public static IServiceCollection AddSentinelPersistence(
        this IServiceCollection services, string connectionString)
    {
        services.AddDbContext<SentinelDbContext>(options => options.UseNpgsql(connectionString, npgsql =>
        {
            // A pooled connection that the server, a firewall or a NAT device has quietly closed fails on
            // the next request that picks it up — "Exception while reading from stream" — and the caller
            // sees a 500 for a query that would have worked a second earlier. It is intermittent, it looks
            // like a bug in whatever ran at the time, and on an engine that must keep evaluating it is a
            // gap in coverage nobody attributes correctly.
            //
            // Retrying transient faults turns that into a pause. Safe here because every write goes
            // through one SaveChanges with no ambient transaction, so EF can tell a failed attempt from a
            // committed one — and the unique indexes on alerts and executions make a repeated insert a
            // refusal rather than a duplicate.
            npgsql.EnableRetryOnFailure(
                maxRetryCount: 3,
                maxRetryDelay: TimeSpan.FromSeconds(5),
                errorCodesToAdd: null);

            npgsql.CommandTimeout(30);
        }));

        // Scoped, because each holds a DbContext. The engine takes a scope per tick rather than holding
        // one for the life of the process.
        services.AddScoped<IAlertStore, EfAlertStore>();
        services.AddScoped<ICooldownStore, EfCooldownStore>();
        services.AddScoped<EfCooldownStore>();
        services.AddScoped<IActionExecutionStore, EfActionExecutionStore>();
        services.AddScoped<IApprovalSweep, EfActionExecutionStore>();
        services.AddScoped<IActionRateStore, EfActionRateStore>();
        services.AddScoped<EfActionRateStore>();
        services.AddScoped<IConnectionLookup, EfConnectionLookup>();
        services.AddScoped<ICheckpointStore, EfCheckpointStore>();
        services.AddScoped<IRuleLeaseStore, EfRuleLeaseStore>();
        services.AddScoped<IRuleRuntimeSource, EfRuleRuntimeSource>();
        services.AddScoped<IAuditTrail, EfAuditTrail>();
        services.AddScoped<IEngineNodeStore, EfEngineNodeStore>();
        services.AddScoped<IAssetLookup, EfAssetLookup>();

        services.AddScoped<RuleEvaluator>();
        services.AddScoped<RuleScheduler>();

        // Singleton, and deliberately not scoped: it exists to escape the scope it is resolved from. The
        // scheduler evaluates several rules at once and each needs its own DbContext — see
        // IRuleEvaluationSlot for the defect that taught us so.
        services.AddSingleton<IRuleEvaluationSlotFactory, ScopedRuleEvaluationSlots>();

        return services;
    }

    /// <summary>Starts the evaluation loop and the sweeper. Only the process that should evaluate calls this.</summary>
    public static IServiceCollection AddSentinelEngine(this IServiceCollection services)
    {
        services.AddHostedService<DetectionEngineService>();
        services.AddHostedService<MaintenanceService>();

        return services;
    }

    private static void AddEventSources(IServiceCollection services)
    {
        // Elasticsearch is the only source in the MVP, and it is registered as one implementation of the
        // abstraction rather than as the abstraction itself. A second source is another line here.
        services.AddSingleton<IEventSource, ElasticsearchEventSource>();
        services.AddSingleton<ElasticsearchEventSource>();
    }

    private static void AddDetection(IServiceCollection services)
    {
        services.AddSingleton<IDetectionStrategy, ThresholdDetectionStrategy>();
        services.AddSingleton<IDetectionStrategy, MatchDetectionStrategy>();
        services.AddSingleton<IDetectionStrategyRegistry, DetectionStrategyRegistry>();

        services.AddSingleton<RuleValidator>();

        // Stateless over the strategy registry, and — deliberately — with no path to a dispatcher, which
        // is what makes a rehearsal structurally unable to execute anything.
        services.AddSingleton<DryRunService>();

        // Stateless for the same reason, and unable to act for the same structural one: it holds a source
        // and nothing else, so "a preview never executes an action" is a property of the type.
        services.AddSingleton<ConditionPreviewService>();

        // Enrichments, gathered by the container the way strategies and actions are. A third is another
        // line here and nothing else changes.
        services.AddSingleton<IEnrichment, NetworkEnrichment>();
        services.AddScoped<IEnrichment, AssetEnrichment>();
        services.AddScoped<EnrichmentPipeline>();

        // Scoped, not singleton: it reads and writes through stores that hold a DbContext. Registering it
        // as a singleton would capture one context for the life of the process, which accumulates every
        // entity the engine has ever touched and shares it across threads.
        services.AddScoped<DetectionPipeline>();
    }

    private static void AddActions(IServiceCollection services)
    {
        services.AddSingleton<IActionProvider, BlockIpActionProvider>();
        services.AddSingleton<IActionProvider, BlockUserActionProvider>();
        services.AddSingleton<IActionProvider, SmsActionProvider>();

        // The registry itself holds only the providers, which are stateless.
        services.AddSingleton<IActionRegistry, ActionRegistry>();

        // Both reach the database — the safety policy through the rate counters, the dispatcher through
        // the execution claim and the connection lookup — so both follow the scope that owns the context.
        services.AddScoped<ActionSafetyPolicy>();
        services.AddScoped<ActionDispatcher>();
    }
}
