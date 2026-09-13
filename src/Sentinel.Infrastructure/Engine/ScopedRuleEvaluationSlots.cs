using Microsoft.Extensions.DependencyInjection;
using Sentinel.Application.Engine;

namespace Sentinel.Infrastructure.Engine;

/// <summary>
/// One container scope per rule, so the rules evaluated together in a tick share no database connection.
///
/// The engine takes a scope per tick for the scheduler itself — reading which rules are active and which
/// are due, both on one thread. That scope cannot also serve the evaluations, because those run
/// concurrently and a <c>DbContext</c> is not thread-safe. This is the seam between the two.
///
/// Singleton: it holds only the root scope factory, and creates everything else per call.
/// </summary>
public sealed class ScopedRuleEvaluationSlots(IServiceScopeFactory scopes) : IRuleEvaluationSlotFactory
{
    public IRuleEvaluationSlot Create() => new Slot(scopes.CreateAsyncScope());

    private sealed class Slot : IRuleEvaluationSlot
    {
        private readonly AsyncServiceScope _scope;

        public Slot(AsyncServiceScope scope)
        {
            _scope = scope;

            // Resolved eagerly. A slot that cannot supply what it promises should fail where it is created
            // rather than part-way through an evaluation that has already acquired a lease.
            Evaluator = scope.ServiceProvider.GetRequiredService<RuleEvaluator>();
            Leases = scope.ServiceProvider.GetRequiredService<IRuleLeaseStore>();
        }

        public RuleEvaluator Evaluator { get; }

        public IRuleLeaseStore Leases { get; }

        public ValueTask DisposeAsync() => _scope.DisposeAsync();
    }
}
