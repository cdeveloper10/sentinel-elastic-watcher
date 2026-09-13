using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Sentinel.Infrastructure.Persistence;

/// <summary>
/// Lets <c>dotnet ef</c> build the model without starting the application.
///
/// The connection string comes from <c>SENTINEL_CONNECTION</c> rather than from a configuration file,
/// because this runs on a developer's machine and in CI against whichever database is at hand. Hard-coding
/// one here would put a credential in the repository and make the tooling silently target the wrong
/// server when somebody forgot to change it.
///
/// The fallback is a local default — enough to generate a migration, which needs a provider rather than a
/// reachable server. Applying one requires the variable to be set.
/// </summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<SentinelDbContext>
{
    public const string ConnectionVariable = "SENTINEL_CONNECTION";

    public SentinelDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable(ConnectionVariable)
                         ?? "Host=localhost;Port=5432;Database=sentinel;Username=postgres;Password=postgres";

        var options = new DbContextOptionsBuilder<SentinelDbContext>()
            .UseNpgsql(connection, npgsql => npgsql.MigrationsAssembly(typeof(SentinelDbContext).Assembly.FullName))
            .Options;

        return new SentinelDbContext(options);
    }
}
